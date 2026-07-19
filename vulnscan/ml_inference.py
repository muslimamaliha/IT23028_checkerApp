"""
ml_inference.py - Fixed version

Key fixes:
1. npm-ONLY filter: Go/PyPI/Debian/Ubuntu entries completely excluded
2. CVSS V3 properly calculated from vector
3. CVSS V4 numeric score extracted directly from OSV severity field
4. ML model blended with real CVSS (70% CVSS + 30% ML)
5. Malicious package detection (MAL- prefix)
"""

import os, sys, re, math, requests, numpy as np
from datetime import datetime, timezone

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(THIS_DIR, "..", "ml"))

try:
    import joblib
    JOBLIB_OK = True
except ImportError:
    JOBLIB_OK = False

from django.conf import settings

NPM_REGISTRY = "https://registry.npmjs.org/{}"
OSV_QUERY    = "https://api.osv.dev/v1/query"
OSV_VULN     = "https://api.osv.dev/v1/vulns/{}"

FEATURE_COLS = [
    "av","ac","pr","ui","scope",
    "ref_count","advisory_ref_count","affected_range_count",
    "alias_count","days_since_published","summary_len",
]

# Ecosystems that are NEVER relevant for npm packages
NON_NPM_ECOSYSTEMS = {
    "go","pypi","rubygems","maven","nuget","cargo","hex","pub","swift",
    "debian","ubuntu","alpine","rocky linux","almalinux","redhat","centos",
    "suse","opensuse","minimos","hackage","erlang","elixir","composer",
}

_cache = {}

# ─── CVSS parsing ────────────────────────────────────────────────────────────

def _parse_v3_components(vec):
    m = re.search(r"CVSS:3[.\d]*/(.+)", vec or "")
    if not m: return {}
    return {k:v for p in m.group(1).split("/") if ":" in p for k,v in [p.split(":",1)]}

def _cvss3_score(vec):
    c = _parse_v3_components(vec)
    if not all(k in c for k in ["AV","AC","PR","UI","S","C","I","A"]): return None
    av  = {"N":0.85,"A":0.62,"L":0.55,"P":0.2}.get(c["AV"])
    ac  = {"L":0.77,"H":0.44}.get(c["AC"])
    sc  = c["S"]=="C"
    pr  = {"N":0.85,"L":0.62 if sc else 0.68,"H":0.5 if sc else 0.27}.get(c["PR"])
    ui  = {"N":0.85,"R":0.62}.get(c["UI"])
    cm  = {"H":0.56,"L":0.22,"N":0.0}
    ci,ii,ai = cm.get(c["C"]),cm.get(c["I"]),cm.get(c["A"])
    if None in (av,ac,pr,ui,ci,ii,ai): return None
    iss = 1-(1-ci)*(1-ii)*(1-ai)
    imp = (7.52*(iss-0.029)-3.25*((iss-0.02)**15)) if sc else 6.42*iss
    exp = 8.22*av*ac*pr*ui
    if imp<=0: return 0.0
    raw = min(1.08*(imp+exp),10) if sc else min(imp+exp,10)
    return math.ceil(raw*10)/10

def _cvss4_score(score_str):
    """OSV stores CVSS v4 score field as the raw vector string.
    The NUMERIC score is in the parent severity entry alongside it.
    We try to extract it from the string if embedded, else return None."""
    # Sometimes OSV embeds "9.1 CVSS:4.0/..." — extract leading number
    m = re.match(r"^(\d+\.\d+)", (score_str or "").strip())
    if m: return float(m.group(1))
    return None

def _best_cvss(vuln_json):
    """
    Extract the single best numeric CVSS score from an OSV record.
    Priority: explicit numeric in db_specific > CVSS v3 vector calc > CVSS v4 numeric > text band.
    """
    db = vuln_json.get("database_specific") or {}
    for key in ("cvss_score","severity_score","score"):
        v = db.get(key)
        if isinstance(v,(int,float)) and v>0:
            return float(v)

    sevs = vuln_json.get("severity") or []

    # Try CVSS V3 first (well-defined formula)
    for s in sevs:
        if s.get("type") == "CVSS_V3":
            score = _cvss3_score(s.get("score",""))
            if score is not None: return score

    # Try CVSS V4 — OSV gives the vector, but also exposes the numeric
    # score in a sibling "score" key in some records; try both ways
    for s in sevs:
        if s.get("type") == "CVSS_V4":
            raw = s.get("score","")
            # Try extracting float directly from score field
            try:
                val = float(raw)
                if 0 < val <= 10: return val
            except (TypeError,ValueError): pass
            # Try if it's embedded as "9.1 CVSS:4.0/..."
            score = _cvss4_score(raw)
            if score is not None: return score

    # Generic: any severity entry with a plain numeric score
    for s in sevs:
        try:
            val = float(s.get("score",""))
            if 0 < val <= 10: return val
        except (TypeError,ValueError): pass

    # Last resort: text severity band midpoints
    sev = (db.get("severity") or "").upper()
    return {"CRITICAL":9.5,"HIGH":7.5,"MODERATE":5.5,"MEDIUM":5.5,"LOW":2.0}.get(sev)

def _severity_band(score):
    if score is None: return "UNKNOWN"
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

# ─── npm relevance filter ─────────────────────────────────────────────────────

def _npm_relevant(vuln_json, pkg_name):
    """
    Return True ONLY if this vuln has at least one 'affected' entry
    with ecosystem == 'npm' (case-insensitive).

    This is the key fix: OSV queries return ALL ecosystems that share
    the keyword — Go, PyPI, Debian, Ubuntu etc. We must filter to npm only.
    """
    affected = vuln_json.get("affected") or []
    if not affected:
        return True  # no affected list = allow (shouldn't happen)

    for entry in affected:
        pkg = entry.get("package") or {}
        eco = pkg.get("ecosystem","").lower().strip()
        if eco == "npm":
            return True  # has at least one npm-ecosystem entry

    return False  # all affected entries are non-npm

def _is_malicious(vid, vuln_json):
    if vid.startswith("MAL-"): return True
    summary = (vuln_json.get("summary") or "").lower()
    return "malicious" in summary

# ─── ML model ────────────────────────────────────────────────────────────────

def _load_models():
    if _cache: return _cache
    if not JOBLIB_OK:
        _cache["available"] = False
        return _cache
    d = str(settings.ML_MODEL_DIR)
    try:
        _cache["rr"] = joblib.load(os.path.join(d,"risk_regressor.pkl"))
        _cache["rs"] = joblib.load(os.path.join(d,"risk_regressor_scaler.pkl"))
        _cache["cr"] = joblib.load(os.path.join(d,"severity_classifier.pkl"))
        _cache["cs"] = joblib.load(os.path.join(d,"severity_classifier_scaler.pkl"))
        _cache["available"] = True
    except FileNotFoundError:
        _cache["available"] = False
    return _cache

def _features(vuln_json):
    DEFAULTS = {"av":0.85,"ac":0.85,"pr":0.8,"ui":0.85,"scope":0.7,
                "ref_count":3,"advisory_ref_count":1,"affected_range_count":1,
                "alias_count":1,"days_since_published":365,"summary_len":80}
    f = dict(DEFAULTS)
    for s in (vuln_json.get("severity") or []):
        if s.get("type")=="CVSS_V3":
            c = _parse_v3_components(s.get("score",""))
            f["av"]    = {"N":1.0,"A":0.75,"L":0.5,"P":0.25}.get(c.get("AV"),f["av"])
            f["ac"]    = {"L":1.0,"H":0.5}.get(c.get("AC"),f["ac"])
            f["pr"]    = {"N":1.0,"L":0.6,"H":0.3}.get(c.get("PR"),f["pr"])
            f["ui"]    = {"N":1.0,"R":0.5}.get(c.get("UI"),f["ui"])
            f["scope"] = {"C":1.0,"U":0.5}.get(c.get("S"),f["scope"])
            break
    refs = vuln_json.get("references") or []
    f["ref_count"] = len(refs)
    f["advisory_ref_count"] = sum(1 for r in refs if r.get("type")=="ADVISORY")
    aff = vuln_json.get("affected") or []
    f["affected_range_count"] = max(1, sum(len(a.get("ranges",[])) for a in aff))
    f["alias_count"] = len(vuln_json.get("aliases") or [])
    f["summary_len"] = len(vuln_json.get("summary","") or "")
    pub = vuln_json.get("published")
    if pub:
        try:
            d = datetime.fromisoformat(pub.replace("Z","+00:00"))
            f["days_since_published"] = (datetime.now(timezone.utc)-d).days
        except: pass
    return f

def _ml_score(feat):
    m = _load_models()
    if not m.get("available"): return None
    X = np.array([[feat.get(c,0) or 0 for c in FEATURE_COLS]])
    try:
        score = float(m["rr"].predict(m["rs"].transform(X))[0])
        return int(round(min(100,max(1,score))))
    except: return None

# ─── main pipeline ────────────────────────────────────────────────────────────

def analyze_package(pkg_name, version=None):
    # 1. npm registry
    npm = requests.get(NPM_REGISTRY.format(pkg_name), timeout=10)
    npm.raise_for_status()
    npm_data = npm.json()
    ver = version or npm_data.get("dist-tags",{}).get("latest")

    # 2. OSV query
    body = {"package":{"name":pkg_name,"ecosystem":"npm"}}
    if ver: body["version"] = ver
    osv_res = requests.post(OSV_QUERY, json=body, timeout=15)
    osv_res.raise_for_status()
    raw_vulns = osv_res.json().get("vulns") or []

    findings = []
    for v in raw_vulns:
        vid = v.get("id","")
        detail = None
        try:
            r = requests.get(OSV_VULN.format(vid), timeout=15)
            if r.status_code == 200: detail = r.json()
        except: pass
        detail = detail or v

        # ── CRITICAL FIX: skip non-npm ecosystems ──
        if not _npm_relevant(detail, pkg_name):
            continue

        malicious = _is_malicious(vid, detail)
        cvss      = _best_cvss(detail)

        if malicious:
            score, severity, method = 95, "CRITICAL", "malicious"
            used_ml = False
        elif cvss is not None:
            cvss100   = int(round(min(100,max(1,(cvss/10.0)*100))))
            feat      = _features(detail)
            ml        = _ml_score(feat)
            if ml:
                score   = int(round(0.70*cvss100 + 0.30*ml))
                used_ml = True
                method  = "cvss+ml"
            else:
                score   = cvss100
                used_ml = False
                method  = "cvss"
            severity = _severity_band(cvss)
        else:
            feat   = _features(detail)
            ml     = _ml_score(feat)
            score  = ml or 30
            sev_map = {range(90,101):"CRITICAL",range(70,90):"HIGH",
                       range(40,70):"MEDIUM",range(0,40):"LOW"}
            severity = next((s for r,s in sev_map.items() if score in r),"MEDIUM")
            used_ml  = bool(ml)
            method   = "ml_only" if ml else "fallback"

        aliases = detail.get("aliases") or []
        cve = next((a for a in aliases if a.startswith("CVE-")), None)

        findings.append({
            "id":        vid,
            "summary":   (detail.get("summary") or "No summary available")[:300],
            "score":     score,
            "severity":  severity,
            "raw_cvss":  cvss,
            "used_ml":   used_ml,
            "method":    method,
            "malicious": malicious,
            "cve":       cve,
            "published": (detail.get("published") or "")[:10],
            "url":       f"https://osv.dev/vulnerability/{vid}",
        })

    findings.sort(key=lambda f: -f["score"])

    time_info = npm_data.get("time") or {}
    return {
        "package_name":     pkg_name,
        "version":          ver,
        "description":      npm_data.get("description",""),
        "license":          str(npm_data.get("license") or "unknown"),
        "created":          (time_info.get("created","") or "")[:10],
        "modified":         (time_info.get("modified","") or "")[:10],
        "findings":         findings,
        "total_vulns":      len(findings),
        "critical_count":   sum(1 for f in findings if f["severity"]=="CRITICAL"),
        "high_count":       sum(1 for f in findings if f["severity"]=="HIGH"),
        "medium_count":     sum(1 for f in findings if f["severity"]=="MEDIUM"),
        "low_count":        sum(1 for f in findings if f["severity"]=="LOW"),
        "overall_score":    findings[0]["score"] if findings else 0,
        "overall_severity": findings[0]["severity"] if findings else "NONE",
        "model_available":  _load_models().get("available",False),
        "any_ml_used":      any(f["used_ml"] for f in findings),
    }
