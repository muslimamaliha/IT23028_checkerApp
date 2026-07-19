"""
collect_training_data.py
Real npm vulnerability data collector from OSV.dev.
Run: python collect_training_data.py
Output: data/vuln_training_data.csv
"""
import os,time,csv,re,math,requests
from datetime import datetime,timezone

THIS_DIR=os.path.dirname(os.path.abspath(__file__))
OUTPUT_CSV=os.path.join(THIS_DIR,"vuln_training_data.csv")
OSV_QUERY="https://api.osv.dev/v1/query"
OSV_VULN="https://api.osv.dev/v1/vulns/{}"
CVSS3_RE=re.compile(r"CVSS:3[.\d]*/(.+)")

SEED_PACKAGES=[
    "lodash","express","minimist","request","axios","moment","jquery",
    "handlebars","marked","ejs","yargs-parser","qs","semver","node-fetch",
    "ws","socket.io","jsonwebtoken","passport","mongoose","sequelize",
    "validator","underscore","async","tar","decompress","extract-zip",
    "glob-parent","trim","braces","micromatch","set-value","mixin-deep",
    "merge","deep-extend","jquery-ui","bootstrap","angular","vue",
    "webpack","eslint","grunt","gulp","node-sass","electron",
    "serialize-javascript","js-yaml","minimatch","ini","dot-prop",
    "shelljs","y18n","yargs","config","debug","color-string","ansi-html",
    "nth-check","css-what","trim-newlines","got","browserify-sign",
    "elliptic","node-forge","jsrsasign","xmlhttprequest-ssl",
    "socket.io-parser","engine.io","vm2","pac-resolver","ip","netmask",
    "url-parse","lodash.template","cross-spawn",
]

CVSS_AV={"N":1.0,"A":0.75,"L":0.5,"P":0.25}
CVSS_AC={"L":1.0,"H":0.5}
CVSS_PR={"N":1.0,"L":0.6,"H":0.3}
CVSS_UI={"N":1.0,"R":0.5}
CVSS_SC={"C":1.0,"U":0.5}

def parse_v3(vec):
    m=CVSS3_RE.search(vec or "")
    if not m: return {}
    return {k:v for p in m.group(1).split("/") if ":" in p for k,v in [p.split(":",1)]}

def cvss3_score(vec):
    c=parse_v3(vec)
    if not all(k in c for k in ["AV","AC","PR","UI","S","C","I","A"]): return None
    av={"N":0.85,"A":0.62,"L":0.55,"P":0.2}.get(c["AV"])
    ac={"L":0.77,"H":0.44}.get(c["AC"])
    sc=c["S"]=="C"
    pr={"N":0.85,"L":0.62 if sc else 0.68,"H":0.5 if sc else 0.27}.get(c["PR"])
    ui={"N":0.85,"R":0.62}.get(c["UI"])
    cm={"H":0.56,"L":0.22,"N":0.0}
    ci,ii,ai=cm.get(c["C"]),cm.get(c["I"]),cm.get(c["A"])
    if None in (av,ac,pr,ui,ci,ii,ai): return None
    iss=1-(1-ci)*(1-ii)*(1-ai)
    imp=(7.52*(iss-0.029)-3.25*((iss-0.02)**15)) if sc else 6.42*iss
    exp=8.22*av*ac*pr*ui
    if imp<=0: return 0.0
    raw=min(1.08*(imp+exp),10) if sc else min(imp+exp,10)
    return math.ceil(raw*10)/10

def severity_from_score(s):
    if s is None: return None
    if s>=9.0: return "CRITICAL"
    if s>=7.0: return "HIGH"
    if s>=4.0: return "MEDIUM"
    return "LOW"

def extract(vuln):
    db=vuln.get("database_specific") or {}
    feat={"id":vuln.get("id"),"cvss_score":None,"severity_label":None,
          "av":None,"ac":None,"pr":None,"ui":None,"scope":None,
          "ref_count":0,"advisory_ref_count":0,"affected_range_count":1,
          "alias_count":0,"days_since_published":365,"summary_len":0,"source_package":""}

    sevs=vuln.get("severity") or []
    for s in sevs:
        if s.get("type")=="CVSS_V3":
            score=cvss3_score(s.get("score",""))
            if score is not None:
                feat["cvss_score"]=score
                c=parse_v3(s.get("score",""))
                feat["av"]=CVSS_AV.get(c.get("AV"))
                feat["ac"]=CVSS_AC.get(c.get("AC"))
                feat["pr"]=CVSS_PR.get(c.get("PR"))
                feat["ui"]=CVSS_UI.get(c.get("UI"))
                feat["scope"]=CVSS_SC.get(c.get("S"))
                break

    if feat["cvss_score"] is None:
        for key in ("cvss_score","severity_score"):
            v=db.get(key)
            if isinstance(v,(int,float)) and v>0:
                feat["cvss_score"]=float(v); break

    sev=(db.get("severity") or "").upper()
    if sev in ("CRITICAL","HIGH","MODERATE","MEDIUM","LOW"):
        feat["severity_label"]="MEDIUM" if sev=="MODERATE" else sev

    if feat["cvss_score"] is None and feat["severity_label"]:
        feat["cvss_score"]={"CRITICAL":9.5,"HIGH":7.5,"MEDIUM":5.5,"LOW":2.0}.get(feat["severity_label"])

    if feat["severity_label"] is None:
        feat["severity_label"]=severity_from_score(feat["cvss_score"])

    refs=vuln.get("references") or []
    feat["ref_count"]=len(refs)
    feat["advisory_ref_count"]=sum(1 for r in refs if r.get("type")=="ADVISORY")
    aff=vuln.get("affected") or []
    feat["affected_range_count"]=max(1,sum(len(a.get("ranges",[])) for a in aff))
    feat["alias_count"]=len(vuln.get("aliases") or [])
    feat["summary_len"]=len(vuln.get("summary","") or "")
    pub=vuln.get("published")
    if pub:
        try:
            d=datetime.fromisoformat(pub.replace("Z","+00:00"))
            feat["days_since_published"]=(datetime.now(timezone.utc)-d).days
        except: pass
    return feat

def main():
    print(f"Fetching real OSV data for {len(SEED_PACKAGES)} npm packages...")
    seen,rows=[],[]
    dropped=0
    for i,pkg in enumerate(SEED_PACKAGES,1):
        try:
            res=requests.post(OSV_QUERY,json={"package":{"name":pkg,"ecosystem":"npm"}},timeout=15)
            vulns=res.json().get("vulns") or []
        except Exception as e:
            print(f"  [{i}] {pkg}: fetch failed ({e})")
            continue
        print(f"  [{i}/{len(SEED_PACKAGES)}] {pkg}: {len(vulns)} vuln(s)")
        for v in vulns:
            vid=v.get("id")
            if not vid or vid in seen: continue
            seen.append(vid)
            try:
                dr=requests.get(OSV_VULN.format(vid),timeout=15)
                detail=dr.json() if dr.status_code==200 else v
            except: detail=v
            feat=extract(detail)
            if feat["cvss_score"] is None or feat["severity_label"] is None:
                dropped+=1; continue
            feat["source_package"]=pkg
            rows.append(feat)
            time.sleep(0.05)
        time.sleep(0.1)
    print(f"\nTotal: {len(rows)} records | Dropped (no score): {dropped}")
    COLS=["id","source_package","cvss_score","severity_label","av","ac","pr","ui","scope",
          "ref_count","advisory_ref_count","affected_range_count","alias_count","days_since_published","summary_len"]
    with open(OUTPUT_CSV,"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=COLS)
        w.writeheader()
        for r in rows: w.writerow(r)
    print(f"Saved {len(rows)} records to {OUTPUT_CSV}")

if __name__=="__main__":
    main()
