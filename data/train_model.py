"""
train_model.py
Train vulnerability risk regressor + severity classifier on real CVSS data.
Run from data/ folder: python train_model.py
"""
import os,numpy as np,pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingRegressor,RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_absolute_error,r2_score,classification_report
import joblib

THIS_DIR=os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT=os.path.dirname(THIS_DIR)
DATA_CSV=os.path.join(THIS_DIR,"vuln_training_data.csv")
ML_DIR=os.path.join(PROJECT_ROOT,"ml")

FEATURE_COLS=["av","ac","pr","ui","scope","ref_count","advisory_ref_count",
              "affected_range_count","alias_count","days_since_published","summary_len"]
SEV_LABELS=["LOW","MEDIUM","HIGH","CRITICAL"]

def main():
    print("Loading data...")
    df=pd.read_csv(DATA_CSV)
    df=df[df["severity_label"].isin(SEV_LABELS)].copy()
    for c in FEATURE_COLS:
        df[c]=pd.to_numeric(df.get(c),errors="coerce")
        df[c]=df[c].fillna(df[c].median() if df[c].notna().any() else 0)
    df["risk100"]=(df["cvss_score"].clip(0,10)/10.0)*100.0
    print(f"Records: {len(df)}")
    print(df["severity_label"].value_counts())

    X=df[FEATURE_COLS]; y_reg=df["risk100"]; y_clf=df["severity_label"]
    Xtr,Xte,yr_tr,yr_te=train_test_split(X,y_reg,test_size=0.2,random_state=42)
    _,__,yc_tr,yc_te=train_test_split(X,y_clf,test_size=0.2,random_state=42)

    scr=StandardScaler()
    Xtr_r=scr.fit_transform(Xtr); Xte_r=scr.transform(Xte)
    reg=GradientBoostingRegressor(n_estimators=200,max_depth=3,learning_rate=0.05,subsample=0.8,random_state=42)
    reg.fit(Xtr_r,yr_tr)
    preds=np.clip(reg.predict(Xte_r),1,100)
    print(f"\nRegressor MAE: {mean_absolute_error(yr_te,preds):.2f}  R²: {r2_score(yr_te,preds):.3f}")

    scc=StandardScaler()
    Xtr_c=scc.fit_transform(Xtr); Xte_c=scc.transform(Xte)
    clf=RandomForestClassifier(n_estimators=300,max_depth=6,class_weight="balanced",random_state=42)
    clf.fit(Xtr_c,yc_tr)
    print("\nClassifier report:")
    print(classification_report(yc_te,clf.predict(Xte_c),zero_division=0))

    os.makedirs(ML_DIR,exist_ok=True)
    joblib.dump(reg,os.path.join(ML_DIR,"risk_regressor.pkl"))
    joblib.dump(scr,os.path.join(ML_DIR,"risk_regressor_scaler.pkl"))
    joblib.dump(clf,os.path.join(ML_DIR,"severity_classifier.pkl"))
    joblib.dump(scc,os.path.join(ML_DIR,"severity_classifier_scaler.pkl"))
    print(f"\nModels saved to {ML_DIR}")

if __name__=="__main__":
    main()
