#python goldenguard.py --income 5000 --consent yes --export-clean --delete-crypt


import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone
import pandas as pd
import numpy as np
import jwt
import pyotp
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest

CSV_FILE    = 'extrato.csv'
KEY_FILE    = 'secret.key'
JWT_FILE    = 'jwt_secret.key'
MFA_FILE    = 'mfa_secret.key'
GUIDELINES  = 'ethics_guidelines.json'
AUDIT_TRAIL = 'audit_trail.json'
EXPLAIN_JSON= 'explanations.json'
BIAS_JSON   = 'bias_audit.json'
VENDORS     = ["BET365","POKERSTAR","SPORTSBOOK","888BET","BETWAY","BWIN","PADDYPOWER"]
ANOMALY_CONT= 0.02
THRESHOLD   = 0.3

def now_utc():
    return datetime.now(timezone.utc)

def load_or_create_jwt_secret(path, size=32):
    if not os.path.exists(path):
        v = os.urandom(size)
        with open(path, 'wb') as f: f.write(v)
    else:
        v = open(path, 'rb').read()
    return v

JWT_SECRET = load_or_create_jwt_secret(JWT_FILE)

def load_or_create_fernet_key(path):
    if not os.path.exists(path):
        key = Fernet.generate_key()
        with open(path, 'wb') as f: f.write(key)
    else:
        key = open(path, 'rb').read()
    return key

if not os.path.exists(MFA_FILE):
    MFA_SECRET = pyotp.random_base32()
    with open(MFA_FILE, 'w') as f: f.write(MFA_SECRET)
else:
    MFA_SECRET = open(MFA_FILE, 'r').read().strip()

def load_guidelines():
    if not os.path.exists(GUIDELINES):
        g = {"privacy":"Não expor PII","fairness":"Evitar vieses","transparency":"Registrar auditoria"}
        with open(GUIDELINES, 'w') as f: json.dump(g, f, indent=2)
        return g
    return json.load(open(GUIDELINES))

load_guidelines()

code = input('MFA code: ')
if not pyotp.TOTP(MFA_SECRET).verify(code):
    sys.exit(1)

trail = []
trail.append({"event":"start","time": now_utc().isoformat()})

def run_static_analysis():
    import subprocess
    try:
        result = subprocess.run(['bandit', '-r', __file__], capture_output=True, text=True)
        trail.append({"event":"bandit","output": result.stdout[:200]})
    except FileNotFoundError:
        trail.append({"event":"bandit","error":"not installed"})

def load_and_sanitize():
    if not os.path.exists(CSV_FILE):
        sys.exit(1)
    df = pd.read_csv(CSV_FILE, parse_dates=['Date'])
    before = len(df)
    df['Amount'] = pd.to_numeric(df['Amount'], errors='coerce')
    df.dropna(subset=['Date','Description','Amount'], inplace=True)
    removed = before - len(df)
    trail.append({"event":"sanitize","removed": removed})
    return df

def detect_anomalies(df):
    model = IsolationForest(contamination=ANOMALY_CONT, random_state=0)
    df['anomaly'] = model.fit_predict(df[['Amount']])
    cnt = int((df['anomaly'] == -1).sum())
    trail.append({"event":"anomaly_detected","count": cnt})
    return df, model

def explain_amount(df):
    vals = np.abs(df['Amount'].values)
    mn, mx = vals.min(), vals.max()
    norm = (vals - mn) / (mx - mn) if mx > mn else np.zeros_like(vals)
    exps = [[('Amount', float(v))] for v in norm]
    json.dump({'importance': norm.tolist()}, open(EXPLAIN_JSON, 'w'), indent=2)
    trail.append({"event":"explain","file": EXPLAIN_JSON})
    return exps

def audit_bias(df):
    rates = df.groupby('Description')['anomaly'].apply(lambda x: float((x==-1).mean())).to_dict()
    json.dump(rates, open(BIAS_JSON, 'w'), indent=2)
    trail.append({"event":"bias_audit","file": BIAS_JSON})
    return rates

def encrypt_data(df, filename):
    key = load_or_create_fernet_key(KEY_FILE)
    fer = Fernet(key)
    tok = fer.encrypt(df.to_csv(index=False).encode())
    with open(filename, 'wb') as f_out:
        f_out.write(tok)
    trail.append({"event":"encrypt","file": filename, "count": len(df)})

def save_trail():
    trail.append({"event":"end","time": now_utc().isoformat()})
    json.dump(trail, open(AUDIT_TRAIL, 'w'), indent=2)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--income', type=float, required=True)
    parser.add_argument('--consent', choices=['yes','no'], required=True)
    parser.add_argument('--export-clean', action='store_true')
    parser.add_argument('--delete-crypt', action='store_true')
    args = parser.parse_args()

    if args.consent != 'yes':
        sys.exit(1)

    payload = {"sub": "student", "scope": ["run"], "exp": now_utc() + timedelta(hours=1)}
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    try:
        pl = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if 'run' not in pl.get('scope', []): raise
    except Exception:
        sys.exit(1)

    run_static_analysis()
    df = load_and_sanitize()
    df, model = detect_anomalies(df)
    exps = explain_amount(df)
    audit_bias(df)

    if args.export_clean:
        df.to_csv('clean_data.csv', index=False)

    bets = df[df['Description'].str.upper().str.contains('|'.join(VENDORS))]
    if not bets.empty:
        total = -bets[bets['Amount'] < 0]['Amount'].sum()
        ratio = total / args.income
        encrypt_data(bets, 'enc_data.bin')

    if args.delete_crypt:
        os.remove('enc_data.bin')

    save_trail()

if __name__ == '__main__':
    main()
