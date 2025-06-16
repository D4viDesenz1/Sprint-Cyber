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

# Configurações
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
THRESHOLD   = 0.3  # 30%


def now_utc():
    return datetime.now(timezone.utc)

# Carrega ou gera segredos JWT (Zero Trust)
def load_or_create_jwt_secret(path, size=32):
    if not os.path.exists(path):
        v = os.urandom(size)
        with open(path, 'wb') as f: f.write(v)
    else:
        v = open(path, 'rb').read()
    return v

JWT_SECRET = load_or_create_jwt_secret(JWT_FILE)

# Carrega ou gera chave de criptografia Fernet (base64 url-safe)
def load_or_create_fernet_key(path):
    if not os.path.exists(path):
        key = Fernet.generate_key()
        with open(path, 'wb') as f: f.write(key)
    else:
        key = open(path, 'rb').read()
    return key

# MFA secret (base32)
if not os.path.exists(MFA_FILE):
    MFA_SECRET = pyotp.random_base32()
    with open(MFA_FILE, 'w') as f: f.write(MFA_SECRET)
    print(f"🔐 Configure seu Authenticator com esta chave MFA: {MFA_SECRET}")
else:
    MFA_SECRET = open(MFA_FILE, 'r').read().strip()

# Diretrizes éticas
def load_guidelines():
    if not os.path.exists(GUIDELINES):
        g = {"privacy":"Não expor PII","fairness":"Evitar vieses","transparency":"Registrar auditoria"}
        with open(GUIDELINES, 'w') as f: json.dump(g, f, indent=2)
        return g
    return json.load(open(GUIDELINES))

g = load_guidelines()
print("⚙️ Diretrizes Éticas:")
for k, v in g.items(): print(f" - {k}: {v}")
print()

# MFA prompt e validação
print('🔑 Digite o código MFA de 6 dígitos do seu app:')
code = input('MFA code: ')
if not pyotp.TOTP(MFA_SECRET).verify(code):
    print('❌ Código MFA inválido')
    sys.exit(1)
print('✅ MFA validado com sucesso!')

# Iniciar trilha de auditoria
trail = []
trail.append({"event":"start","time": now_utc().isoformat()})

# Etapas do pipeline
def run_static_analysis():
    import subprocess
    print('🔍 Rodando análise estática (Bandit)...', flush=True)
    try:
        result = subprocess.run(['bandit', '-r', __file__], capture_output=True, text=True)
        # mostrar resultado resumido
        print('✅ Bandit concluído.', flush=True)
        print(result.stdout[:500], flush=True)
        trail.append({"event":"bandit","output": result.stdout[:200]})
    except FileNotFoundError:
        print('⚠️ Bandit não instalado; pulando.', flush=True)
        trail.append({"event":"bandit","error":"not installed"})

def load_and_sanitize():
    print('📥 Carregando e sanitizando CSV...')
    if not os.path.exists(CSV_FILE):
        print(f"❌ {CSV_FILE} não encontrado")
        sys.exit(1)
    df = pd.read_csv(CSV_FILE, parse_dates=['Date'])
    before = len(df)
    df['Amount'] = pd.to_numeric(df['Amount'], errors='coerce')
    df.dropna(subset=['Date','Description','Amount'], inplace=True)
    removed = before - len(df)
    print(f'✅ Sanitização removidas {removed} linhas inválidas.')
    trail.append({"event":"sanitize","removed": removed})
    return df


def detect_anomalies(df):
    print('🔎 Detectando anomalias...')
    model = IsolationForest(contamination=ANOMALY_CONT, random_state=0)
    df['anomaly'] = model.fit_predict(df[['Amount']])
    cnt = int((df['anomaly'] == -1).sum())
    print(f'✅ Encontradas {cnt} anomalias.')
    trail.append({"event":"anomaly_detected","count": cnt})
    return df, model


def explain_amount(df):
    vals = np.abs(df['Amount'].values)
    mn, mx = vals.min(), vals.max()
    norm = (vals - mn) / (mx - mn) if mx > mn else np.zeros_like(vals)
    exps = [[('Amount', float(v))] for v in norm]
    json.dump({'importance': norm.tolist()}, open(EXPLAIN_JSON, 'w'), indent=2)
    print(f'✅ Explicações salvas em {EXPLAIN_JSON}')
    trail.append({"event":"explain","file": EXPLAIN_JSON})
    return exps


def audit_bias(df):
    rates = df.groupby('Description')['anomaly'].apply(lambda x: float((x==-1).mean())).to_dict()
    json.dump(rates, open(BIAS_JSON, 'w'), indent=2)
    print(f'✅ Fairness auditado em {BIAS_JSON}')
    trail.append({"event":"bias_audit","file": BIAS_JSON})
    return rates


def encrypt_data(df, filename):
    print(f'🔒 Criptografando dados em {filename}...')
    key = load_or_create_fernet_key(KEY_FILE)
    fer = Fernet(key)
    tok = fer.encrypt(df.to_csv(index=False).encode())
    with open(filename, 'wb') as f_out:
        f_out.write(tok)
    print('✅ Criptografia concluída.')
    trail.append({"event":"encrypt","file": filename, "count": len(df)})({"event":"encrypt","file": filename, "count": len(df)})({"event":"encrypt","file": filename, "count": len(df)})


def save_trail():
    trail.append({"event":"end","time": now_utc().isoformat()})
    json.dump(trail, open(AUDIT_TRAIL, 'w'), indent=2)
    print(f'📝 Audit trail salvo em {AUDIT_TRAIL}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--income', type=float, required=True)
    parser.add_argument('--consent', choices=['yes','no'], required=True)
    parser.add_argument('--export-clean', action='store_true')
    parser.add_argument('--delete-crypt', action='store_true')
    args = parser.parse_args()

    if args.consent != 'yes':
        print('❌ É preciso --consent yes')
        sys.exit(1)

    # JWT autenticação
    payload = {"sub": "student", "scope": ["run"], "exp": now_utc() + timedelta(hours=1)}
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    try:
        pl = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if 'run' not in pl.get('scope', []): raise
    except Exception:
        print('❌ JWT inválido ou sem permissão')
        sys.exit(1)
    print('✅ JWT authenticated')
    print('--- Iniciando pipeline ---', flush=True)
    
    run_static_analysis()
    df = load_and_sanitize()
    df, model = detect_anomalies(df)
    exps = explain_amount(df)
    for i, e in enumerate(exps[:3], 1): print(f'Transação {i} importância: {e}')
    rates = audit_bias(df)
    print('Fairness rates:', rates)

    if args.export_clean:
        df.to_csv('clean_data.csv', index=False)
        print('✅ clean_data.csv gerado')
        trail.append({"event":"export_clean","file":"clean_data.csv"})

    bets = df[df['Description'].str.upper().str.contains('|'.join(VENDORS))]
    if bets.empty:
        print('Nenhuma aposta encontrada')
    else:
        total = -bets[bets['Amount'] < 0]['Amount'].sum()
        ratio = total / args.income
        print(('⚠️' if ratio > THRESHOLD else '✅'), f'{ratio:.1%} gasto em apostas')
        encrypt_data(bets, 'enc_data.bin')

    if args.delete_crypt:
        os.remove('enc_data.bin')
        print('🗑️ enc_data.bin removido')
        trail.append({"event":"delete_crypt"})

    save_trail()
    print('✅ Processo completo.')

if __name__ == '__main__':
    main()