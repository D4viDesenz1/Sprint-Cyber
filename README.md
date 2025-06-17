# GoldenGuard

## 👥 Participantes
- **Márcio Gastaldi** – RM98811  
- **Arthur Bessa Pian** – RM99215  
- **Davi Desenzi** – RM550849  
- **João Victor** – RM551410  

---

## 💡 Ideia Inicial do Projeto

**GoldenGuard** é um aplicativo móvel que visa ajudar pessoas a identificarem e controlarem comportamentos relacionados ao vício em apostas online. O app:

- Analisa automaticamente o extrato bancário do usuário.
- Detecta transações com casas de apostas.
- Classifica e resume valores depositados e recebidos em cada casa.
- Emite alertas quando os gastos ultrapassam 30% do salário declarado.

---

## Sanitização e Processamento

- Leitura do CSV de transações (`extrato.csv`)
- Conversão e validação de campos: datas e valores
- Remoção de registros inválidos
- Análise estática de segurança com **Bandit**
- Detecção de anomalias com **IsolationForest**

---

## Explicação de Saídas (XAI)

- Cálculo de importância com base no valor absoluto da transação (`Amount`)
- Geração de `explanations.json` com scores de importância para auditoria

---

## Mitigação de Vieses

- Cálculo da taxa de anomalias por descrição (`vendor`)
- Geração de `bias_audit.json` para avaliação de fairness

---

## Conformidade com LGPD

- Consentimento explícito via argumento `--consent yes`
- Criptografia de dados sensíveis com **Fernet** (`enc_data.bin`)
- Exportação opcional do CSV limpo (`--export-clean`)
- Registro de todas as ações em `audit_trail.json`

---

## Segurança Avançada

- **JWT**: autenticação baseada em tokens com escopo de execução
- **MFA**: segundo fator via **TOTP** (Google Authenticator)
- Gerenciamento de segredos em arquivos (JWT e MFA)

---

## Design Ético

- Carregamento de diretrizes de ética via `ethics_guidelines.json`
- Remoção de dados pessoais (PII)
- Rastreabilidade completa das operações

---

## Como Rodar

### Instalar dependências

```bash
pip install pandas numpy scikit-learn cryptography PyJWT bandit pyotp
````

### Executar o script

```bash
python goldenguard.py --income 5000 --consent yes --export-clean --delete-crypt
```

* Insira o código **MFA** de 6 dígitos quando solicitado.
* O pipeline exibirá o status de cada etapa no terminal.

---

## 📤 Saídas

* `clean_data.csv`: cópia do CSV sanitizado
* `enc_data.bin`: dados de apostas criptografados
* `explanations.json`: scores de importância das transações
* `bias_audit.json`: relatório de fairness
* `audit_trail.json`: log completo das operações

---

## 📁 Estrutura de Arquivos

```plaintext
extrato.csv             # Entrada de transações
goldenguard.py          # Script principal
secret.key              # Chave Fernet para criptografia
jwt_secret.key          # Segredo para tokens JWT
mfa_secret.key          # Chave Base32 para TOTP
ethics_guidelines.json  # Diretrizes éticas carregadas
clean_data.csv          # CSV sanitizado (opcional)
enc_data.bin            # Dados de apostas criptografados
explanations.json       # Explicações de importância das transações
bias_audit.json         # Taxas de anomalias por descrição
audit_trail.json        # Registro de todas as ações do pipeline
```
