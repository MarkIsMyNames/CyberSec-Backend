# SecureMsg

A FastAPI backend for Signal-protocol end-to-end encrypted messaging with post-quantum key exchange (ML-KEM-1024).

## Threat Model

- **Confidentiality**: Messages are E2E encrypted; the server stores and relays ciphertext only.
- **Post-quantum forward secrecy**: PQXDH hybrid key exchange (X25519 + ML-KEM-1024) protects against harvest-now-decrypt-later attacks.
- **Authentication**: SRP-6a zero-knowledge password proof (server never sees plaintext), TOTP 2FA, JWT access/refresh tokens.
- **Integrity**: AES-256-GCM AEAD; Ed25519 signed prekeys prevent key substitution.
- **Known limitations**: No sealed sender (server sees social graph); TOFU trust model; Ed25519 signatures not post-quantum.

## Tech Stack

- Python 3.13, FastAPI, PostgreSQL (psycopg2)
- `cryptography` — AES-256-GCM, HKDF-SHA256/SHA512, X25519, Ed25519
- `liboqs-python` (`oqs`) — ML-KEM-1024
- `srp` — SRP-6a zero-knowledge password authentication
- `PyJWT` — JWT tokens (HS256)
- `pyotp` — TOTP 2FA
- `slowapi` — rate limiting
- Pydantic v2 — strict request/response validation

---

## Setup

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Local Development

For local development, export the three secrets directly in your shell. Do not create a `.env` file.

```bash
export SERVER_MASTER_SECRET=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export JWT_SECRET_KEY=dev_jwt_secret_key
export DATABASE_URL=postgresql://user:pass@localhost/securemsg
uvicorn app.main:application --host 127.0.0.1 --port 8000
```

> Note: the ASGI app is `app.main:application` (the `SecurityHeadersMiddleware`-wrapped instance), not `app.main:app`.

---

## VM Setup (Production)

All production secrets are managed by HashiCorp Vault. There is no `.env` file on the server.

### Step 1 — Install Vault

```bash
sudo apt-get update && sudo apt-get install -y gpg curl
```

```bash
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
```

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
```

```bash
sudo apt-get update && sudo apt-get install -y vault
```

Verify:

```bash
vault --version
```

---

### Step 2 — Create Vault User and Directories

```bash
sudo useradd --system --home /etc/vault --shell /bin/false vault
```

```bash
sudo mkdir -p /etc/vault /var/lib/vault/data /var/log/vault
```

```bash
sudo chown -R vault:vault /etc/vault /var/lib/vault /var/log/vault
```

```bash
sudo chmod 750 /etc/vault /var/lib/vault /var/log/vault
```

---

### Step 3 — Write Vault Config

```bash
sudo nano /etc/vault/config.hcl
```

Type the following, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```hcl
ui = false

storage "file" {
  path = "/var/lib/vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8200"
```

```bash
sudo chown vault:vault /etc/vault/config.hcl && sudo chmod 640 /etc/vault/config.hcl
```

---

### Step 4 — Create and Start the Vault systemd Service

```bash
sudo nano /etc/systemd/system/vault.service
```

Type the following, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```ini
[Unit]
Description=HashiCorp Vault
Documentation=https://developer.hashicorp.com/vault/docs
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault/config.hcl

[Service]
Type=notify
User=vault
Group=vault
ExecStart=/usr/bin/vault server -config=/etc/vault/config.hcl
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
```

```bash
sudo systemctl enable vault
```

```bash
sudo systemctl start vault
```

Verify:

```bash
sudo systemctl is-active vault
```

If not active, check logs:

```bash
sudo journalctl -u vault -n 20 --no-pager
```

---

### Step 5 — Initialise and Unseal Vault

> Do this **once only**. Save the unseal key and root token in a password manager — you need the unseal key after every VM reboot.

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
```

```bash
vault operator init -key-shares=1 -key-threshold=1
```

Output:
```
Unseal Key 1: <save this>
Initial Root Token: <save this>
```

Unseal (replace `<unseal-key>` with the key above):

```bash
vault operator unseal <unseal-key>
```

Log in (replace `<root-token>` with the token above):

```bash
vault login <root-token>
```

---

### Step 6 — Enable Audit Logging and KV Engine

```bash
vault audit enable file file_path=/var/log/vault/audit.log
```

```bash
vault secrets enable -path=secret kv-v2
```

Store your real application secrets (open nano to fill in values):

```bash
nano /tmp/store-secrets.sh
```

Type the following, replacing the placeholders with your real values, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```bash
#!/bin/bash
export VAULT_ADDR='http://127.0.0.1:8200'
vault kv put secret/securemsg/prod \
  SERVER_MASTER_SECRET="YOUR_64_HEX_CHAR_VALUE_HERE" \
  JWT_SECRET_KEY="$(openssl rand -base64 48)" \
  DATABASE_URL="postgresql://YOUR_USER:YOUR_PASSWORD@localhost/securemsg"
```

```bash
chmod +x /tmp/store-secrets.sh && bash /tmp/store-secrets.sh && rm /tmp/store-secrets.sh
```

Verify:

```bash
vault kv get secret/securemsg/prod
```

---

### Step 7 — Configure AppRole Auth

```bash
nano /tmp/securemsg-app.hcl
```

Type the following, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```hcl
path "secret/data/securemsg/prod" {
  capabilities = ["read"]
}
path "secret/data/securemsg/blockchain" {
  capabilities = ["read"]
}
```

```bash
vault policy write securemsg-app /tmp/securemsg-app.hcl && rm /tmp/securemsg-app.hcl
```

```bash
nano /tmp/securemsg-deploy.hcl
```

Type the following, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```hcl
path "secret/data/securemsg/prod" {
  capabilities = ["create", "update"]
}
path "secret/data/securemsg/blockchain" {
  capabilities = ["create", "update"]
}
```

```bash
vault policy write securemsg-deploy /tmp/securemsg-deploy.hcl && rm /tmp/securemsg-deploy.hcl
```

```bash
vault auth enable approle
```

```bash
vault write auth/approle/role/securemsg-app \
  token_policies="securemsg-app" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0
```

Get the role_id (save it):

```bash
vault read auth/approle/role/securemsg-app/role-id
```

Get the secret_id (save it):

```bash
vault write -f auth/approle/role/securemsg-app/secret-id
```

Create the deploy token for GitHub Actions (save it — add to GitHub Actions secrets as `VAULT_DEPLOY_TOKEN`):

```bash
vault token create -policy="securemsg-deploy" -ttl=0 -period=720h
```

---

### Step 8 — Clone Repo and Install Dependencies

```bash
cd /home/student
git clone https://github.com/MarkIsMyNames/CyberSec-Backend.git
cd CyberSec-Backend
python3 -m venv .venv
.venv/bin/pip install --upgrade pip --quiet
.venv/bin/pip install -r requirements.txt --quiet
```

---

### Step 9 — Write Credentials File and securemsg Service

```bash
sudo mkdir -p /etc/securemsg
```

Open nano to fill in the role_id and secret_id from Step 7:

```bash
sudo nano /etc/securemsg/vault-credentials
```

Type the following (replace the placeholders), then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```
VAULT_ROLE_ID=<role_id from Step 7>
VAULT_SECRET_ID=<secret_id from Step 7>
VAULT_ADDR=http://127.0.0.1:8200
```

```bash
sudo chown root:student /etc/securemsg/vault-credentials && sudo chmod 640 /etc/securemsg/vault-credentials
```

```bash
sudo nano /etc/systemd/system/securemsg.service
```

Type the following, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```ini
[Unit]
Description=SecureMsg FastAPI backend
After=network-online.target vault.service
Requires=vault.service

[Service]
Type=simple
User=student
Group=student
WorkingDirectory=/home/student/CyberSec-Backend
EnvironmentFile=/etc/securemsg/vault-credentials
ExecStart=/home/student/CyberSec-Backend/.venv/bin/uvicorn app.main:application --host 0.0.0.0 --port 80
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo setcap 'cap_net_bind_service=+ep' $(readlink -f /home/student/CyberSec-Backend/.venv/bin/python3)
```

Verify:

```bash
getcap $(readlink -f /home/student/CyberSec-Backend/.venv/bin/python3)
```

Expected: `python3.x = cap_net_bind_service+ep`

```bash
sudo systemctl daemon-reload && sudo systemctl enable securemsg
```

---

### Step 10 — Install auditd and Create Canary Rule

```bash
sudo apt-get install -y auditd
```

```bash
sudo nano /etc/audit/rules.d/securemsg-canary.rules
```

Type the following, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```
-w /home/student/CyberSec-Backend/.env -p r -k canary_read
-w /etc/securemsg/vault-credentials -p r -k vault_credentials_read
```

```bash
sudo augenrules --load
```

```bash
sudo systemctl enable auditd && sudo systemctl restart auditd
```

Verify:

```bash
sudo systemctl is-active auditd
```

```bash
sudo auditctl -l | grep canary_read
```

Create believable-looking canary values with openssl:

```bash
echo "SERVER_MASTER_SECRET=$(openssl rand -hex 32)"
echo "JWT_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')"
echo "DATABASE_URL=postgresql://securemsg:$(openssl rand -hex 12)@localhost/securemsg"
```

Run all three commands and note the output. Then open the canary file:

```bash
nano /home/student/CyberSec-Backend/.env
```

Type the following using the values generated above, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```
SERVER_MASTER_SECRET=<output of first command>
JWT_SECRET_KEY=<output of second command>
DATABASE_URL=<output of third command>
```

```bash
chmod 644 /home/student/CyberSec-Backend/.env
```

---

### Step 11 — Store Blockchain Credentials in Vault

Store the blockchain credentials (contract address, RPC URL, and wallet private key) in Vault:

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
vault login <root-token from Step 5>
```

```bash
nano /tmp/store-blockchain.sh
```

Type the following, replacing the placeholders, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```bash
#!/bin/bash
export VAULT_ADDR='http://127.0.0.1:8200'
vault kv put secret/securemsg/blockchain \
  WALLET_PRIVATE_KEY="0xYOUR_PRIVATE_KEY_HERE" \
  ALCHEMY_RPC_URL="https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY" \
  CONTRACT_ADDRESS="0xYOUR_DEPLOYED_CONTRACT_ADDRESS"
```

```bash
chmod +x /tmp/store-blockchain.sh && bash /tmp/store-blockchain.sh && rm /tmp/store-blockchain.sh
```

---

### Step 12 — Create audit-watcher Service

```bash
sudo nano /etc/systemd/system/audit-watcher.service
```

Type the following, then save with `Ctrl+O`, `Enter`, `Ctrl+X`:

```ini
[Unit]
Description=SecureMsg canary audit watcher
After=vault.service auditd.service
Requires=vault.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/student/CyberSec-Backend
EnvironmentFile=/etc/securemsg/vault-credentials
ExecStart=/home/student/CyberSec-Backend/.venv/bin/python -m app.audit_watcher
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable audit-watcher
```

```bash
sudo systemctl start audit-watcher
```

Verify:

```bash
sudo systemctl is-active audit-watcher
```

```bash
sudo journalctl -u audit-watcher -n 20 --no-pager
```

---

### Viewing Audit Events

#### On-chain (Sepolia Etherscan)

Every access event is recorded as an immutable `SecretAccess` log on Sepolia. To view them:

1. Go to [sepolia.etherscan.io](https://sepolia.etherscan.io)
2. Search your deployed contract address
3. Click the **Logs** tab

Each entry shows:
- `eventHash` — keccak256 hash of `(block.timestamp, pid, uid, path)` — tamper-evident proof the event occurred without exposing raw values on-chain. 
  - `block.timestamp` — Unix timestamp at the moment of recording (same as the emitted `timestamp` field)
  - `pid` — process ID of the process that triggered the access
  - `uid` — OS user ID of the process
  - `path` — file or Vault path accessed: `/home/student/CyberSec-Backend/.env` (canary), `/etc/securemsg/vault-credentials` (AppRole credentials), or `secret/data/securemsg/prod` (real Vault secret). The path alone identifies what was accessed.
- `timestamp` — Unix block timestamp of when the event was recorded on-chain
- `reporter` — wallet address that submitted the transaction (indexed, so you can filter Etherscan by your server wallet)

#### Pre-hashed raw data (local VM)

The raw details for each event are logged locally in `securemsg.log` alongside the transaction hash, so you can correlate on-chain records back to the original event:

```bash
grep "on-chain event submitted" /home/student/CyberSec-Backend/securemsg.log
```

To verify an on-chain hash matches a local log entry, take the `tx` hash from the local log, look it up on Sepolia Etherscan, and confirm the `eventHash` in the transaction matches what you expect.

---

### After Every VM Reboot

Vault seals itself on reboot. After any reboot, unseal before starting the services:

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
vault operator unseal <your-unseal-key>
sudo systemctl start securemsg
sudo systemctl start audit-watcher
```

---

### Run

#### Production

The API is publicly accessible at **https://BobbyTables.theburkenator.com**. TLS is terminated at the gateway (Let's Encrypt, A+ rated). The app listens on port 80 internally:

```bash
sudo systemctl start securemsg
```

---

## API Reference

All endpoints are prefixed with `/api/v1`.

### Auth

#### `POST /auth/register`

Register a new user. The client computes the SRP verifier locally from the password — the server never receives the plaintext password. Returns TOTP provisioning URI for 2FA setup.


**Request body:**
```json
{"username": "alice", "srp_salt": "<hex>", "srp_verifier": "<hex>"}
```

The client generates `srp_salt` and `srp_verifier` using SRP-6a with a 4096-bit group (`NG_4096`) and SHA-256.

**Response `201`:**
```json
{"user_id": 1, "totp_provisioning_uri": "otpauth://totp/SecureMsg:alice?secret=..."}
```

**Errors:** `409` — username taken. `422` — username invalid or hex fields malformed. `429` — rate limit exceeded.

---

#### `POST /auth/srp-init`

Step 1 of SRP login. Client sends its public ephemeral value; server responds with the stored salt and its own public ephemeral value.


**Request body:**
```json
{"username": "alice", "client_public": "<hex A>"}
```

**Response `200`:**
```json
{"session_id": "<token>", "srp_salt": "<hex>", "server_public": "<hex B>"}
```

**Errors:** `401` — unknown username. `429` — rate limit exceeded.

---

#### `POST /auth/srp-verify`

Step 2 of SRP login. Client proves knowledge of the password; server returns its own proof and a pre-auth token for TOTP.


**Request body:**
```json
{"session_id": "<token>", "client_proof": "<hex M1>"}
```

**Response `200`:**
```json
{"server_proof": "<hex M2>", "pre_auth_token": "<token>"}
```

The client **must** verify `server_proof` before trusting the session — this proves the server also holds the correct verifier.

**Errors:** `401` — wrong password or expired/missing session. `429` — rate limit exceeded.

---

#### `POST /auth/verify-2fa`

Step 2 of 2FA login. Validates TOTP code; returns access and refresh tokens.


**Request body:**
```json
{"totp_code": "123456", "pre_auth_token": "<token>"}
```

**Response `200`:**
```json
{"access_token": "...", "refresh_token": "..."}
```

**Errors:** `401` — invalid/expired pre-auth token or wrong TOTP code. `429` — rate limit exceeded.

---

#### `POST /auth/refresh`

Exchange a refresh token for new access + refresh tokens. Refresh tokens are single-use.


**Request body:**
```json
{"refresh_token": "<token>"}
```

**Response `200`:**
```json
{"access_token": "...", "refresh_token": "..."}
```

**Errors:** `401` — invalid, expired, or already-used refresh token. `429` — rate limit exceeded.

---

#### `POST /auth/logout`

Revoke a refresh token.


**Request body:**
```json
{"refresh_token": "<token>"}
```

**Response `204`:** No content.

**Errors:** `401` — invalid, expired, or already-used refresh token. `429` — rate limit exceeded.

---

#### `DELETE /auth/me`

Delete the authenticated user's own account and all associated data.

On deletion: the user record is removed; all messages sent by or addressed to the user are deleted; all group memberships are removed (the group itself is deleted if the user was the last member); all key bundles and prekeys are deleted. The access token is immediately invalidated — subsequent requests with the same token return `401`.

**Response `204`:** No content.

**Errors:** `401` — missing, invalid, or expired access token, or user already deleted. `429` — rate limit exceeded.

---

### Keys

#### `POST /keys/bundle`

Publish the user's key bundle (identity key, signed prekey, OPKs, ML-KEM-1024 prekey).


**Request body:**
```json
{
  "identity_pub": "<base64>",
  "signed_prekey_pub": "<base64>",
  "signed_prekey_sig": "<base64, 64 bytes>",
  "one_time_prekeys": ["<base64>", "..."],
  "pq_prekey_pub": "<base64, 1184 bytes>",
  "pq_prekey_sig": "<base64, 64 bytes>"
}
```

**Response `204`:** No content.

**Errors:** `401` — bad token. `422` — missing or invalid fields. `429` — rate limit exceeded.

---

#### `POST /keys/prekeys`

Upload additional one-time prekeys.


**Request body:**
```json
{"one_time_prekeys": ["<base64>", "..."]}
```

**Response `204`:** No content.

**Errors:** `401` — bad token. `422` — invalid base64. `429` — rate limit exceeded.

---

#### `GET /keys/prekeys/count`

Return the number of one-time prekeys the server holds for the authenticated user. Clients should poll this periodically and upload more prekeys when the count falls below a threshold (Signal recommends replenishing when fewer than 10 remain).


**Response `200`:**
```json
{"count": 7}
```

**Errors:** `401` — bad token. `429` — rate limit exceeded.

---

#### `GET /keys/lookup/by-username`

Look up a user's identity public key and user ID by username. Use this to find someone before initiating a session — type their username, get their identity key to verify trust and their user ID to call subsequent API endpoints.


**Query parameters:** `username=<string>`

**Response `200`:**
```json
{"user_id": 1, "identity_pub": "<base64>"}
```

**Errors:** `404` — username not found or user has no published key bundle. `429` — rate limit exceeded.

---

#### `GET /keys/{user_id}`

Fetch a key bundle for initiating a session. Pops one OPK (consumed, non-repeating). If no OPKs remain, `one_time_prekey` is `null`.


**Response `200`:**
```json
{
  "user_id": 1,
  "identity_pub": "<base64>",
  "signed_prekey_pub": "<base64>",
  "signed_prekey_sig": "<base64>",
  "one_time_prekey": "<base64 or null>",
  "pq_prekey_pub": "<base64>",
  "pq_prekey_sig": "<base64>"
}
```

**Errors:** `404` — user not found or has no bundle. `429` — rate limit exceeded.

---

### Messages

#### `POST /messages/`

Send an encrypted message.


**Request body:**
```json
{
  "recipient_id": 2,
  "ciphertext": "<base64>",
  "ratchet_header_enc": "<base64>"
}
```

**Response `201`:**
```json
{"id": 1}
```

**Errors:** `403` — cannot send a message to yourself. `422` — invalid base64 fields. `429` — rate limit exceeded.

---

#### `GET /messages/`

List messages addressed to the authenticated user.

**Response `200`:**
```json
[
  {
    "id": 1,
    "sender_id": 3,
    "ciphertext": "<base64>",
    "ratchet_header_enc": "<base64>"
  }
]
```

**Errors:** `429` — rate limit exceeded.

---

#### `POST /messages/{message_id}/receipt`

Acknowledge receipt (deletes the message from server storage).


**Response `204`:** No content.

**Errors:** `403` — not the recipient. `404` — message not found. `429` — rate limit exceeded.

---

#### `DELETE /messages/{message_id}`

Revoke a sent message.


**Response `204`:** No content.

**Errors:** `403` — not the sender. `404` — message not found. `429` — rate limit exceeded.

---

### Groups

#### `GET /groups/`

List all groups the authenticated user is a member of.

**Response `200`:**
```json
{
  "groups": [
    {"id": 1, "name": "my-group", "members": [1, 2, 3], "epoch": 0}
  ]
}
```

**Errors:** `429` — rate limit exceeded.

---

#### `POST /groups/`

Create a new group. Creator becomes the first member.

**Request body:**
```json
{
  "name": "my-group",
  "initial_members": {
    "2": "<base64 skdm ciphertext for user 2>",
    "3": "<base64 skdm ciphertext for user 3>"
  }
}
```

Each key is a user ID (as a string); the value is the creator's sender key encrypted pairwise for that member. Omit `initial_members` (or pass `{}`) to create an empty group.

**Response `201`:**
```json
{"id": 1}
```

**Errors:** `422` — invalid fields. `429` — rate limit exceeded.

---

#### `GET /groups/{group_id}`

Get group details and member list.


**Response `200`:**
```json
{"id": 1, "name": "my-group", "members": [1, 2, 3], "epoch": 2}
```

**Errors:** `403` — not a member. `404` — group not found. `429` — rate limit exceeded.

---

#### `POST /groups/{group_id}/members`

Add a member to a group (creator only). The request body must include the creator's sender key encrypted for the new member.


**Request body:**
```json
{
  "user_id": 5,
  "skdm_ciphertext": "<base64 sender-key encrypted for user 5>"
}
```

**Response `204`:** No content.

**Errors:** `403` — not the creator. `429` — rate limit exceeded.

---

#### `DELETE /groups/{group_id}/members/{user_id}`

Remove a member, or leave the group by supplying your own `user_id`. If the removed user was the creator, the member with the lowest user ID is promoted. If removal leaves only one member the group is deleted automatically.

When the creator forcibly removes another member, the request body must include fresh sender keys for all remaining members. Voluntary leave does not require a body.


**Request body (forced removal only):**
```json
{
  "skdm_ciphertexts": {
    "<recipient_user_id>": "<base64-encoded ciphertext>",
    "...": "..."
  }
}
```

**Response `204`:** No content.

**Errors:** `403` — attempting to remove another member without being the owner. `404` — target user is not a member. `429` — rate limit exceeded.

---

#### `POST /groups/{group_id}/messages`

Send an encrypted message to a group.


**Request body:**
```json
{"epoch": 2, "ciphertext": "<base64>"}
```

**Response `201`:**
```json
{"id": 1}
```

**Errors:** `403` — not a member. `429` — rate limit exceeded.

---

#### `GET /groups/{group_id}/messages`

List messages in a group.


**Response `200`:**
```json
[
  {
    "id": 1,
    "group_id": 1,
    "epoch": 2,
    "ciphertext": "<base64>"
  }
]
```

**Errors:** `403` — not a member. `429` — rate limit exceeded.

---

#### `DELETE /groups/{group_id}/messages/{msg_id}`

Revoke a group message.


**Response `204`:** No content.

**Errors:** `403` — not the sender or not a member. `404` — message not found. `429` — rate limit exceeded.

---

#### `POST /groups/{group_id}/messages/{msg_id}/receipt`

Acknowledge receipt of a group message. The message is deleted from server storage once all recipients have acknowledged it.


**Response `204`:** No content.

**Errors:** `403` — not a member. `429` — rate limit exceeded.

---

#### `POST /groups/{group_id}/skdm`

Distribute sender keys to group members. Each key is a recipient user ID; the value is the sender key encrypted pairwise for that member. Call this after an epoch change.


**Request body:**
```json
{"skdm_ciphertexts": {"2": "<base64>", "3": "<base64>"}}
```

**Response `204`:** No content.

**Errors:** `403` — not a member. `404` — group not found. `429` — rate limit exceeded.

---

#### `GET /groups/{group_id}/skdm`

Fetch and consume all pending sender key distribution messages for this group. Consume-on-read — entries are deleted after being returned. Call this after joining a group, after an epoch change and periodically.


**Response `200`:**
```json
{
  "skdm_ciphertexts": [
    {"epoch": 2, "ciphertext": "<base64>"}
  ]
}
```

Current key is the one whose `epoch` is the highest. It won't be known to the removed member.

**Errors:** `403` — not a member. `429` — rate limit exceeded.

---

## Security Design Decisions

### Authentication

**Secure Remote Password (SRP-6a)** — zero-knowledge password proof using a 4096-bit group and SHA-256. The server never receives the plaintext password. The client computes `v = g^x mod N` locally; the server stores the encrypted verifier. An attacker must complete a live handshake, which is rate-limited. Both sides exchange mutual proofs (M1/M2), so a compromised server cannot silently accept any password. A MITM cannot silently relay the handshake — they would need to independently solve both halves of the SRP exchange simultaneously.

**TOTP 2FA** — required after every SRP handshake. TOTP secrets are encrypted at rest with AES-256-GCM; the key is derived from `SERVER_MASTER_SECRET` via HKDF-SHA256.

**JWT tokens** — short-lived access tokens (15 min) plus single-use refresh tokens. Refresh tokens are revoked immediately on use and blocklisted on logout. The signing secret (`JWT_SECRET_KEY`) is rotated on every deploy, invalidating all active sessions.

### End-to-End Encryption

**PQXDH session init** — hybrid KEM (X25519 + ML-KEM-1024) produces the initial shared secret seeding the Double Ratchet. Both primitives must be broken to compromise the session. One-time prekeys ensure each session derives a unique secret, providing forward secrecy for session establishment — compromise of long-term keys does not expose past sessions.

**Double Ratchet** — symmetric chain ratchet provides per-message forward secrecy; DH ratchet provides break-in recovery. The ratchet header is encrypted (`ratchet_header_enc`) to hide session progression metadata from the server.

**Sender Key (groups)** — each sender maintains a chain key that advances per message, avoiding O(n) encryptions per group message. SKDMs are encrypted pairwise using the same PQXDH hybrid KEM.

**Group epoch** — increments on every key change. Clients must regenerate and redistribute their sender key when the epoch advances. SKDMs stamped with an old epoch must be discarded.

> `sender_id` is stored for server-side revocation authorisation only. Clients must not use it to verify message origin — authenticity requires verifying the Ed25519 signature against the sender's published identity key.

### Message Revocation

Authorised by identity: the server checks `sender_id` matches the authenticated user.

### TLS and Security Headers

TLS 1.2/1.3 terminated at the gateway. HSTS (`max-age=63072000; includeSubDomains`) set on all responses. Security headers injected at the ASGI layer so they are present on all responses including FastAPI error responses:

| Header | Value | Why |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Tells browsers to use HTTPS only for 2 years; prevents protocol downgrade attacks |
| `X-Frame-Options` | `DENY` | Prevents the app being embedded in an iframe, blocking clickjacking |
| `X-Content-Type-Options` | `nosniff` | Stops browsers guessing MIME types, preventing content-sniffing attacks |
| `Content-Security-Policy` | `default-src 'none'` | Blocks all resource loading; appropriate for a pure API with no frontend |
| `Referrer-Policy` | `no-referrer` | Suppresses the `Referer` header, preventing URL leakage to third parties |
| `Server` | *(removed)* | Strips the uvicorn banner so attackers cannot fingerprint the software version |

---

## Why PostgreSQL

SQLite was used initially but replaced with PostgreSQL for two reasons:

- **Concurrent connections** — SQLite serialises all writes with a single file lock. PostgreSQL handles many simultaneous writers without contention, which is essential for a multi-user messaging backend.
- **Production readiness** — SQLite is a file on disk with no access control. PostgreSQL has proper user permissions and connection pooling.

---

## Why FastAPI

- **Async-native** — FastAPI uses `async`/`await` so a single thread can handle many requests concurrently. Flask assigns one thread per request — that thread sits idle while waiting for the database to respond. Under load this means hundreds of blocked threads. With async, the thread moves on to the next request while waiting, so far fewer threads are needed.
- **Pydantic validation** — every request body is validated before the handler runs. Invalid fields, bad base64, or unexpected keys all return `422` automatically with no application code executed.
- **Dependency injection** — `Depends()` centralises auth and repo wiring. Swapping a dependency in tests requires no changes to the handler.

---

## Known Limitations

- **No sealed sender** — the server can observe who messages whom (social graph visible).
- **TOFU trust model** — the first published key bundle is trusted unconditionally; no key transparency log. A transparency log would not fully solve this anyway: the server controls the log and could show Alice and Bob two different versions (a split-view attack), each internally consistent. The standard mitigation is gossip — clients exchange the root hash they've seen so discrepancies are detected — but the server could simply drop gossip packets, silently preventing detection without either client knowing.
- **Ed25519 not post-quantum** — unlike encryption, signatures are not vulnerable to store-now-decrypt-later attacks. Post-quantum signature schemes (ML-DSA, SLH-DSA) produce signatures 10–50× larger than Ed25519's 64 bytes, adding significant overhead per message. They are also recent NIST standards with far less real-world scrutiny than Ed25519.
- **SRP-6a not post-quantum** — Shor's algorithm breaks discrete log, so a quantum attacker with a stolen verifier database could recover passwords. The post quantum replacement is OPAQUE, but no pip-installable Python implementation exists yet, and as a relatively new protocol it has had less real-world scrutiny than SRP.
- **No Device Bound Service Credentials** — access tokens are not device-bound. Device binding is straightforward in browsers via the Web Authentication API (WebAuthn), but we've to build our own client; adding device-binding scheme would add significant complexity.

---

## CI / GitHub Actions

Every push and pull request to `main` runs the following workflows:

| Workflow | Tool | What it checks |
|---|---|---|
| Unit + Security Tests | `pytest` + `coverage` | All tests (unit and OWASP security); enforces ≥95% line coverage |
| Type Check | `mypy` | Static type correctness across `app/` |
| Lint | `ruff`, `black` | Style and formatting |
| Security Scan | `bandit` | Static analysis for common security anti-patterns |
| Secret Scanning | `gitleaks` | Hardcoded secrets / credentials in commits and working tree |
| Dependency Audit | `pip-audit` | Known CVEs in dependencies |

### Cryptographic Security Levels

| Primitive | Key size | Usage | Classical security | Post-quantum security |
|---|---|---|---|---|
| AES-256-GCM | 256-bit | Symmetric encryption (TOTP secrets, SRP verifiers at rest) | 256-bit | 128-bit (Grover halves key search) |
| X25519 | 255-bit | ECDH key exchange (X3DH, Double Ratchet) | 128-bit | Broken by Shor's algorithm |
| ML-KEM-1024 | 1184-byte public key | Post-quantum KEM (PQXDH) — NIST Level 5 | 256-bit | 128-bit |
| X25519 + ML-KEM-1024 hybrid | — | Session key establishment | 128-bit | 128-bit (both must be broken) |
| Ed25519 | 256-bit | Prekey signatures | 128-bit | Broken by Shor's algorithm |
| SRP-6a (NG_4096, SHA-256) | 4096-bit group | Password authentication | ~140-bit | Broken by Shor's algorithm |
| HKDF-SHA256 | 256-bit output | Key derivation | 128-bit | 128-bit |
| JWT HS256 | 256-bit | Token signing | 128-bit | 128-bit |

## Running Tests Locally

### All tests

```bash
pytest app/ -v
```

### With coverage

```bash
coverage run -m pytest app/ -v
coverage report --fail-under=95
```

### Security tests only

```bash
pytest app/security_tests/ -v
```

### Integration tests

Live integration tests run against the deployed server and require no local database or environment variables.

```bash
pytest tests/integration/ -v --tb=short
```

The suite registers a temporary user via the full SRP+TOTP flow, exercises every endpoint, then deletes the user at teardown. Rate-limited requests are automatically retried using the `Retry-After` header. All connections enforce TLS 1.2 or higher — the test suite fails if the server cannot negotiate at least TLS 1.2.

---

## Deploy Pipeline

Every push to `main` triggers the deploy-and-test workflow (`.github/workflows/deploy.yml`):

1. **Deploy job** — SSHes into the VM at `200.69.13.70:2206`, pulls the latest code via `git pull --ff-only`, reinstalls Python dependencies only when `requirements.txt` has changed (hash cached at `~/.cache/securemsg_dep_hash`), rotates `JWT_SECRET_KEY` by generating a fresh secret and updating `/home/student/CyberSec-Backend/.env` (invalidating all active sessions on every deploy), restarts the `securemsg` systemd service, then polls `https://BobbyTables.theburkenator.com/health` every 2s for up to 60s. The job fails if the health check does not return `200 OK` within that window.

2. **Test job** — Runs only after the deploy job succeeds. Checks out the repo, installs `requirements.txt`, and runs `pytest tests/integration/` against the live server.

**Required GitHub secret:** `VM_SSH_KEY` — the private SSH key for the deployment VM.

Run results are visible in the **Actions** tab of the repository.
