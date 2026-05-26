#!/usr/bin/env bash
set -euo pipefail

# Run once on a fresh Ubuntu/Debian VM to set up SecureMsg.

APP="securemsg"
CURRENT_USER="$(whoami)"
REPO_DIR="$HOME/CyberSec-Backend"
VENV_DIR="$REPO_DIR/.venv"
VAULT_ADDR="http://127.0.0.1:8200"
CREDS_FILE="/etc/$APP/vault-credentials"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
section() { echo -e "\n${BOLD}━━━  $*  ━━━${RESET}"; }
die()     { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

trap 'echo -e "${RED}[✗]${RESET} Script failed at line $LINENO" >&2' ERR

# Prompts for a value; runs the generate command if left blank.
ask() {
    local prompt="$1" generate="$2"
    local value=""
    read -r -p "$prompt (leave blank to auto-generate): " value
    [ -z "$value" ] && value=$(eval "$generate")
    printf '%s' "$value"
}

# ─── Prerequisites ────────────────────────────
command -v jq &>/dev/null || sudo apt-get install -y -qq jq

# ─── PostgreSQL ───────────────────────────────
section "Setting up PostgreSQL"
command -v psql &>/dev/null || { info "Installing postgresql..."; sudo apt-get install -y -qq postgresql; }
info "Enabling postgresql service..."
sudo systemctl enable postgresql --quiet
sudo systemctl start postgresql
info "Checking database role..."
ROLE_EXISTS=false
if sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$APP'" | grep -q 1; then
    ROLE_EXISTS=true
    info "Role $APP already exists."
else
    info "Creating role $APP..."
    DB_PASS=$(openssl rand -hex 16)
    sudo -u postgres psql -c "CREATE USER $APP WITH PASSWORD '$DB_PASS';"
fi
info "Checking database..."
if ! sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$APP'" | grep -q 1; then
    info "Creating database $APP..."
    sudo -u postgres psql -c "CREATE DATABASE $APP OWNER $APP;"
fi
info "PostgreSQL ready."

# ─── Vault ────────────────────────────────────
section "Installing Vault"
if ! command -v vault &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq gpg curl
    curl -fsSL https://apt.releases.hashicorp.com/gpg \
        | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
        | sudo tee /etc/apt/sources.list.d/hashicorp.list > /dev/null
    sudo apt-get update -qq && sudo apt-get install -y -qq vault
fi
info "Vault $(vault version) ready."

section "Configuring Vault"
id vault &>/dev/null || sudo useradd --system --home /etc/vault --shell /bin/false vault
sudo mkdir -p /etc/vault /var/lib/vault/data /var/log/vault
sudo chown -R vault:vault /etc/vault /var/lib/vault /var/log/vault
sudo chmod 750 /etc/vault /var/lib/vault /var/log/vault

sudo tee /etc/vault/config.hcl > /dev/null <<'HCL'
ui = false
storage "file" { path = "/var/lib/vault/data" }
listener "tcp" {
  address   = "127.0.0.1:8200"
  tls_disable = true
}
api_addr = "http://127.0.0.1:8200"
HCL
sudo chown vault:vault /etc/vault/config.hcl
sudo chmod 640 /etc/vault/config.hcl

sudo tee /etc/systemd/system/vault.service > /dev/null <<'UNIT'
[Unit]
Description=HashiCorp Vault
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
UNIT

sudo systemctl daemon-reload
sudo systemctl enable vault --quiet
sudo systemctl start vault || true
sleep 2
sudo systemctl is-active --quiet vault || { sudo journalctl -u vault -n 20 >&2; die "Vault failed to start."; }
info "Vault service running."

section "Initialising Vault"
export VAULT_ADDR
if vault status 2>/dev/null | grep -q "Initialized.*true"; then
    warn "Vault already initialised — skipping init. Unseal manually if needed."
else
    INIT_OUTPUT=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
    UNSEAL_KEY=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[0]')
    ROOT_TOKEN=$(echo "$INIT_OUTPUT" | jq -r '.root_token')
    vault operator unseal "$UNSEAL_KEY" > /dev/null
    vault login "$ROOT_TOKEN" > /dev/null
    info "Vault initialised and unsealed."
fi

vault audit list 2>/dev/null | grep -q "file/" || vault audit enable file file_path=/var/log/vault/audit.log
vault secrets list 2>/dev/null | grep -q "secret/" || vault secrets enable -path=secret kv-v2

if [ "$ROLE_EXISTS" = true ]; then
    info "Reading database password from Vault..."
    DB_PASS=$(vault kv get -field=DATABASE_URL secret/$APP/prod 2>/dev/null \
        | grep -oP '(?<=://'"$APP"':)[^@]+' || true)
    if [ -z "$DB_PASS" ]; then
        info "No existing secret found — generating new password and updating role..."
        DB_PASS=$(openssl rand -hex 16)
        sudo -u postgres psql -c "ALTER USER $APP WITH PASSWORD '$DB_PASS';"
    fi
fi
DATABASE_URL="postgresql://$APP:$DB_PASS@localhost/$APP"

# ─── Secrets ──────────────────────────────────
section "Storing secrets"
if s secret/$APP/prod &>/dev/null; then
    warn "secret/$APP/prod already exists — skipping."
else
    section "Collecting configuration"
    SERVER_MASTER_SECRET=$(ask "SERVER_MASTER_SECRET" "openssl rand -hex 32")
    JWT_SECRET_KEY=$(ask "JWT_SECRET_KEY" "openssl rand -base64 48 | tr -d '\\n'")
    vault kv put secret/$APP/prod \
        SERVER_MASTER_SECRET="$SERVER_MASTER_SECRET" \
        JWT_SECRET_KEY="$JWT_SECRET_KEY" \
        DATABASE_URL="$DATABASE_URL" > /dev/null
    info "App secrets stored."
fi

if vault kv get secret/$APP/blockchain &>/dev/null; then
    warn "secret/$APP/blockchain already exists — skipping."
else
    RPC_URL=$(ask "Sepolia RPC URL" "echo 'https://ethereum-sepolia-rpc.publicnode.com'")
    WALLET_PRIVATE_KEY=$(ask "Wallet private key (0x...)" \
        "printf '0x%s' \"\$(openssl rand -hex 32)\"")
    CONTRACT_ADDRESS=$(ask "Contract address (leave blank to deploy now)" "echo ''")
    vault kv put secret/$APP/blockchain \
        RPC_URL="$RPC_URL" \
        WALLET_PRIVATE_KEY="$WALLET_PRIVATE_KEY" \
        CONTRACT_ADDRESS="$CONTRACT_ADDRESS" > /dev/null
    info "Blockchain secrets stored."
fi

# ─── AppRole ──────────────────────────────────
section "Configuring AppRole"
vault policy write $APP-app - > /dev/null <<HCL
path "secret/data/$APP/prod"        { capabilities = ["read"] }
path "secret/data/$APP/blockchain"  { capabilities = ["read"] }
HCL
vault policy write $APP-deploy - > /dev/null <<HCL
path "secret/data/$APP/prod"        { capabilities = ["create", "update"] }
path "secret/data/$APP/blockchain"  { capabilities = ["create", "update"] }
HCL
vault auth list 2>/dev/null | grep -q "approle/" || vault auth enable approle
vault write auth/approle/role/$APP-app \
    token_policies="$APP-app" \
    token_ttl=1h token_max_ttl=4h secret_id_ttl=0 > /dev/null
ROLE_ID=$(vault read -field=role_id auth/approle/role/$APP-app/role-id)
if grep -q "VAULT_SECRET_ID" "$CREDS_FILE" 2>/dev/null; then
    SECRET_ID=$(grep "VAULT_SECRET_ID" "$CREDS_FILE" | cut -d= -f2)
    warn "AppRole secret_id already exists — reusing from $CREDS_FILE."
else
    SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/$APP-app/secret-id)
fi
DEPLOY_TOKEN=$(vault token create -policy="$APP-deploy" -ttl=0 -period=720h -field=token)
info "AppRole configured."

# ─── Repo and deps ────────────────────────────
section "Cloning repository"
[ -d "$REPO_DIR" ] || git clone https://github.com/MarkIsMyNames/CyberSec-Backend.git "$REPO_DIR"
cd "$REPO_DIR"
git pull --ff-only --quiet
[ -f "$VENV_DIR/bin/activate" ] || python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install -r "$REPO_DIR/requirements.txt" --quiet
info "Python dependencies installed."

# ─── Credentials file ─────────────────────────
sudo mkdir -p /etc/$APP
sudo tee "$CREDS_FILE" > /dev/null <<EOF
VAULT_ADDR=$VAULT_ADDR
VAULT_ROLE_ID=$ROLE_ID
VAULT_SECRET_ID=$SECRET_ID
EOF
sudo chown root:"$CURRENT_USER" "$CREDS_FILE"
sudo chmod 640 "$CREDS_FILE"

# ─── Smart contract ───────────────────────────
section "Deploying AuditLog contract"
if [ -n "$CONTRACT_ADDRESS" ]; then
    info "Contract already deployed — skipping."
else
    WALLET_PRIVATE_KEY=$(vault kv get -field=WALLET_PRIVATE_KEY secret/$APP/blockchain)
    WALLET_ADDRESS=$("$VENV_DIR/bin/python3" -c "
from eth_account import Account
print(Account.from_key('$WALLET_PRIVATE_KEY').address)
")
    section "Fund wallet"
    echo -e "  Address     : ${YELLOW}$WALLET_ADDRESS${RESET}"
    echo -e "  Private Key : ${YELLOW}$WALLET_PRIVATE_KEY${RESET}"
    echo -e "  Faucet      : https://sepolia-faucet.pk910.de"
    echo ""
    read -r -p "Press Enter once funded..."
    if ! command -v node &>/dev/null; then
        info "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - > /dev/null
        sudo apt-get install -y -qq nodejs
    fi
    info "Installing npm dependencies..."
    npm install
    info "Deploying contract..."
    DEPLOY_OUTPUT=$(VAULT_ADDR="$VAULT_ADDR" VAULT_ROLE_ID="$ROLE_ID" VAULT_SECRET_ID="$SECRET_ID" \
        npm run deploy 2>&1) || true
    echo "$DEPLOY_OUTPUT"
    CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep -oP '(?<=AuditLog deployed to: )0x[0-9a-fA-F]+')
    [ -n "$CONTRACT_ADDRESS" ] || { die "Could not parse contract address."; }
    vault kv patch secret/$APP/blockchain CONTRACT_ADDRESS="$CONTRACT_ADDRESS" > /dev/null
    info "Contract deployed to $CONTRACT_ADDRESS."
fi

# ─── systemd services ─────────────────────────
section "Creating systemd services"
sudo tee /etc/systemd/system/$APP.service > /dev/null <<UNIT
[Unit]
Description=SecureMsg FastAPI backend
After=network-online.target vault.service
Requires=vault.service

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_USER
WorkingDirectory=$REPO_DIR
EnvironmentFile=$CREDS_FILE
ExecStart=$VENV_DIR/bin/uvicorn app.main:application --host 0.0.0.0 --port 80
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/audit-watcher.service > /dev/null <<UNIT
[Unit]
Description=SecureMsg audit watcher
After=vault.service auditd.service
Requires=vault.service

[Service]
Type=simple
User=root
WorkingDirectory=$REPO_DIR
EnvironmentFile=$CREDS_FILE
ExecStart=$VENV_DIR/bin/python -m app.audit_watcher
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT
#Allow access to low numbered ports (port 80)
sudo setcap 'cap_net_bind_service=+ep' "$(readlink -f "$VENV_DIR/bin/python3")"
sudo systemctl daemon-reload
sudo systemctl enable $APP audit-watcher --quiet
info "Services created."

# ─── auditd ───────────────────────────────────
section "Installing auditd"
command -v auditd &>/dev/null || sudo apt-get install -y -qq auditd
sudo tee /etc/audit/rules.d/$APP-canary.rules > /dev/null <<RULES
-w $REPO_DIR/.env -p r -k canary_read
-w $CREDS_FILE -p r -k vault_credentials_read
RULES
sudo augenrules --load > /dev/null 2>&1
sudo systemctl enable auditd --quiet
sudo systemctl restart auditd
info "auditd configured."

# ─── Canary .env ──────────────────────────────
cat > "$REPO_DIR/.env" <<EOF
SERVER_MASTER_SECRET=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')
DATABASE_URL=postgresql://$APP:$(openssl rand -hex 12)@localhost/$APP
EOF
chmod 644 "$REPO_DIR/.env"
info "Canary .env written."

# ─── Start ────────────────────────────────────
section "Starting services"
sudo systemctl start $APP audit-watcher
for i in $(seq 1 30); do
    curl -sf https://BobbyTables.theburkenator.com/health > /dev/null 2>&1 && {
        info "Health check passed after $((i * 2))s."; break
    }
    [ "$i" -eq 30 ] && { sudo journalctl -u $APP -n 50 >&2; die "Health check timed out."; }
    sleep 2
done

# ─── Done ─────────────────────────────────────
if [ -z "${WALLET_ADDRESS:-}" ]; then
    WALLET_PRIVATE_KEY=$(vault kv get -field=WALLET_PRIVATE_KEY secret/$APP/blockchain)
    WALLET_ADDRESS=$("$VENV_DIR/bin/python3" -c "
from eth_account import Account
print(Account.from_key('$WALLET_PRIVATE_KEY').address)
")
fi

echo ""
echo -e "${GREEN}${BOLD}━━━  Setup complete  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  $APP          : $(sudo systemctl is-active $APP)"
echo -e "  audit-watcher : $(sudo systemctl is-active audit-watcher)"
echo -e "  vault         : $(sudo systemctl is-active vault)"
echo ""
echo -e "${RED}${BOLD}━━━  SAVE THESE  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  Unseal Key         : ${YELLOW}${UNSEAL_KEY:-<already initialised — check your records>}${RESET}"
echo -e "  Root Token         : ${YELLOW}${ROOT_TOKEN:-<already initialised — check your records>}${RESET}"
echo -e "  VAULT_DEPLOY_TOKEN : ${YELLOW}$DEPLOY_TOKEN${RESET}"
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "Add ${BOLD}VAULT_DEPLOY_TOKEN${RESET} to GitHub → Settings → Secrets → Actions."
echo -e "The unseal key is needed after every VM reboot."
