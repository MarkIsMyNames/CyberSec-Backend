#!/usr/bin/env bash
set -euo pipefail

APP="securemsg"
REPO_DIR="$HOME/CyberSec-Backend"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

info() { echo -e "${GREEN}[+]${RESET} $*"; }
die()  { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

echo -e "${RED}${BOLD}This will remove all $APP services, data, and configuration.${RESET}"
read -r -p "Are you sure? (yes/no): " confirm
[ "$confirm" = "yes" ] || die "Aborted."

info "Stopping services..."
sudo systemctl stop $APP audit-watcher vault postgresql auditd 2>/dev/null || true
sudo systemctl disable $APP audit-watcher vault 2>/dev/null || true

info "Removing systemd units..."
sudo rm -f /etc/systemd/system/$APP.service
sudo rm -f /etc/systemd/system/audit-watcher.service
sudo rm -f /etc/systemd/system/vault.service
sudo systemctl daemon-reload

info "Removing Vault data and config..."
sudo rm -rf /var/lib/vault/data /etc/vault /etc/$APP
sudo rm -f /etc/apt/sources.list.d/hashicorp.list
sudo rm -f /usr/share/keyrings/hashicorp-archive-keyring.gpg

info "Removing audit rules..."
sudo rm -f /etc/audit/rules.d/$APP-canary.rules
sudo augenrules --load 2>/dev/null || true

info "Dropping PostgreSQL user and database..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS $APP;" 2>/dev/null || true
sudo -u postgres psql -c "DROP USER IF EXISTS $APP;" 2>/dev/null || true

info "Removing repository..."
rm -rf "$REPO_DIR"

echo -e "\n${GREEN}${BOLD}Reset complete. Run start.sh to set up again.${RESET}"
