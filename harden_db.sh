#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - Database Hardening (Ubuntu 24.04)
# VM: 192.168.t.7  |  Service: Postgres Access (500pts)
#
# FIXES:
#   - password_encryption and pg_hba METHOD both set to 'scram-sha-256' - no mismatch
#   - listen_addresses rewritten with direct append, not fragile sed
#   - TEAM variable validated before use - no silent UFW rule failures
#   - CISA 14+ char passwords for all local users
#   - jailed users for common accounts
#   - Scoring connection test before script exits
# Run as root. Re-run safe.
# =============================================================================
LOGFILE="/vagrant/logs/ncae_harden_db.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === DB Hardening START ==="

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

# Validated team detection
TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || echo "")
if [[ -z "$TEAM" ]] || ! [[ "$TEAM" =~ ^[0-9]+$ ]]; then
    echo "[!] Could not auto-detect team number from IP."
    read -rp "    Enter team number manually: " TEAM
fi
echo "[*] Team: $TEAM"

# -- Password generator (CISA: 14+ chars) -------------------------------------
gen_pass() {
    local len=${1:-16}
    local pass
    while true; do
        pass=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=' </dev/urandom | head -c "$len")
        [[ "$pass" =~ [A-Z] ]] && [[ "$pass" =~ [a-z] ]] && \
        [[ "$pass" =~ [0-9] ]] && [[ "$pass" =~ [^A-Za-z0-9] ]] && break
    done
    echo "$pass"
}

CRED_FILE="/root/ncae_credentials_db.txt"
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "# NCAE DB Credentials - $(date)" >> "$CRED_FILE"

# Scoring DB password - prompt or env var
if [[ -z "${NCAE_DB_PASS:-}" ]]; then
    echo ""
    echo "[!] Enter the scoring engine Postgres password from the competition platform."
    echo "    Leave blank to generate a CISA-compliant random password:"
    read -rsp "    DB scoring password: " NCAE_DB_PASS
    echo ""
fi
if [[ -z "$NCAE_DB_PASS" ]]; then
    NCAE_DB_PASS=$(gen_pass 16)
    echo "[*] Generated DB scoring password (update if competition provides one)"
fi
SCORING_DB_USER="scoring"
SCORING_DB_NAME="scoringdb"
echo "Postgres scoring password: $NCAE_DB_PASS" >> "$CRED_FILE"

# -- 1. Update -----------------------------------------------------------------
echo "[*] Updating packages..."
apt-get update -y && apt-get upgrade -y --no-new-recommends

# -- 2. Install packages -------------------------------------------------------
echo "[*] Installing packages..."
apt-get install -y ufw fail2ban auditd libpam-pwquality libcap2-bin 2>/dev/null || true
if ! command -v psql &>/dev/null; then
    apt-get install -y postgresql postgresql-contrib
fi

PG_VER=$(psql --version 2>/dev/null | grep -oP '\d+' | head -1 || echo "16")
PG_CONF="/etc/postgresql/${PG_VER}/main"
echo "[*] PostgreSQL version: $PG_VER | Config: $PG_CONF"

systemctl enable postgresql 2>/dev/null || true

systemctl start postgresql 2>/dev/null || true
# -- 3. User lockdown + CISA passwords ----------------------------------------
echo "[*] Locking user accounts..."
KEEP_USERS=("root" "postgres" "scoring" "ubuntu" "daemon" "nobody")
[[ -d /vagrant ]] && KEEP_USERS+=("vagrant")
while IFS= read -r user; do
    uid=$(id -u "$user" 2>/dev/null || echo 0)
    if [[ $uid -ge 1000 ]] && [[ ! " ${KEEP_USERS[*]} " == *" $user "* ]]; then
        NEW_PASS=$(gen_pass 16)
        echo "$user:$NEW_PASS" | chpasswd 2>/dev/null || true
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        echo "USER $user : $NEW_PASS" >> "$CRED_FILE"
        echo "  [-] Locked: $user"
    fi
done < <(cut -d: -f1 /etc/passwd)

ROOT_PASS=$(gen_pass 20)
echo "root:$ROOT_PASS" | chpasswd 2>/dev/null || true
echo "ROOT password: $ROOT_PASS" >> "$CRED_FILE"

# -- 4. jailed users ------------------------------------------------------
echo "[*] Creating jailed users..."
JAILED_USERS=("admin" "dbadmin" "dba")
for juser in "${JAILED_USERS[@]}"; do
    if ! id "$juser" &>/dev/null; then
        useradd -m -s /usr/bin/"$juser" 2>/dev/null || \
        useradd -m -s /bin/rbash "$juser" 2>/dev/null || true
    else
        usermod -s /usr/bin/"$juser" 2>/dev/null || \
        usermod -s /bin/rbash "$juser" 2>/dev/null || true
    fi
    JAIL_PASS=$(gen_pass 16)
    echo "$juser:$JAIL_PASS" | chpasswd 2>/dev/null || true
    echo "JAILED $juser : $JAIL_PASS" >> "$CRED_FILE"
done

# -- 5. Create scoring DB user + database -------------------------------------
echo "[*] Configuring PostgreSQL scoring user and database..."
sudo -u postgres psql <<EOSQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${SCORING_DB_USER}') THEN
        CREATE ROLE ${SCORING_DB_USER} LOGIN PASSWORD '${NCAE_DB_PASS}';
    ELSE
        ALTER ROLE ${SCORING_DB_USER} PASSWORD '${NCAE_DB_PASS}';
    END IF;
END
\$\$;
SELECT 'CREATE DATABASE ${SCORING_DB_NAME} OWNER ${SCORING_DB_USER}'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${SCORING_DB_NAME}')\gexec
GRANT ALL PRIVILEGES ON DATABASE ${SCORING_DB_NAME} TO ${SCORING_DB_USER};
EOSQL

sudo -u postgres psql -d "$SCORING_DB_NAME" <<EOSQL2
CREATE TABLE IF NOT EXISTS scoring_test (
    id SERIAL PRIMARY KEY,
    entry TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
GRANT ALL ON TABLE scoring_test TO ${SCORING_DB_USER};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${SCORING_DB_USER};
INSERT INTO scoring_test (entry) VALUES ('initial_entry');
EOSQL2

echo "[+] DB user and database ready"

# -- 6. pg_hba.conf - scram-sha-256 (matches password_encryption below) ------------
# scram-sha-256 is the modern Postgres auth standard (replaces deprecated md5)
# md5 sends a crackable hash; scram-sha-256 uses a challenge-response that can't be replayed
# IMPORTANT: If the scoring engine uses an old psql client that doesn't support scram,
# change METHOD to 'md5' in the pg_hba lines below AND set password_encryption=md5 in postgresql.conf
echo "[*] Writing pg_hba.conf (scram-sha-256 - secure, no plaintext hash transmission)..."
# NOTE: scram-sha-256 is the modern standard (md5 is deprecated, sends crackable hash).
# If the scoring engine uses an old psql client that doesn't support scram, fall back to md5
# by changing METHOD below. Check psql --version on scoring engine side if auth fails.
cp "${PG_CONF}/pg_hba.conf" "${PG_CONF}/pg_hba.conf.bak.$(date +%s)" 2>/dev/null || true

cat > "${PG_CONF}/pg_hba.conf" <<EOF
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     scram-sha-256
# Scoring engine from internal LAN
host    ${SCORING_DB_NAME}   ${SCORING_DB_USER}   192.168.${TEAM}.0/24     scram-sha-256
host    ${SCORING_DB_NAME}   ${SCORING_DB_USER}   127.0.0.1/32             scram-sha-256
# Deny all other remote connections - catch-all must come AFTER the scoring rules
# (pg_hba is evaluated top-to-bottom, first match wins)
host    all             all             0.0.0.0/0               reject
host    all             all             ::/0                    reject
EOF

# -- 7. postgresql.conf - single-pass clean rewrite (no double-append bug) ----
echo "[*] Configuring postgresql.conf..."
cp "${PG_CONF}/postgresql.conf" "${PG_CONF}/postgresql.conf.bak.$(date +%s)" 2>/dev/null || true

# Strip ALL managed settings in one pass, then append them once cleanly
# This prevents double-append if the script is run multiple times (idempotent)
# grep -v removes matching lines; piping through multiple greps is one pass
grep -v '^#*listen_addresses' "${PG_CONF}/postgresql.conf" | \
    grep -v '^#*password_encryption' | \
    grep -v '^#*log_connections' | \
    grep -v '^#*log_disconnections' | \
    grep -v '^#*log_statement' > /root/pg_conf_clean.tmp || true
cat /root/pg_conf_clean.tmp > "${PG_CONF}/postgresql.conf"
rm -f /root/pg_conf_clean.tmp

# Append all managed settings exactly once
cat >> "${PG_CONF}/postgresql.conf" <<PGEOF
# -- NCAE hardening settings ---------------------------------------
listen_addresses = '192.168.${TEAM}.7, 127.0.0.1'  # Internal LAN IP + loopback only
password_encryption = scram-sha-256  # Must match METHOD in pg_hba.conf above
log_connections = on
log_disconnections = on
log_statement = 'mod'
PGEOF

systemctl restart postgresql 2>/dev/null || true
echo "[+] PostgreSQL restarted"

# -- 8. Verify listen address is correct --------------------------------------
echo "[*] Verifying listen_addresses in config..."
LISTEN_CHECK=$(grep "^listen_addresses" "${PG_CONF}/postgresql.conf" | tail -1)
echo "    -> $LISTEN_CHECK"
if [[ "$LISTEN_CHECK" != *"192.168.${TEAM}.7"* ]]; then
    echo "[!] WARNING: listen_addresses may not include 192.168.${TEAM}.7 - verify manually"
fi

# -- 9. Verify scoring connection ----------------------------------------------
echo "[*] Testing scoring user connection..."
sleep 2  # Let postgres fully restart
# .pgpass file: postgres reads it automatically for connection passwords
# Using .pgpass instead of PGPASSWORD env var prevents the password from
# appearing in /proc/PID/environ where any local user could read it
{
  echo "127.0.0.1:5432:${SCORING_DB_NAME}:${SCORING_DB_USER}:${NCAE_DB_PASS}"
  echo "192.168.${TEAM}.7:5432:${SCORING_DB_NAME}:${SCORING_DB_USER}:${NCAE_DB_PASS}"
} > /root/.pgpass
chmod 600 /root/.pgpass
psql -h 127.0.0.1 -U "$SCORING_DB_USER" -d "$SCORING_DB_NAME" \
    -c "INSERT INTO scoring_test (entry) VALUES ('harden_verify'); SELECT COUNT(*) FROM scoring_test;" \
    2>&1 && echo "[+] DB read/write test PASSED" || echo "[!!] DB test FAILED - check pg_hba and password"

# -- 10. UFW with validated TEAM -----------------------------------------------
echo "[*] Configuring UFW..."
apt-get install -y ufw 2>/dev/null || true
ufw --force reset
ufw default deny incoming
ufw default deny outgoing
ufw allow 22/tcp    comment "SSH"
# Validated TEAM var used here - safe
ufw allow from "192.168.${TEAM}.0/24" to any port 5432 comment "Postgres internal LAN"
ufw allow out to "192.168.${TEAM}.0/24" comment "Internal LAN outbound"
ufw allow out to "172.18.0.0/16" comment "Scoring engine outbound"
ufw allow out to any port 53 comment "DNS resolution"
ufw --force enable
echo "[*] UFW status:"
ufw status

# -- 11. SSH hardening ---------------------------------------------------------
echo "[*] Hardening SSH..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/ncae_harden.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
LoginGraceTime 30
AllowUsers *@192.168.${TEAM}.0/24 *@172.18.0.0/16 *@127.0.0.1
EOF
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# -- 12. Fail2Ban --------------------------------------------------------------
echo "[*] Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.d/ncae.conf <<'EOF'
[sshd]
enabled = true
maxretry = 3
bantime = 3600
EOF
systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
# -- 13. Auditd ----------------------------------------------------------------
# auditd watches for writes (-p wa) to critical config files and logs them to
# /var/log/audit/audit.log - if red team modifies pg_hba.conf you'll see it
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
# Persist rules to survive reboot
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_db.rules <<AUDITEOF
-w ${PG_CONF}/pg_hba.conf -p wa -k pg_hba_changes
-w ${PG_CONF}/postgresql.conf -p wa -k pg_conf_changes
-w /etc/ssh/sshd_config.d -p wa -k ssh_config_changes
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_db.rules 2>/dev/null || true

# -- 14. PAM password policy (CISA 14+ chars) ---------------------------------
if [[ -f /etc/security/pwquality.conf ]]; then
    cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 4
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
    # Activate pwquality in PAM (Ubuntu requires pam-auth-update; Rocky uses authselect)
    if command -v pam-auth-update &>/dev/null; then
        pam-auth-update --enable pwquality 2>/dev/null || true
    elif command -v authselect &>/dev/null; then
        authselect enable-feature with-pwquality 2>/dev/null || true
    fi
fi

# -- 15. Watchdog cron ---------------------------------------------------------
# Watchdog: restarts postgresql if it goes down - runs every minute
# 'systemctl is-active --quiet' returns 0 if active, non-zero otherwise
# The || means: if the check fails (service down), run the restart command
cat > /etc/cron.d/ncae_db_watchdog <<'EOF'
* * * * * root systemctl is-active --quiet postgresql || systemctl restart postgresql
EOF

echo ""
echo "[$(date)] === DB Hardening COMPLETE ==="
echo "Credentials: $CRED_FILE"
echo ""
echo "SCORING CHECKLIST (500pts):"
echo "  Test from another VM on internal LAN:"
echo "  # Add to /root/.pgpass: 192.168.${TEAM}.7:5432:${SCORING_DB_NAME}:${SCORING_DB_USER}:<pass>"
echo "  psql -h 192.168.${TEAM}.7 -U ${SCORING_DB_USER} -d ${SCORING_DB_NAME} -c 'SELECT NOW();'"
echo "  (Password is in $CRED_FILE)"
echo ""
echo "  Verify listen address:"
echo "  ss -tlnp | grep 5432"
echo "  Expected: 192.168.${TEAM}.7:5432"
echo ""
echo "  Config: password_encryption = scram-sha-256  # Must match METHOD in pg_hba.conf above  |  pg_hba method = scram-sha-256  (matched)"
