#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - Shell / SMB Hardening (Rocky Linux 9)
# VM: 172.18.14.t (DHCP on External LAN)
# Services: SSH Login (1000), SMB Login (500), SMB Write (1000), SMB Read (1000)
#           => 3500pts total
#
# FIXES:
#   - Scoring password NOT hardcoded - prompted interactively or set via env var
#   - SSH password auth stays enabled until scoring key confirmed, then locked
#   - nmb made optional (may not exist on Rocky 9 minimal)
#   - Share names flagged as TBD - check scoreboard at 10:30 AM
#   - CISA 14+ char passwords for all local users
#   - jailed users for common accounts
#   - Disk quota guard against write-fill DoS
# Run as root. Re-run safe.
# =============================================================================
LOGFILE="/vagrant/logs/ncae_harden_shell.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === Shell/SMB Hardening START ==="

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

TEAM=$(ip addr show | grep -oP '172\.18\.14\.\K[0-9]+' | head -1 2>/dev/null || \
       ip addr show | grep -oP '192\.168\.\K[0-9]+' | head -1 2>/dev/null || echo "1")
echo "[*] Team: $TEAM"

# -- Password generator (CISA: 14+ chars, 4 complexity classes) ---------------
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

CRED_FILE="/root/ncae_credentials_shell.txt"
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "# NCAE Shell/SMB Credentials - $(date)" >> "$CRED_FILE"

# -- Scoring password: prompt or env var --------------------------------------
# Set NCAE_SCORING_PASS env var before running to skip prompt, e.g.:
#   NCAE_SCORING_PASS='CompPassword123!' sudo bash harden_shell_smb.sh
if [[ -z "${NCAE_SCORING_PASS:-}" ]]; then
    echo ""
    echo "[!] Enter the scoring engine SMB/SSH password from the competition platform."
    echo "    (Check the scoreboard or inject at 10:30 AM for exact credentials)"
    echo "    Leave blank to generate a CISA-compliant random password:"
    read -rsp "    Scoring password: " NCAE_SCORING_PASS
    echo ""
fi
if [[ -z "$NCAE_SCORING_PASS" ]]; then
    NCAE_SCORING_PASS=$(gen_pass 16)
    echo "[*] Generated scoring password (update if competition provides one)"
fi
echo "SCORING SMB/SSH password: $NCAE_SCORING_PASS" >> "$CRED_FILE"

# -- 1. Update -----------------------------------------------------------------
echo "[*] Updating packages..."
dnf update -y

# -- 2. Install packages -------------------------------------------------------
echo "[*] Installing packages..."
# Core packages - must succeed
dnf install -y samba samba-client samba-common libcap \
    policycoreutils-python-utils quota
# fail2ban requires EPEL - optional, skip silently if unavailable
dnf install -y fail2ban 2>/dev/null || echo "[!] fail2ban not available (EPEL not enabled) - skipping"

# -- 3. User lockdown + CISA passwords ----------------------------------------
echo "[*] Locking user accounts with CISA-compliant passwords..."
KEEP_USERS=("root" "scoring" "nobody" "daemon" "samba" "dbus" "systemd-network")
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
JAILED_USERS=("admin" "smbadmin" "fileadmin")
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

# -- 5. Create scoring user ----------------------------------------------------
echo "[*] Setting up scoring user..."
if ! id scoring &>/dev/null; then
    useradd -m -s /bin/bash scoring
fi
echo "scoring:$NCAE_SCORING_PASS" | chpasswd

# SSH key setup for scoring
SSH_DIR="/home/scoring/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown scoring:scoring "$SSH_DIR"

# Placeholder for scoring engine public key
AUTH_KEYS="${SSH_DIR}/authorized_keys"
if [[ ! -s "$AUTH_KEYS" ]]; then
    echo "# PASTE SCORING ENGINE PUBLIC KEY HERE" > "$AUTH_KEYS"
    echo "[!!] ACTION REQUIRED: Add scoring engine SSH pubkey to $AUTH_KEYS"
    echo "     Get it from the competition scoreboard at 10:30 AM"
fi
chmod 600 "$AUTH_KEYS"
chown scoring:scoring "$AUTH_KEYS"

# -- 6. SSH hardening ---------------------------------------------------------
# STRATEGY: Keep password auth ON initially so we don't lock ourselves out
# before the scoring engine's public key is added to /home/scoring/.ssh/authorized_keys
# Run /root/ncae_lock_ssh.sh AFTER confirming the scoring key works to disable passwords
echo "[*] Hardening SSH..."
echo "[*] Keeping PasswordAuthentication YES until scoring pubkey is confirmed"
echo "    Run: sudo bash /root/ncae_lock_ssh.sh  - AFTER confirming key works"
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/ncae_harden.conf <<EOF
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers scoring@172.18.0.0/16 root@192.168.${TEAM}.0/24 *@127.0.0.1
# scoring: only from external LAN 172.18.0.0/16 (scoring engine + jumphost)
# root: only from internal LAN 192.168.t.0/24 (jump from another of our VMs)
EOF

# Script to disable password auth AFTER confirming key works
cat > /root/ncae_lock_ssh.sh <<'EOF'
#!/bin/bash
# Run this ONLY after confirming scoring SSH key works
echo "[*] Testing scoring SSH key..."
echo "Test this first: ssh -i <scoring_key> scoring@$(hostname -I | awk '{print $1}')"
read -rp "Did the key work? (yes/no): " confirm
if [[ "$confirm" == "yes" ]]; then
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/ncae_harden.conf
    systemctl restart sshd
    echo "[+] Password auth disabled. Key-only from now on."
else
    echo "[!] Keeping password auth enabled. Fix the key first."
fi
EOF
chmod +x /root/ncae_lock_ssh.sh
systemctl restart sshd 2>/dev/null || true

# -- 7. SMB share setup --------------------------------------------------------
echo "[*] Setting up SMB shares..."
# NOTE: Share names below are placeholders.
# Check the competition scoreboard at 10:30 AM for exact share names the scoring engine expects.
# Common names: 'share', 'files', 'data', 'scoring', 'public'
# Update [share_name] sections in /etc/samba/smb.conf if needed.
SMB_WRITE_DIR="/srv/samba/write"
SMB_READ_DIR="/srv/samba/read"
mkdir -p "$SMB_WRITE_DIR" "$SMB_READ_DIR"

# Populate read share with scoring-expected files
cat > "$SMB_READ_DIR/readme.txt" <<'EOF'
NCAE CyberGames 2026 - NightHax Team
SMB Read Share - operational
EOF
cat > "$SMB_READ_DIR/scorefile.txt" <<'EOF'
Team operational - SMB read share active.
EOF

chown -R scoring:scoring "$SMB_WRITE_DIR" "$SMB_READ_DIR"
chmod 770 "$SMB_WRITE_DIR"
chmod 755 "$SMB_READ_DIR"

# SMB scoring user
# smbpasswd -a adds the user to Samba's password database (separate from /etc/shadow)
# -s reads password from stdin (non-interactive), two copies = password + confirmation
# Samba uses its own TDB password database, NOT the system /etc/shadow
echo -e "${NCAE_SCORING_PASS}\n${NCAE_SCORING_PASS}" | smbpasswd -s -a scoring 2>/dev/null || true
smbpasswd -e scoring 2>/dev/null || true  # -e enables the account (it may be disabled by default)

# -- 8. smb.conf --------------------------------------------------------------
# SMBv2+ only (server min protocol = SMB2): disables SMBv1 which has known
# critical vulnerabilities (EternalBlue/WannaCry). Scoring engine supports SMB2+.
# ntlm auth = ntlmv2-only: disables NTLMv1 (easily cracked) and anonymous NTLM
# restrict anonymous = 2: prevents unauthenticated listing of shares
# server signing = mandatory: requires message signing, prevents MITM/relay attacks
echo "[*] Writing smb.conf..."
cp /etc/samba/smb.conf "/etc/samba/smb.conf.bak.$(date +%s)" 2>/dev/null || true

cat > /etc/samba/smb.conf <<EOF
[global]
    workgroup = NCAE
    server string = NightHax Shell ${TEAM}
    netbios name = SHELL${TEAM}
    security = user
    map to guest = Never
    passdb backend = tdbsam
    log file = /var/log/samba/log.%m
    max log size = 50
    logging = file

    # Harden: SMBv2+ only
    server min protocol = SMB2
    ntlm auth = ntlmv2-only
    restrict anonymous = 2
    client signing = auto
    server signing = mandatory

# -- WRITE SHARE --------------------------------------------------------------
# [!] Rename section if scoreboard specifies a different share name
[write]
    comment = Scoring Write Share
    path = ${SMB_WRITE_DIR}
    browseable = yes
    read only = no
    writable = yes
    valid users = scoring
    create mask = 0664
    directory mask = 0775
    force user = scoring

# -- READ SHARE ---------------------------------------------------------------
# [!] Rename section if scoreboard specifies a different share name
[read]
    comment = Scoring Read Share
    path = ${SMB_READ_DIR}
    browseable = yes
    read only = yes
    valid users = scoring
    force user = scoring
EOF

# testparm validates smb.conf syntax and logic - run this after any manual edits too
testparm -s /etc/samba/smb.conf 2>/dev/null && echo "[+] smb.conf valid" || echo "[!] smb.conf invalid - check above"

# -- 9. Start Samba ------------------------------------------------------------
echo "[*] Starting Samba..."
systemctl enable smb 2>/dev/null || true
systemctl restart smb 2>/dev/null || true
# nmb may not exist on Rocky 9 minimal - optional
systemctl enable nmb 2>/dev/null || true
systemctl restart nmb 2>/dev/null || true
# -- 10. SELinux contexts ------------------------------------------------------
# SELinux on Rocky Linux enforces mandatory access control based on file labels
# samba_share_t is the correct type for files/dirs that Samba is allowed to serve
# Without this, SELinux will block Samba from reading the share dirs even though
# Unix permissions are correct. restorecon applies the labels we set with semanage.
echo "[*] Setting SELinux contexts..."
semanage fcontext -a -t samba_share_t "${SMB_WRITE_DIR}(/.*)?" 2>/dev/null || true
semanage fcontext -a -t samba_share_t "${SMB_READ_DIR}(/.*)?" 2>/dev/null || true
restorecon -Rv "$SMB_WRITE_DIR" "$SMB_READ_DIR" 2>/dev/null || true

# -- 11. Firewall --------------------------------------------------------------
echo "[*] Configuring firewalld (restricted - SSH + SMB from 172.18.0.0/16 only)..."
systemctl enable firewalld 2>/dev/null || true
systemctl start firewalld 2>/dev/null || true
firewall-cmd --permanent --set-default-zone=drop 2>/dev/null || true
firewall-cmd --permanent --new-zone=ncae-shell 2>/dev/null || true
firewall-cmd --permanent --zone=ncae-shell --set-target=DROP 2>/dev/null || true
# SSH from external LAN (scoring + jumphost) and internal LAN
firewall-cmd --permanent --zone=ncae-shell \
    --add-rich-rule="rule family='ipv4' source address='172.18.0.0/16' service name='ssh' accept" 2>/dev/null || true
firewall-cmd --permanent --zone=ncae-shell \
    --add-rich-rule="rule family='ipv4' source address='192.168.${TEAM}.0/24' service name='ssh' accept" 2>/dev/null || true
# SMB from external LAN (scoring)
firewall-cmd --permanent --zone=ncae-shell \
    --add-rich-rule="rule family='ipv4' source address='172.18.0.0/16' service name='samba' accept" 2>/dev/null || true
NIC=$(ip route | grep default | awk '{print $5}' | head -1)
[[ -z "$NIC" ]] && NIC=$(ip link show | grep -v 'lo\|LOOPBACK' | awk -F: 'NR==1{print $2}' | tr -d ' ')
[[ -z "$NIC" ]] && NIC="eth0"
firewall-cmd --permanent --zone=ncae-shell --add-interface="$NIC" 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

# -- 12. Fail2Ban --------------------------------------------------------------
echo "[*] Installing Fail2Ban..."
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true
# -- 13a. Disk write DoS guard --------------------------------------------------
# Red team might flood the write share with large files to fill the disk
# This fills /srv/samba/write which could crash services that write to /
# Alert-only (not auto-delete) to avoid accidentally removing scoring files
echo "[*] Setting write share quota guard (1GB max - alert only, no auto-delete)..."
cat > /usr/local/bin/ncae_smb_quota_check.sh <<'QUOTAEOF'
#!/bin/bash
WRITE_DIR="/srv/samba/write"
SIZE=$(du -sb "$WRITE_DIR" 2>/dev/null | awk '{print $1}')
LIMIT=1073741824  # 1GB
if [[ "$SIZE" -gt "$LIMIT" ]]; then
    echo "[ALERT][$(date)] SMB write share exceeds 1GB (${SIZE} bytes) - possible disk fill attack" \
        | tee -a /var/log/ncae_alerts.log
fi
QUOTAEOF
chmod +x /usr/local/bin/ncae_smb_quota_check.sh
cat > /etc/cron.d/ncae_smb_quota <<'EOF'
* * * * * root /usr/local/bin/ncae_smb_quota_check.sh
EOF

# -- 13b. Auditd ---------------------------------------------------------------
echo "[*] Configuring auditd..."
dnf install -y audit 2>/dev/null || true
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_shell.rules <<'AUDITEOF'
-w /etc/samba/smb.conf -p wa -k smb_config
-w /srv/samba -p wa -k smb_shares
-w /etc/ssh/sshd_config.d -p wa -k ssh_config_changes
-w /home/scoring/.ssh/authorized_keys -p wa -k scoring_keys_tamper
-w /root/.ssh/authorized_keys -p wa -k root_keys_tamper
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_shell.rules 2>/dev/null || true

# -- 14. Watchdog cron ---------------------------------------------------------
cat > /etc/cron.d/ncae_smb_watchdog <<'EOF'
* * * * * root systemctl is-active --quiet smb  || systemctl restart smb 2>/dev/null
* * * * * root systemctl is-active --quiet sshd || systemctl restart sshd 2>/dev/null
EOF

echo ""
echo "[$(date)] === Shell/SMB Hardening COMPLETE ==="
echo "Credentials: $CRED_FILE"
echo ""
echo "SCORING CHECKLIST (3500pts):"
echo "  SSH Login  (1000): Add scoring pubkey to $AUTH_KEYS"
echo "    -> Then run: /root/ncae_lock_ssh.sh"
echo "  SMB Login  (500):  smbclient -L //172.18.14.${TEAM}/ -U scoring%\$(grep SCORING $CRED_FILE | awk '{print \$NF}')"
echo "  SMB Write  (1000): smbclient //172.18.14.${TEAM}/write -U scoring%'<pass>' -c 'put /etc/hostname test.txt'"
echo "  SMB Read   (1000): smbclient //172.18.14.${TEAM}/read  -U scoring%'<pass>' -c 'get readme.txt /tmp/readme.txt'"
echo "  (Password in $CRED_FILE)"
echo ""
echo "  [!!] CHECK SCOREBOARD AT 10:30 AM for exact share names expected by scoring engine"
echo "       If wrong, edit /etc/samba/smb.conf share names and: systemctl restart smb"
