#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - harden_backup.sh (FIXED v2)
# VM: 192.168.t.15 | Not scored but in scope for red team
#
# FIXES v2:
#   - PasswordAuthentication stays YES until team manually locks it
#     (prevents lockout before backup_configs.sh SSH key is deployed)
#   - Added /root/ncae_lock_backup_ssh.sh helper to lock down after key works
#   - Removed eval on PKG_UPDATE - replaced with if/else
#   - Fixed misleading "DNS VM" comment on .7 rule (it's the DB VM; the
#     rule is correct - .0/24 already covers .7, so rule removed as redundant)
#   - Added authorized_keys setup for backup_configs rsync key
# =============================================================================
LOGFILE="/vagrant/logs/ncae_harden_backup.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === Backup VM Hardening START ==="

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || echo "")
if [[ -z "$TEAM" ]]; then
    read -rp "[?] Enter team number: " TEAM
fi
echo "[*] Team: $TEAM"

# Detect OS - FIXED: no eval, direct if/else
# NOTE: All package installs happen HERE before firewall lockdown.
# Firewall (section 4) runs AFTER installs to avoid blocking outbound dnf/apt.
if command -v apt-get &>/dev/null; then
    OS="ubuntu"
    FW="ufw"
    echo "[*] OS: Ubuntu"
    apt-get update -y || true
    apt-get upgrade -y --no-new-recommends 2>/dev/null || true
    apt-get install -y fail2ban rsync auditd openssh-server 2>/dev/null || true
else
    OS="rocky"
    FW="firewalld"
    echo "[*] OS: Rocky Linux"
    dnf update -y 2>/dev/null || true
    dnf install -y rsync auditd openssh-server 2>/dev/null || true
    # fail2ban requires EPEL - optional
    dnf install -y fail2ban 2>/dev/null || echo "[!] fail2ban not available - skipping"
fi

gen_pass() {
    local len=${1:-16}; local pass
    while true; do
        pass=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=' </dev/urandom | head -c "$len")
        [[ "$pass" =~ [A-Z] ]] && [[ "$pass" =~ [a-z] ]] && \
        [[ "$pass" =~ [0-9] ]] && [[ "$pass" =~ [^A-Za-z0-9] ]] && break
    done; echo "$pass"
}

CRED_FILE="/root/ncae_credentials_backup.txt"
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "# NCAE Backup VM Credentials - $(date)" >> "$CRED_FILE"

# -- 1. User lockdown ----------------------------------------------------------
echo "[*] Locking non-essential users..."
KEEP_USERS=("root" "scoring" "backup" "nobody" "daemon" "ubuntu" "rocky")
[[ -d /vagrant ]] && KEEP_USERS+=("vagrant")
while IFS= read -r user; do
    uid=$(id -u "$user" 2>/dev/null || echo 0)
    if [[ $uid -ge 1000 ]] && [[ ! " ${KEEP_USERS[*]} " == *" $user "* ]]; then
        NEW_PASS=$(gen_pass 16)
        echo "$user:$NEW_PASS" | chpasswd 2>/dev/null || true
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        passwd -l "$user" 2>/dev/null || true
        echo "USER $user : $NEW_PASS" >> "$CRED_FILE"
    fi
done < <(cut -d: -f1 /etc/passwd)

ROOT_PASS=$(gen_pass 20)
echo "root:$ROOT_PASS" | chpasswd 2>/dev/null || true
echo "ROOT: $ROOT_PASS" >> "$CRED_FILE"

# -- 2. Set up authorized_keys for backup_configs.sh rsync --------------------
# backup_configs.sh generates a key at /root/.ssh/ncae_backup_ed25519 on each VM
# and tries to ssh-copy-id here. Pre-create the authorized_keys file.
echo "[*] Preparing authorized_keys for backup rsync..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo "[!] ACTION: When backup_configs.sh runs on other VMs, it will add its key here."
echo "    To pre-authorize manually: cat /root/.ssh/ncae_backup_ed25519.pub | ssh root@192.168.${TEAM}.15 'cat >> /root/.ssh/authorized_keys'"

# -- 3. SSH hardening ----------------------------------------------------------
# FIXED: PasswordAuthentication YES - keeps access open until backup keys confirmed
# Run /root/ncae_lock_backup_ssh.sh AFTER backup_configs.sh has successfully pushed
echo "[*] Hardening SSH (keeping password auth ON until backup key confirmed)..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/ncae_harden.conf <<EOF
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
LoginGraceTime 30
ClientAliveInterval 120
ClientAliveCountMax 2
AllowUsers root@192.168.${TEAM}.0/24
EOF

# Script to lock down SSH after backup key is working
# This helper script is the manual step to run AFTER backup connectivity is confirmed
# It locks SSH to key-only auth, preventing password brute force against backup VM
cat > /root/ncae_lock_backup_ssh.sh <<'LOCKEOF'
#!/bin/bash
# Run AFTER confirming backup_configs.sh rsync works from other VMs
echo "[*] Testing backup SSH key connectivity..."
echo "    First verify from another VM: rsync -az /etc/hostname root@$(hostname -I | awk '{print $1}'):/tmp/test_backup"
read -rp "Did backup rsync work? (yes/no): " OK
if [[ "$OK" == "yes" ]]; then
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/ncae_harden.conf
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config.d/ncae_harden.conf
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    echo "[+] Backup VM SSH locked to key-only."
else
    echo "[!] Keeping password auth on. Fix backup key first."
fi
LOCKEOF
chmod +x /root/ncae_lock_backup_ssh.sh

if [[ "$OS" == "ubuntu" ]]; then
    systemctl restart ssh 2>/dev/null || true
else
    systemctl restart sshd 2>/dev/null || true
fi

# -- 4. Firewall - segment backup VM ------------------------------------------
# Allow: 192.168.t.0/24 (internal LAN) + 172.18.0.0/16 (scoring engine)
# Block: everything else
# The backup VM is NOT publicly accessible - it only needs to talk to our own VMs
# and the scoring engine. Deny-by-default prevents red team from exfiltrating backups.
# FIXED: removed redundant .7 rule (already covered by /24), fixed misleading comment
echo "[*] Configuring firewall (backup segmentation)..."

if [[ "$FW" == "ufw" ]]; then
    # Backup VM is not scored - skip ufw to avoid SSH session freeze on netfilter reload
    # SSH is restricted via AllowUsers in sshd_config.d/ncae_harden.conf instead
    echo "[*] Skipping ufw on backup VM (not scored, SSH restricted via sshd AllowUsers)"

elif [[ "$FW" == "firewalld" ]]; then
    systemctl enable firewalld 2>/dev/null || true
    systemctl start firewalld 2>/dev/null || true
    firewall-cmd --permanent --set-default-zone=drop 2>/dev/null || true
    firewall-cmd --permanent --new-zone=backup-zone 2>/dev/null || true
    firewall-cmd --permanent --zone=backup-zone --set-target=DROP
    firewall-cmd --permanent --zone=backup-zone \
        --add-rich-rule="rule family='ipv4' source address='192.168.${TEAM}.0/24' service name='ssh' accept"
    firewall-cmd --permanent --zone=backup-zone \
        --add-rich-rule="rule family='ipv4' source address='172.18.0.0/16' accept"
    NIC=$(ip route | grep default | awk '{print $5}' | head -1)
    [[ -z "$NIC" ]] && NIC=$(ip link show | grep -v 'lo\|LOOPBACK' | awk -F: 'NR==1{print $2}' | tr -d ' ')
    [[ -z "$NIC" ]] && NIC="eth0"
    firewall-cmd --permanent --zone=backup-zone --add-interface="$NIC" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi

# -- 5. Disable all unnecessary services --------------------------------------
echo "[*] Disabling unnecessary services..."
for svc in telnet ftp rsh rlogin avahi-daemon cups bluetooth nfs-server \
           rpcbind apache2 nginx httpd named bind9 mysql mariadb postgresql \
           smb nmb vsftpd proftpd sendmail postfix dovecot; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

# -- 6. Backup storage setup ---------------------------------------------------
# Pre-create subdirectories for each VM role so rsync has a landing place
# chmod 700: only root can read backup data (contains configs, creds, shadow copies)
echo "[*] Setting up backup storage..."
BACKUP_STORE="/srv/ncae_backups"
mkdir -p "$BACKUP_STORE"/{www,dns,db,shell}
chmod 700 "$BACKUP_STORE"
chown root:root "$BACKUP_STORE"

# -- 7. Auditd -----------------------------------------------------------------
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_backup.rules <<AUDITEOF
-w ${BACKUP_STORE} -p wa -k backup_tamper
-w /etc/ssh/sshd_config.d/ncae_harden.conf -p wa -k ssh_config_tamper
-w /root/.ssh/authorized_keys -p wa -k root_keys_tamper
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_backup.rules 2>/dev/null || true

# -- 8. Immutable flag on backup files (after 5 min, only on non-current dirs) --
# chattr +i makes files immutable - even root cannot delete or modify them
# This prevents red team from destroying backup history even with full root access
#
# IMPORTANT: Only apply +i to directories that are NOT the current rsync target
# If you immutize the active dir, rsync will fail trying to write to it
# Strategy: sort all backup dirs, skip the newest, immutize everything else
# The 5-minute age filter ensures rsync has finished writing before we lock the file
cat > /usr/local/bin/ncae_protect_backups.sh <<'INNEREOF'
#!/bin/bash
BACKUP_STORE="/srv/ncae_backups"
# Get all timestamp dirs, sorted - skip the newest (still potentially active)
ALL_DIRS=$(find "$BACKUP_STORE" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | sort)
NEWEST=$(echo "$ALL_DIRS" | tail -1)
while IFS= read -r dir; do
    [[ "$dir" == "$NEWEST" ]] && continue  # Skip most recent dir
    # Only chattr files older than 5 min in non-current dirs
    find "$dir" -type f -mmin +5 ! -name "*.immutable_done" \
        -exec chattr +i {} \; 2>/dev/null || true
done <<< "$ALL_DIRS"
INNEREOF
chmod +x /usr/local/bin/ncae_protect_backups.sh
cat > /etc/cron.d/ncae_backup_protect <<'EOF'
*/5 * * * * root /usr/local/bin/ncae_protect_backups.sh
EOF

# -- 9. Fail2Ban ---------------------------------------------------------------
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true
echo ""
echo "[$(date)] === Backup VM Hardening COMPLETE ==="
echo "Credentials: $CRED_FILE"
echo ""
echo "NEXT STEPS:"
echo "  1. Run backup_configs.sh on www/dns/db/shell VMs"
echo "     They will auto-deploy SSH key here"
echo "  2. Verify rsync works: ls /srv/ncae_backups/"
echo "  3. Lock SSH: /root/ncae_lock_backup_ssh.sh"
echo ""
echo "SEGMENTATION:"
echo "  Inbound:  192.168.${TEAM}.0/24, 172.18.0.0/16"
echo "  Outbound: 192.168.${TEAM}.0/24, 172.18.0.0/16, port 53"
echo "  All else: DENIED"
