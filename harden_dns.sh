#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - DNS Server Hardening (Rocky Linux 9)
# VM: 192.168.t.12  |  Services: DNS INT FWD/REV + EXT FWD/REV (4x500 = 2000pts)
#
# FIXES:
#   - IP MAP CORRECTED: DB=192.168.t.7, DNS=192.168.t.12 (was swapped before)
#   - Zone serial now dynamic (date-based) - hot-reload safe
#   - dnssec-validation set to 'no' (no keys generated, avoids silent auth fail)
#   - CISA 14+ char passwords
#   - jailed users for common accounts
#   - recursion allowed from internal LAN for INT scoring
#   - rate-limit added to resist DNS flood attacks
# Run as root. Re-run safe.
# =============================================================================
LOGFILE="/vagrant/logs/ncae_harden_dns.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === DNS Hardening START ==="

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | head -1 2>/dev/null || echo "1")
SERIAL=$(date +%s)  # Unix epoch timestamp used as zone serial number
# Benefits: always a valid 32-bit uint, auto-increments on every run, no manual management
# BIND requires serial to increase on every zone change for secondaries to pick up updates
# Max value 4294967295 (2^32-1) - current epoch ~1.77B, safe for 80+ years
echo "[*] Team: $TEAM  |  Serial: $SERIAL"

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

CRED_FILE="/root/ncae_credentials_dns.txt"
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "# NCAE DNS Credentials - $(date)" >> "$CRED_FILE"

# -- 1. Update -----------------------------------------------------------------
echo "[*] Updating packages..."
dnf update -y

# -- 2. Install packages -------------------------------------------------------
echo "[*] Installing packages..."
dnf install -y bind bind-utils policycoreutils-python-utils fail2ban-firewalld libcap 2>/dev/null || \
dnf install -y bind bind-utils libcap 2>/dev/null || true

# -- 3. User lockdown + CISA passwords ----------------------------------------
echo "[*] Locking user accounts..."
KEEP_USERS=("root" "named" "scoring" "nobody" "daemon")
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
JAILED_USERS=("admin" "dnsadmin" "netadmin")
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

# -- 5. SSH hardening ---------------------------------------------------------
echo "[*] Hardening SSH..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/ncae_harden.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
LoginGraceTime 30
AllowUsers *@192.168.${TEAM}.0/24 *@172.18.0.0/16 *@127.0.0.1
EOF
systemctl restart sshd 2>/dev/null || true

# -- 6. Firewall ---------------------------------------------------------------
echo "[*] Configuring firewalld (restricted)..."
systemctl enable firewalld 2>/dev/null || true
systemctl start firewalld 2>/dev/null || true
firewall-cmd --permanent --set-default-zone=drop 2>/dev/null || true
firewall-cmd --permanent --new-zone=ncae-dns 2>/dev/null || true
firewall-cmd --permanent --zone=ncae-dns --set-target=DROP 2>/dev/null || true
# DNS from anywhere (scoring requires external access)
firewall-cmd --permanent --zone=ncae-dns --add-port=53/tcp 2>/dev/null || true
firewall-cmd --permanent --zone=ncae-dns --add-port=53/udp 2>/dev/null || true
# SSH from internal LAN + external scoring range only
firewall-cmd --permanent --zone=ncae-dns \
    --add-rich-rule="rule family='ipv4' source address='192.168.${TEAM}.0/24' service name='ssh' accept" 2>/dev/null || true
firewall-cmd --permanent --zone=ncae-dns \
    --add-rich-rule="rule family='ipv4' source address='172.18.0.0/16' service name='ssh' accept" 2>/dev/null || true
NIC=$(ip route | grep default | awk '{print $5}' | head -1)
[[ -z "$NIC" ]] && NIC=$(ip link show | grep -v 'lo\|LOOPBACK' | awk -F: 'NR==1{print $2}' | tr -d ' ')
[[ -z "$NIC" ]] && NIC="eth0"  # last-resort fallback
firewall-cmd --permanent --zone=ncae-dns --add-interface="$NIC" 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

# -- 7. BIND named.conf -------------------------------------------------------
echo "[*] Writing named.conf..."
cp /etc/named.conf "/etc/named.conf.bak.$(date +%s)" 2>/dev/null || true

cat > /etc/named.conf <<EOF
options {
    listen-on port 53 { any; };
    listen-on-v6 port 53 { none; };
    directory "/var/named";
    dump-file "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";

    allow-query     { any; };
    /* Recursion for internal LAN only - external clients get REFUSED */
    allow-recursion { 192.168.${TEAM}.0/24; 127.0.0.1; };
    recursion yes;

    /* dnssec-validation disabled: we have no DNSSEC keys configured, so enabling
       validation would cause all queries to fail silently. Always set to "no" unless
       you have explicitly generated and signed zone keys. */
    dnssec-validation no;

    /* Hides BIND version string from "dig chaos txt version.bind" queries
       Prevents red team from targeting known CVEs for the exact version */
    version "NCAE-DNS";

    /* Rate limiting: limits responses per client IP per second
       Defends against DNS amplification attacks where red team uses our server
       as a reflector. 10 responses/sec is enough for scoring engine. */
    rate-limit {
        responses-per-second 10;
        window 5;
    };

    /* Zone transfers (AXFR) hand the entire DNS database to the requester
       Setting to "none" prevents red team from enumerating all our hostnames */
    allow-transfer { none; };
};

logging {
    channel ncae_log {
        file "/var/log/named/named.log" versions 3 size 10m;
        severity dynamic;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default  { ncae_log; };
    category queries  { ncae_log; };
    category security { ncae_log; };
};

/* --- FORWARD ZONE (internal) --- */
zone "team${TEAM}.local" IN {
    type master;
    file "/var/named/team${TEAM}.local.fwd";
    allow-update { none; };
};

/* --- REVERSE ZONE (internal) --- */
zone "${TEAM}.168.192.in-addr.arpa" IN {
    type master;
    file "/var/named/team${TEAM}.local.rev";
    allow-update { none; };
};
EOF

# -- 8. Forward zone file ------------------------------------------------------
echo "[*] Writing forward zone (CORRECTED IPs)..."
# VERIFIED FROM TOPOLOGY:
#   .1  = Router
#   .5  = Web Server
#   .7  = Database        <-- was wrongly mapped to DNS before
#   .12 = DNS (this VM)   <-- was wrongly mapped to DB before
#   .15 = Backup
#   .14 = Shell/SMB (external IP 172.18.14.t)

mkdir -p /var/named
cat > "/var/named/team${TEAM}.local.fwd" <<EOF
\$TTL 86400
@   IN SOA  ns1.team${TEAM}.local. admin.team${TEAM}.local. (
            ${SERIAL} ; serial (epoch) - auto-increments on every re-run
            3600      ; refresh
            1800      ; retry
            604800    ; expire
            86400 )   ; minimum

            IN  NS  ns1.team${TEAM}.local.

ns1         IN  A   192.168.${TEAM}.12
router      IN  A   192.168.${TEAM}.1
www         IN  A   192.168.${TEAM}.5
db          IN  A   192.168.${TEAM}.7
dns         IN  A   192.168.${TEAM}.12
shell       IN  A   172.18.14.${TEAM}
backup      IN  A   192.168.${TEAM}.15
EOF

# -- 9. Reverse zone file ------------------------------------------------------
echo "[*] Writing reverse zone..."
cat > "/var/named/team${TEAM}.local.rev" <<EOF
\$TTL 86400
@   IN SOA  ns1.team${TEAM}.local. admin.team${TEAM}.local. (
            ${SERIAL} ; serial (epoch)
            3600      ; refresh
            1800      ; retry
            604800    ; expire
            86400 )   ; minimum

            IN  NS  ns1.team${TEAM}.local.

1           IN  PTR router.team${TEAM}.local.
5           IN  PTR www.team${TEAM}.local.
7           IN  PTR db.team${TEAM}.local.
12          IN  PTR dns.team${TEAM}.local.
15          IN  PTR backup.team${TEAM}.local.
EOF

# -- 10. Permissions + SELinux ------------------------------------------------
# named process runs as user "named" - it needs read access to zone files
# chmod 750 means named:named can read/exec, others cannot (prevents info leak)
# restorecon applies the correct SELinux file context - without this, SELinux
# will deny named from reading files even if Unix permissions are correct
chown -R named:named /var/named/
chmod -R 750 /var/named/  # named:named only - zone files not world-readable
mkdir -p /var/log/named && chown named:named /var/log/named && chmod 750 /var/log/named
restorecon -Rv /var/named/ 2>/dev/null || true

# -- 11. Validate and start BIND -----------------------------------------------
echo "[*] Validating BIND config..."
if named-checkconf /etc/named.conf 2>&1; then
    named-checkzone "team${TEAM}.local" "/var/named/team${TEAM}.local.fwd" 2>&1 || true
    named-checkzone "${TEAM}.168.192.in-addr.arpa" "/var/named/team${TEAM}.local.rev" 2>&1 || true
    systemctl enable named && systemctl restart named
    echo "[+] BIND started"
else
    echo "[!] named.conf validation failed - check above output"
fi

# -- 12. Fail2Ban for DNS brute ------------------------------------------------
echo "[*] Installing Fail2Ban..."
dnf install -y fail2ban 2>/dev/null || true
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true
# -- 12b. Auditd ---------------------------------------------------------------
echo "[*] Configuring auditd..."
dnf install -y audit 2>/dev/null || true
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_dns.rules <<'AUDITEOF'
-w /etc/named.conf -p wa -k named_config
-w /var/named -p wa -k zone_changes
-w /etc/ssh/sshd_config.d -p wa -k ssh_config_changes
-w /root/.ssh/authorized_keys -p wa -k root_keys_tamper
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_dns.rules 2>/dev/null || true

# -- 12a. rndc.key permissions -------------------------------------------------
# rndc.key grants control over named: stop, flush, reload, etc.
# If red team can read it they can run rndc remotely without touching the service.
# named reads it as user 'named' - group ownership gives it access without world-read.
# Also audit any write access so tampering shows up in audit.log immediately.
echo "[*] Locking down rndc.key..."
RNDC_KEY="/etc/rndc.key"
if [[ -f "$RNDC_KEY" ]]; then
    chown root:named "$RNDC_KEY"
    chmod 640 "$RNDC_KEY"
    echo "[+] rndc.key: root:named 640"
    # Add audit watch for rndc.key tampering
    auditctl -w "$RNDC_KEY" -p wa -k rndc_key_tamper 2>/dev/null || true
    # Persist the audit rule
    echo "-w ${RNDC_KEY} -p wa -k rndc_key_tamper" >> /etc/audit/rules.d/ncae_dns.rules
    augenrules --load 2>/dev/null || true
else
    echo "[!] rndc.key not found at $RNDC_KEY - named may generate it on first start"
    echo "    Re-run this block after named starts: chown root:named /etc/rndc.key && chmod 640 /etc/rndc.key"
fi

# -- 13. Watchdog cron ---------------------------------------------------------
# Watchdog: if BIND crashes or is killed by red team, restart it within 1 minute
cat > /etc/cron.d/ncae_dns_watchdog <<'EOF'
* * * * * root systemctl is-active --quiet named || systemctl restart named 2>/dev/null
EOF

echo ""
echo "[$(date)] === DNS Hardening COMPLETE ==="
echo "Credentials: $CRED_FILE"
echo ""
echo "SCORING CHECKLIST (2000pts):"
echo "  INT FWD (500): dig @192.168.${TEAM}.12 www.team${TEAM}.local"
echo "  INT REV (500): dig @192.168.${TEAM}.12 -x 192.168.${TEAM}.5"
echo "  EXT FWD (500): dig @172.18.13.${TEAM} www.team${TEAM}.local"
echo "  EXT REV (500): dig @172.18.13.${TEAM} -x 192.168.${TEAM}.5"
echo ""
echo "  ROUTER PORT FORWARDS REQUIRED FOR EXT SCORING:"
echo "  /ip firewall nat add chain=dstnat in-interface=ether1 dst-port=53 protocol=tcp action=dst-nat to-addresses=192.168.${TEAM}.12 to-ports=53"
echo "  /ip firewall nat add chain=dstnat in-interface=ether1 dst-port=53 protocol=udp action=dst-nat to-addresses=192.168.${TEAM}.12 to-ports=53"
echo ""
echo "  VERIFY: systemctl status named | grep -i running"
echo "  RELOAD ZONE (after edits): rndc reload"
