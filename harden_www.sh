#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - Web Server Hardening (Ubuntu 24.04)
# VM: 192.168.t.5  |  Services: HTTP (80) 500pts, HTTPS (443) 1500pts,
#                               WWW Content 1500pts  => 3500pts total
# FIXES: SSL VirtualHost written, no set -e kill on missing services,
#        CISA 14+ char passwords, jailed users, Wazuh agent, 80->443 redirect
# Run as root. Re-run safe.
# =============================================================================
# DO NOT use set -euo pipefail here - many commands probe for optional services
# (nginx, wazuh) that may not be installed. set -e would abort the script on the
# first non-zero exit, leaving the VM partially hardened.
LOGFILE="/vagrant/logs/ncae_harden_www.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === WWW Hardening START ==="

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | head -1 2>/dev/null || echo "1")
echo "[*] Team number: $TEAM"

# -- Password generator (CISA: 14+ chars, upper+lower+digit+special) ----------
gen_pass() {
    local len=${1:-16}
    local pass
    while true; do
        pass=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=' </dev/urandom | head -c "$len")
        # Ensure CISA complexity: upper, lower, digit, special
        [[ "$pass" =~ [A-Z] ]] && \
        [[ "$pass" =~ [a-z] ]] && \
        [[ "$pass" =~ [0-9] ]] && \
        [[ "$pass" =~ [^A-Za-z0-9] ]] && break
    done
    echo "$pass"
}

CRED_FILE="/root/ncae_credentials_www.txt"
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"
echo "# NCAE WWW Credentials - $(date)" >> "$CRED_FILE"

# -- 1. Update -----------------------------------------------------------------
echo "[*] Updating packages..."
apt-get update -y && apt-get upgrade -y --no-new-recommends

# -- 2. Install tools ----------------------------------------------------------
echo "[*] Installing security tools..."
apt-get install -y ufw fail2ban auditd aide libpam-pwquality curl wget libcap2-bin 2>/dev/null || true

# -- 3. User account lockdown + CISA passwords --------------------------------
echo "[*] Locking down user accounts with CISA-compliant passwords..."
KEEP_USERS=("root" "ubuntu" "www-data" "scoring" "daemon" "nobody")
# Add vagrant to whitelist only when running in a local Vagrant lab
[[ -d /vagrant ]] && KEEP_USERS+=("vagrant")

while IFS= read -r user; do
    uid=$(id -u "$user" 2>/dev/null || echo 0)
    if [[ $uid -ge 1000 ]] && [[ ! " ${KEEP_USERS[*]} " == *" $user "* ]]; then
        NEW_PASS=$(gen_pass 16)
        echo "$user:$NEW_PASS" | chpasswd 2>/dev/null || true
        echo "USER $user : $NEW_PASS" >> "$CRED_FILE"
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        echo "  [-] Locked shell + changed password: $user"
    fi
done < <(cut -d: -f1 /etc/passwd)

# Root password
ROOT_PASS=$(gen_pass 20)
echo "root:$ROOT_PASS" | chpasswd 2>/dev/null || true
echo "ROOT password: $ROOT_PASS" >> "$CRED_FILE"

# -- 4. Create jailed users for common accounts --------------------------
echo "[*] Creating jailed users..."
JAILED_USERS=("admin" "webmaster" "webadmin")
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
    echo "  [+] Jailed user: $juser"
done

# -- 5. SSH hardening ---------------------------------------------------------
echo "[*] Hardening SSH..."
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/ncae_harden.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/ssh/banner
AllowUsers *@192.168.${TEAM}.0/24 *@127.0.0.1
EOF
echo "Authorized access only - NCAE CyberGames 2026" > /etc/ssh/banner
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# -- 6. UFW firewall -----------------------------------------------------------
echo "[*] Configuring UFW..."
ufw --force reset
ufw default deny incoming
ufw default deny outgoing
ufw allow 22/tcp    comment "SSH"
ufw allow 80/tcp    comment "HTTP scoring"
ufw allow 443/tcp   comment "HTTPS scoring"
ufw allow out to "192.168.${TEAM}.0/24" comment "Internal LAN outbound"
ufw allow out to "172.18.0.0/16" comment "Scoring engine + CA server"
ufw allow out to any port 53 comment "DNS resolution"
ufw --force enable

# -- 7. Apache hardening (with SSL VirtualHost) --------------------------------
if command -v apache2 &>/dev/null || dpkg -l apache2 &>/dev/null 2>&1; then
    echo "[*] Hardening Apache2..."

    # Enable required modules
    a2dismod -f status autoindex cgi 2>/dev/null || true  # Remove modules that expose server info or run scripts
    a2enmod headers ssl rewrite 2>/dev/null || true        # headers=security headers, ssl=HTTPS, rewrite=80->443 redirect

    # Security config (based on Aptive hardening guide)
    cat > /etc/apache2/conf-available/ncae_security.conf <<'EOF'
# Hide Apache version from HTTP response headers
ServerTokens Prod
# Suppress Apache version from error pages
ServerSignature Off
# Disable HTTP TRACE (used in cross-site tracing attacks)
TraceEnable Off
# Prevents inode/mtime leakage via ETag headers
FileETag None
Timeout 60
MaxKeepAliveRequests 100

# Security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=()"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
Header always unset X-Powered-By

<Directory /var/www/>
    Options FollowSymLinks
    AllowOverride None
    Require all granted
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>
EOF
    a2disconf security 2>/dev/null || true      # disable default security.conf so ours takes priority
    a2enconf ncae_security 2>/dev/null || true

    # -- SSL Certificate Setup --------------------------------------------------
    # CA: ca.ncaecybergames.org | 172.18.0.38
    SSL_DIR="/etc/ssl/ncae"
    mkdir -p "$SSL_DIR/private" "$SSL_DIR/certs"
    chmod 700 "$SSL_DIR/private"

    DOMAIN="www.team${TEAM}.local"
    echo "[*] Generating CSR for $DOMAIN (CA: ca.ncaecybergames.org)..."

    # Generate private key + CSR
    # Generate a 4096-bit RSA private key and a Certificate Signing Request (CSR)
    # -nodes = no passphrase on the key (needed for Apache to start without manual input)
    # The CSR is sent to the competition CA at 172.18.0.38 to get a signed certificate
    echo "    [1/2] Generating private key and CSR..."
    openssl req -new -newkey rsa:4096 -nodes \
        -keyout "$SSL_DIR/private/server.key" \
        -out "$SSL_DIR/certs/server.csr" \
        -subj "/CN=${DOMAIN}/O=NightHax/C=US" 2>&1
    chmod 600 "$SSL_DIR/private/server.key"

    if [[ ! -f "$SSL_DIR/private/server.key" ]]; then
        echo "[!] ERROR: server.key not generated - check openssl output above"
    else
        echo "    [+] server.key generated OK"
    fi

    echo "    [2/2] Generating self-signed placeholder cert..."
    openssl x509 -req -days 365 \
        -in "$SSL_DIR/certs/server.csr" \
        -signkey "$SSL_DIR/private/server.key" \
        -out "$SSL_DIR/certs/server.crt" 2>&1

    if [[ ! -f "$SSL_DIR/certs/server.crt" ]]; then
        echo "[!] ERROR: server.crt not generated"
    else
        echo "    [+] server.crt generated OK"
    fi

    echo "[!] PLACEHOLDER self-signed cert installed - REPLACE with CA-signed cert from 172.18.0.38"
    echo "    Steps:"
    echo "    1. scp $SSL_DIR/certs/server.csr to CA machine"
    echo "    2. Get signed cert back, place at $SSL_DIR/certs/server.crt"
    echo "    3. systemctl restart apache2"
    echo "CA_CSR_PATH: $SSL_DIR/certs/server.csr" >> "$CRED_FILE"

    # HTTP VirtualHost - redirect all to HTTPS
    # NOTE: Using %{HTTP_HOST} so redirect works whether accessed by hostname or IP
    cat > /etc/apache2/sites-available/000-default.conf <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    ServerAlias *
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}\$1 [R=301,L]
    ErrorLog \${APACHE_LOG_DIR}/http_error.log
    CustomLog \${APACHE_LOG_DIR}/http_access.log combined
</VirtualHost>
EOF

    # HTTPS VirtualHost
    cat > /etc/apache2/sites-available/default-ssl.conf <<EOF
<VirtualHost *:443>
    ServerName ${DOMAIN}
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile      ${SSL_DIR}/certs/server.crt
    SSLCertificateKeyFile   ${SSL_DIR}/private/server.key
    # SSLCACertificateFile - uncomment and set to CA cert AFTER getting signed cert from 172.18.0.38
    # SSLCACertificateFile  ${SSL_DIR}/certs/ca.crt

    # Strong SSL settings
    # TLS 1.2+ only; older versions are broken
    SSLProtocol             all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    # Let client pick cipher from our list (modern best practice)
    SSLHonorCipherOrder     off
    # Disable session tickets - they bypass perfect forward secrecy
    SSLSessionTickets       off

    # HSTS: tells browsers to always use HTTPS for 2 years - prevents SSL stripping attacks
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    <Directory /var/www/html>
        Options FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/ssl_access.log combined
</VirtualHost>
EOF

    a2ensite default-ssl 2>/dev/null || true

    # Validate and restart
    if apache2ctl configtest 2>/dev/null; then
        systemctl restart apache2 && echo "[+] Apache restarted OK"
    else
        echo "[!] Apache configtest failed - check manually"
        apache2ctl configtest 2>&1 | tee -a "$LOGFILE"
    fi
fi

# -- 8. Nginx hardening (if present) ------------------------------------------
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo "[*] Hardening Nginx..."
    cat > /etc/nginx/conf.d/ncae_security.conf <<'EOF'
server_tokens off;
add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
EOF
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || echo "[!] Nginx config issue"
fi

# -- 9. Fail2Ban ---------------------------------------------------------------
echo "[*] Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.d/ncae.conf <<'EOF'
[sshd]
enabled = true
maxretry = 3
bantime = 3600
findtime = 600

[apache-auth]
enabled = true
maxretry = 5
bantime = 3600

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true
EOF
systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
# -- 10. Auditd ----------------------------------------------------------------
echo "[*] Configuring auditd..."
systemctl enable auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ncae_www.rules <<'AUDITEOF'
-w /var/www/html -p wa -k webroot_changes
-w /etc/apache2 -p wa -k apache_config
-w /etc/ssh/sshd_config.d -p wa -k ssh_config
-w /etc/ssl/ncae -p wa -k ssl_cert_changes
AUDITEOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ncae_www.rules 2>/dev/null || true

# -- 11. Wazuh agent (removed - install manually if needed) -------------------

# -- 12. File integrity baseline -----------------------------------------------
# Takes a SHA256 hash of every file in the web root right after hardening
# The watchdog cron (step 14) re-checks these hashes every 5 minutes
# If a web shell is planted, the hash will change and the alert fires
echo "[*] Creating web root baseline..."
find /var/www -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null > /root/www_baseline.sha256 || true
echo "[+] Baseline: /root/www_baseline.sha256 | Check: sha256sum -c /root/www_baseline.sha256"

# -- 13. Disable unnecessary services -----------------------------------------
echo "[*] Disabling unnecessary services..."
for svc in telnet ftp rsh rlogin avahi-daemon cups; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

# -- 14. Watchdog cron ---------------------------------------------------------
cat > /etc/cron.d/ncae_www_watchdog <<'EOF'
* * * * * root systemctl is-active --quiet apache2 || systemctl restart apache2 2>/dev/null
* * * * * root systemctl is-active --quiet nginx   || systemctl restart nginx 2>/dev/null
*/5 * * * * root sha256sum -c /root/www_baseline.sha256 >> /var/log/ncae_integrity.log 2>&1
EOF

# -- 15. PAM password policy (CISA 14+ chars) ---------------------------------
echo "[*] Enforcing CISA password policy..."
if command -v pam-auth-update &>/dev/null; then
    cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 4
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
    pam-auth-update --enable pwquality 2>/dev/null || true
elif command -v authselect &>/dev/null; then
    authselect enable-feature with-pwquality 2>/dev/null || true
fi

echo ""
echo "[$(date)] === WWW Hardening COMPLETE ==="
echo "Credentials saved to: $CRED_FILE"
echo ""
echo "SCORING CHECKLIST:"
echo "  HTTP  (500): curl -I http://192.168.${TEAM}.5"
echo "  HTTPS (1500): curl -Ik https://192.168.${TEAM}.5"
echo "  Content(1500): curl -s https://192.168.${TEAM}.5 | grep -i title"
echo ""
echo "  [!!] ACTION: Replace self-signed cert with CA-signed from 172.18.0.38"
echo "  CSR at: /etc/ssl/ncae/certs/server.csr"
echo "  After getting signed cert:"
echo "    cp signed.crt /etc/ssl/ncae/certs/server.crt"
echo "    systemctl restart apache2"
