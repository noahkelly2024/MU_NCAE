#!/bin/bash

# NCAE Cyber Games - Web Server Deployment (Streamlined)
# Ubuntu 24.04 - Apache2 + SSL + Firewall

set -e

if [[ $EUID -ne 0 ]]; then
   echo "Error: Run as root"
   exit 1
fi

echo "=== NCAE Web Server Deployment ==="
read -p "Enter team number: " TEAM_NUM

WEB_IP="192.168.${TEAM_NUM}.5"
ROUTER_IP="192.168.${TEAM_NUM}.1"
DNS_IP="192.168.${TEAM_NUM}.12"

# Network Configuration
echo "[1/7] Configuring network..."
NETPLAN_FILE="/etc/netplan/01-netcfg.yaml"
mkdir -p /etc/netplan

cat > "$NETPLAN_FILE" <<EOF
network:
    version: 2
    renderer: NetworkManager
    ethernets:
        ens18:
            addresses:
                - ${WEB_IP}/24
            routes:
                - to: default
                  via: ${ROUTER_IP}
            nameservers:
                addresses: [${DNS_IP}, 8.8.8.8]
EOF

netplan apply
sleep 2

# Install Apache2
echo "[2/7] Installing Apache2..."
apt-get update -qq
apt-get install -y apache2 openssl curl &>/dev/null

# Create Team Page
echo "[3/7] Creating team page..."
cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>NCAE Cyber Games - Team ${TEAM_NUM}</title>
    <style>
        body { font-family: Arial; text-align: center; margin-top: 50px; background: #667eea; color: white; }
        h1 { font-size: 3em; }
    </style>
</head>
<body>
    <h1>Team ${TEAM_NUM}</h1>
    <p>NCAE Cyber Games 2026</p>
    <p>Web Server Online</p>
</body>
</html>
EOF

# SSL Setup
echo "[4/7] Configuring SSL..."
a2enmod ssl &>/dev/null
mkdir -p /etc/ssl/ncace

openssl genrsa -out /etc/ssl/ncace/web.key 4096 2>/dev/null
openssl req -new -key /etc/ssl/ncace/web.key -out /etc/ssl/ncace/web.csr \
    -subj "/C=US/O=Blue Team/CN=web.ncacecybergames.org" 2>/dev/null

cat > /etc/apache2/sites-available/default-ssl.conf <<'SSLCONF'
<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        
        SSLEngine on
        SSLCertificateFile /etc/ssl/ncace/web.crt
        SSLCertificateKeyFile /etc/ssl/ncace/web.key
        SSLCertificateChainFile /etc/ssl/ncace/ca.crt
        
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
            SSLOptions +StdEnvVars
        </FilesMatch>
    </VirtualHost>
</IfModule>
SSLCONF

# Firewall
echo "[5/7] Configuring firewall..."
ufw --force enable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Security Hardening
echo "[6/7] Applying security..."
sed -i 's/ServerTokens OS/ServerTokens Prod/' /etc/apache2/conf-available/security.conf
sed -i 's/ServerSignature On/ServerSignature Off/' /etc/apache2/conf-available/security.conf
a2enconf security &>/dev/null

# Start Services
echo "[7/7] Starting services..."
systemctl enable apache2 &>/dev/null
systemctl restart apache2

# Test
echo ""
echo "=== Deployment Complete ==="
echo "IP: ${WEB_IP}"
echo "HTTP Test: $(curl -s -o /dev/null -w '%{http_code}' http://localhost)"
echo ""
echo "Next steps:"
echo "1. Install SSL certificates: ./install-certs.sh"
echo "2. Test external: curl http://172.18.13.${TEAM_NUM}"
