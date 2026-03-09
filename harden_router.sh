#!/usr/bin/env bash
# shellcheck disable=SC2154  # wanIface is a RouterOS variable inside a heredoc, not a bash var
# =============================================================================
# NCAE Cyber Games 2026 - harden_router.sh (FIXED v2)
# MikroTik RouterOS - Run from a Linux box via SSH to the router
# Router External: 172.18.13.t | Internal: 192.168.t.1
# Scored: Router ICMP (500pts)
# Required for ext scoring: port forwards 80/443/53
#
# FIXES v2:
#   - Flush existing rules BEFORE adding (removes red team persistence)
#   - WAN interface auto-detected via RouterOS :local, not hardcoded ether1
#   - Log rules use positional index, not fragile comment-based place-before
#   - Password changed LAST so import session stays alive
#   - SCP uses MikroTik root '/'
#   - Added external LAN (172.18.0.0/16) to SSH allow for jumphost access
#
# Usage: bash harden_router.sh <team_number> <router_ip> [router_user]
# =============================================================================
LOGFILE="/vagrant/logs/ncae_router_$(date +%Y%m%d_%H%M%S).log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === Router Hardening START ==="

TEAM="${1:-}"
ROUTER_IP="${2:-}"
ROUTER_USER="${3:-admin}"

if [[ -z "$TEAM" || -z "$ROUTER_IP" ]]; then
    echo "Usage: $0 <team_number> <router_ip> [router_user]"
    echo "Example: $0 5 172.18.13.5 admin"
    TEAM="X"
    ROUTER_IP="172.18.13.X"
fi

gen_pass() {
    local len=${1:-16}; local pass
    while true; do
        # Note: Avoiding $ in router password - RouterOS RSC files may misinterpret $
        # Using ! @ # % ^ & * ( ) _ + = instead
        pass=$(tr -dc 'A-Za-z0-9!@#%^&*()_+=' </dev/urandom | head -c "$len")
        [[ "$pass" =~ [A-Z] ]] && [[ "$pass" =~ [a-z] ]] && \
        [[ "$pass" =~ [0-9] ]] && [[ "$pass" =~ [^A-Za-z0-9] ]] && break
    done; echo "$pass"
}

ROUTER_PASS=$(gen_pass 16)
CRED_FILE="/root/ncae_credentials_router.txt"
# Create and lock BEFORE writing any secrets (prevents race window)
: > "$CRED_FILE"
chmod 600 "$CRED_FILE"
{
    echo "# NCAE Router Credentials - $(date)"
    echo "Router IP: $ROUTER_IP"
    echo "Router admin password: $ROUTER_PASS"
} >> "$CRED_FILE"
echo "[*] Router password generated (saved to $CRED_FILE)"
echo "[!] Password change is applied LAST - your current session remains live during import"

cat > /root/ncae_router_commands.rsc <<EOF
# NCAE CyberGames 2026 - MikroTik RouterOS Hardening
# Team ${TEAM} | Ext: 172.18.13.${TEAM} | Int: 192.168.${TEAM}.1

# -- Step 1: Disable unused management services --------------------------------
# telnet/ftp/www/api expose the router to exploitation over HTTP or plaintext protocols
# winbox is the MikroTik GUI - disable to reduce attack surface, SSH is all we need
/ip service disable telnet,ftp,www,api,api-ssl,winbox
/ip service enable ssh
/ip service set ssh port=22

# -- Step 2: Disable attack surface -------------------------------------------
# neighbor-discovery (LLDP/CDP equivalent) broadcasts router info to the network
# mac-server allows Winbox access via MAC address even without IP - disable both
# bandwidth-server, SNMP, UPnP: all unnecessary services that expand attack surface
# allow-remote-requests=no: prevents the router from acting as a DNS resolver for others
/ip neighbor discovery-settings set discover-interface-list=none
/tool mac-server set allowed-interface-list=none
/tool mac-server mac-winbox set allowed-interface-list=none
/tool bandwidth-server set enabled=no
/snmp set enabled=no
/ip upnp set enabled=no
/ip dns set allow-remote-requests=no

# -- Step 3: Detect WAN interface from default route --------------------------
# RouterOS scripting: :local declares a variable, [/ip route get ...] queries the routing table
# We detect WAN dynamically instead of hardcoding 'ether1' in case the interface name differs
# If detection fails, we fall back to ether1 and log a warning-
:local wanIface [/ip route get [find dst-address="0.0.0.0/0"] gateway-interface]
:if (\$wanIface = "") do={ :set wanIface "ether1"; :log warning "WAN not detected, using ether1" }
:log info ("WAN interface: " . \$wanIface)

# -- Step 4: FLUSH all existing rules (remove red team persistence) ------------
# [find] returns all existing rules; 'remove' deletes them
# Critical: red team may have planted persistent firewall rules that re-open backdoors
# Flushing first guarantees a clean slate before we add our rules
/ip firewall filter remove [find]
/ip firewall nat remove [find]

# -- Step 5: Connection tracking -----------------------------------------------
/ip firewall connection tracking set enabled=yes

# -- Step 6: INPUT chain -------------------------------------------------------
# INPUT chain = traffic destined FOR the router itself (management traffic)
# Order matters: established/related first (stateful, fast path), then specific allows,
# then log everything that reaches the end (for visibility), then drop
/ip firewall filter
add chain=input connection-state=established,related action=accept comment="ncae-input-established"
add chain=input connection-state=invalid action=drop comment="ncae-input-drop-invalid"
add chain=input protocol=icmp action=accept comment="ncae-ICMP-SCORING-DO-NOT-REMOVE"
# ^ DO NOT REMOVE: ICMP is how the scoring engine checks router uptime (500pts)
add chain=input protocol=tcp dst-port=22 src-address=192.168.${TEAM}.0/24 action=accept comment="ncae-ssh-internal-lan"
add chain=input protocol=tcp dst-port=22 src-address=172.18.0.0/16 action=accept comment="ncae-ssh-external-lan-jumphost"
add chain=input action=log log-prefix="DROP-IN: " comment="ncae-log-input"
add chain=input action=drop comment="ncae-drop-input"

# -- Step 7: FORWARD chain -----------------------------------------------------
# FORWARD chain = traffic passing THROUGH the router (LAN <-> WAN)
# We allow: established sessions, LAN going out, and scoring engine coming in to LAN
/ip firewall filter
add chain=forward connection-state=established,related action=accept comment="ncae-forward-established"
add chain=forward connection-state=invalid action=drop comment="ncae-forward-invalid"
add chain=forward src-address=192.168.${TEAM}.0/24 action=accept comment="ncae-forward-lan-out"
add chain=forward dst-address=192.168.${TEAM}.0/24 action=accept comment="ncae-forward-scoring-to-lan"
add chain=forward src-address=172.18.0.0/16 dst-address=192.168.${TEAM}.0/24 action=accept comment="ncae-forward-ext-to-int"
add chain=forward action=log log-prefix="DROP-FWD: " comment="ncae-log-forward"
add chain=forward action=drop comment="ncae-drop-forward"

# -- Step 8: NAT srcnat --------------------------------------------------------
# Source NAT (masquerade): rewrites the source IP of outbound packets to the WAN IP
# Required for internal VMs (192.168.t.x) to reach the internet/scoring engine
# masquerade automatically picks the correct WAN IP (better than static SNAT)
/ip firewall nat
add chain=srcnat out-interface=\$wanIface action=masquerade comment="ncae-srcnat"

# -- Step 9: PORT FORWARDS (dstnat) using detected WAN interface ---------------
# Destination NAT: rewrites the destination IP of inbound packets
# Scoring engine hits 172.18.13.t (WAN) -> router rewrites to internal service IP
# Using $wanIface variable (set in Step 3) instead of hardcoded interface name
add chain=dstnat in-interface=\$wanIface dst-port=80 protocol=tcp \
    action=dst-nat to-addresses=192.168.${TEAM}.5 to-ports=80 comment="ncae-www-80"
add chain=dstnat in-interface=\$wanIface dst-port=443 protocol=tcp \
    action=dst-nat to-addresses=192.168.${TEAM}.5 to-ports=443 comment="ncae-www-443"
add chain=dstnat in-interface=\$wanIface dst-port=53 protocol=tcp \
    action=dst-nat to-addresses=192.168.${TEAM}.12 to-ports=53 comment="ncae-dns-tcp"
add chain=dstnat in-interface=\$wanIface dst-port=53 protocol=udp \
    action=dst-nat to-addresses=192.168.${TEAM}.12 to-ports=53 comment="ncae-dns-udp"

# -- Step 10: Verify before password change ------------------------------------
/ip firewall nat print
/ip firewall filter print
/ip service print
/ping 172.18.0.1 count=2

# -- Step 11: Change password LAST (keeps import session alive) ----------------
# If we change the password early in the script, the import session authenticates with
# the old password and dies mid-import. Putting it last ensures all rules are applied
# before the session is potentially disrupted.
/user set admin password="${ROUTER_PASS}"
:log info "Router hardening complete"

EOF

echo "[*] RSC file written to /root/ncae_router_commands.rsc"
chmod 600 /root/ncae_router_commands.rsc

if [[ "$ROUTER_IP" != "172.18.13.X" ]] && command -v ssh &>/dev/null; then
    echo "[*] Attempting push to $ROUTER_IP - enter CURRENT password when prompted"
    scp -o StrictHostKeyChecking=accept-new \
        /root/ncae_router_commands.rsc \
        "${ROUTER_USER}@${ROUTER_IP}:/ncae_router_commands.rsc" 2>/dev/null && \
    ssh -o StrictHostKeyChecking=accept-new "${ROUTER_USER}@${ROUTER_IP}" \
        "/import file-name=ncae_router_commands.rsc" 2>/dev/null && \
    echo "[+] Applied. New password in $CRED_FILE. Reconnect to verify." || \
    echo "[!] Auto-push failed - paste /root/ncae_router_commands.rsc manually into router terminal"
else
    echo "[!] Manual: ssh ${ROUTER_USER}@${ROUTER_IP} then paste /root/ncae_router_commands.rsc"
fi

echo ""
echo "[$(date)] === Router Hardening COMPLETE ==="
echo "SCORING CHECKLIST:"
echo "  ICMP  (500): ping 172.18.13.${TEAM}"
echo "  HTTP  (500): curl -I http://172.18.13.${TEAM}"
echo "  HTTPS(1500): curl -Ik https://172.18.13.${TEAM}"
echo "  DNS-F (500): dig @172.18.13.${TEAM} www.team${TEAM}.local"
echo "  DNS-R (500): dig @172.18.13.${TEAM} -x 192.168.${TEAM}.5"
echo "  Verify WAN: /ip route print where dst-address=0.0.0.0/0"
