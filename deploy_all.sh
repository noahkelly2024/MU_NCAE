#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - deploy_all.sh (FIXED v2)
#
# PURPOSE: Single entry point that runs recon, the correct harden script for
#          this VM, starts the monitor in a tmux session, and kicks off the
#          first config backup. Run this immediately after gaining access.
#
# TEAM/ROLE AUTO-DETECTION:
#   - Reads IP addresses from 'ip addr show' and matches against known topology
#   - 192.168.t.5  -> www     (Apache/HTTPS)
#   - 192.168.t.7  -> db      (PostgreSQL)
#   - 192.168.t.12 -> dns     (BIND)
#   - 172.18.14.t  -> shell   (SSH + Samba) -- NOTE: 172.18 not 192.168
#   - 192.168.t.15 -> backup  (storage only)
#   - Manual arg   -> router  (MikroTik via SSH)
#
# FIXES v2:
#   - TEAM detection on shell VM: now uses 172.18.14.t specifically,
#     not 172.18.*.* which could grab gateway (172.18.0.1 -> team=1 wrong)
#   - Backup push runs after monitor so SSH key has time to deploy
#   - Router role correctly passes $2 as router IP
#
# Usage:
#   sudo bash deploy_all.sh              # auto-detect
#   sudo bash deploy_all.sh www
#   sudo bash deploy_all.sh dns
#   sudo bash deploy_all.sh db
#   sudo bash deploy_all.sh shell
#   sudo bash deploy_all.sh backup
#   sudo bash deploy_all.sh router 172.18.13.5
# =============================================================================
LOGFILE="/vagrant/logs/ncae_deploy_all.log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"  # Lock before writing - log contains credentials
exec > >(tee -a "$LOGFILE") 2>&1
START=$(date +%s)

echo "================================================================"
echo " NCAE CyberGames 2026 - NightHax deploy_all.sh"
echo " $(date)"
echo "================================================================"

[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

# All scripts must live in the same directory as this file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -- TEAM detection ------------------------------------------------------------
# Grab all IP addresses on this machine (one per line)
MY_IPS=$(ip addr show | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+')

# First try: extract the third octet from a 192.168.t.x address
# grep -oP with \K drops everything before the match - returns just the team digit(s)
TEAM=$(echo "$MY_IPS" | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 || true)

if [[ -z "$TEAM" ]]; then
    # FIXED: Shell VM is on 172.18.14.t specifically - match that subnet, not all of 172.18.*
    # Without this fix, 172.18.0.1 (the gateway) would give team=0 or team=1 incorrectly
    TEAM=$(echo "$MY_IPS" | grep -oP '172\.18\.14\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 || true)
fi

if [[ -z "$TEAM" ]]; then
    # Last resort: prompt manually
    read -rp "[?] Could not detect team number. Enter manually: " TEAM
fi
echo "[*] Team: $TEAM"

# -- Role detection ------------------------------------------------------------
ROLE="${1:-auto}"
if [[ "$ROLE" == "auto" ]]; then
    # Match IPs against known topology to determine this VM's role
    if   echo "$MY_IPS" | grep -q "192\.168\.${TEAM}\.5";    then ROLE="www"
    elif echo "$MY_IPS" | grep -q "192\.168\.${TEAM}\.7";    then ROLE="db"
    elif echo "$MY_IPS" | grep -q "192\.168\.${TEAM}\.12";   then ROLE="dns"
    elif echo "$MY_IPS" | grep -q "172\.18\.14\.${TEAM}";    then ROLE="shell"
    elif echo "$MY_IPS" | grep -q "192\.168\.${TEAM}\.15";   then ROLE="backup"
    else
        echo "[!] Could not detect role from IPs: $MY_IPS"
        echo "    Roles: www | dns | db | shell | backup | router"
        read -rp "Enter role: " ROLE
    fi
fi
echo "[*] Role: $ROLE"

# Wrapper that checks the script exists, makes it executable, runs it, and
# reports success/failure with the exit code
run_script() {
    local script="$1"; shift
    local full="${SCRIPT_DIR}/${script}"
    if [[ ! -f "$full" ]]; then
        echo "[!] Not found: $full"
        return 1
    fi
    echo ""
    echo "--------------------------------------------------------"
    echo " Running: $script $*"
    echo "--------------------------------------------------------"
    chmod +x "$full"
    bash "$full" "$@"
    local rc=$?
    [[ $rc -ne 0 ]] && echo "[!] $script exited $rc" || echo "[+] $script done"
}

# -- Phase 1: Recon ------------------------------------------------------------
# Always run recon first - gives you a baseline before anything is changed
echo ""
echo "[PHASE 1] Recon..."
run_script "00_recon.sh"

# -- Phase 2: Harden -----------------------------------------------------------
echo ""
echo "[PHASE 2] Hardening: $ROLE"
case "$ROLE" in
    www)    run_script "harden_www.sh" ;;
    dns)    run_script "harden_dns.sh" ;;
    db)     run_script "harden_db.sh" ;;
    shell)  run_script "harden_shell_smb.sh" ;;
    backup) run_script "harden_backup.sh" ;;
    router)
        # FIXED: $2 is the router IP passed directly to deploy_all.sh
        # e.g.: sudo bash deploy_all.sh router 172.18.13.5
        ROUTER_IP="${2:-172.18.13.${TEAM}}"
        run_script "harden_router.sh" "$TEAM" "$ROUTER_IP" "admin"
        ;;
    *) echo "[!] Unknown role: $ROLE"; exit 1 ;;
esac

# -- Phase 3: Start monitor in tmux -------------------------------------------
# tmux lets the monitor run in the background while you keep working in the foreground
# Attach any time with: tmux attach -t ncae_monitor
echo ""
echo "[PHASE 3] Starting monitor..."
if ! command -v tmux &>/dev/null; then
    # Install tmux if missing - try apt (Ubuntu) then dnf (Rocky)
    apt-get install -y tmux 2>/dev/null || dnf install -y tmux 2>/dev/null || true
fi

if command -v tmux &>/dev/null; then
    tmux kill-session -t ncae_monitor 2>/dev/null || true   # Kill stale session if re-running
    tmux new-session -d -s ncae_monitor "bash ${SCRIPT_DIR}/monitor.sh"
    echo "[+] Monitor: tmux attach -t ncae_monitor"
else
    # Fallback if tmux not available: run monitor in background with nohup
    nohup bash "${SCRIPT_DIR}/monitor.sh" >> /var/log/ncae_monitor.log 2>&1 &
    echo "[+] Monitor background PID $!"
fi

# -- Phase 4: Config backup ----------------------------------------------------
# FIXED: runs AFTER monitor phase so the SSH key generated in setup_ssh_key()
# has already been attempted before the first backup push happens
echo ""
echo "[PHASE 4] Config backup..."
run_script "backup_configs.sh" "192.168.${TEAM}.15"

# -- Phase 5: Script integrity lock --------------------------------------------
# chattr +i makes files immutable - even root cannot modify or delete them
# without first removing the immutable flag (chattr -i).
# This closes the attack path where red team gets root and appends malicious
# code to monitor.sh or incident_response.sh, causing your own automation to
# run their payload on the next loop.
# NOTE: chattr +i requires the filesystem to support it (ext4/xfs - yes; tmpfs/vfat - no)
# If this fails silently (e.g. /vagrant is a vboxsf mount), the scripts are still
# chmod 700 root-owned. Check: lsattr deploy_all.sh
echo ""
echo "[PHASE 5] Locking script integrity..."
if command -v chattr &>/dev/null; then
    for f in "${SCRIPT_DIR}"/*.sh; do
        chattr +i "$f" 2>/dev/null && echo "  [+] Immutable: $f" || \
            echo "  [!] chattr failed on $f (filesystem may not support it - OK on vboxsf)"
    done
    echo "[*] To unlock for edits: chattr -i <script>"
else
    echo "[!] chattr not available - applying chmod 444 instead"
    chmod 444 "${SCRIPT_DIR}"/*.sh
fi

# -- Summary -------------------------------------------------------------------
ELAPSED=$(( $(date +%s) - START ))
echo ""
echo "================================================================"
echo " DEPLOY COMPLETE - ${ELAPSED}s | $(date)"
echo "================================================================"
echo ""
echo "[ CREDENTIALS ]"
echo "  Credentials saved to: /root/ncae_credentials_*.txt"
echo "  View with: cat /root/ncae_credentials_${ROLE}.txt (root only - chmod 600)"

echo ""
echo "[ SCORING CHECKLIST - $ROLE ]"
case "$ROLE" in
    www)
        echo "  HTTP   (500): curl -I http://192.168.${TEAM}.5"
        echo "  SSL   (1500): curl -Ik https://192.168.${TEAM}.5"
        echo "  CONTENT(1500): curl -sk https://192.168.${TEAM}.5 | grep -i '<title>'"
        echo "  [!!] Replace self-signed cert: /etc/ssl/ncae/certs/server.csr -> CA 172.18.0.38"
        ;;
    dns)
        echo "  INT FWD (500): dig @192.168.${TEAM}.12 www.team${TEAM}.local"
        echo "  INT REV (500): dig @192.168.${TEAM}.12 -x 192.168.${TEAM}.5"
        echo "  EXT FWD (500): dig @172.18.13.${TEAM} www.team${TEAM}.local"
        echo "  EXT REV (500): dig @172.18.13.${TEAM} -x 192.168.${TEAM}.5"
        echo "  [!!] Router port forwards 53 TCP+UDP -> 192.168.${TEAM}.12 required"
        ;;
    db)
        echo "  Postgres (500): psql -h 192.168.${TEAM}.7 -U scoring -d scoringdb"
        echo "  (.pgpass set up by harden_db.sh - or: cat /root/ncae_credentials_db.txt)"
        echo "  Verify listen: ss -tlnp | grep 5432"
        ;;
    shell)
        echo "  SSH    (1000): Add scoring pubkey -> /home/scoring/.ssh/authorized_keys"
        echo "    Then: /root/ncae_lock_ssh.sh"
        echo "  SMB Login (500): smbclient -L //172.18.14.${TEAM}/ -U scoring"
        echo "  SMB Write(1000): smbclient //172.18.14.${TEAM}/write -U scoring -c 'put /etc/hostname t'"
        echo "  SMB Read (1000): smbclient //172.18.14.${TEAM}/read -U scoring -c 'get readme.txt /tmp/t'"
        echo "  [!!] Check scoreboard at 10:30 for exact share names"
        ;;
    router)
        echo "  ICMP  (500): ping -c3 172.18.13.${TEAM}"
        echo "  Verify: /ip firewall nat print | grep ncae"
        ;;
    backup)
        echo "  Not scored. Verify backup storage: ls /srv/ncae_backups/"
        echo "  Lock SSH when ready: /root/ncae_lock_backup_ssh.sh"
        ;;
esac

echo ""
echo "[ QUICK COMMANDS ]"
echo "  Monitor:  tmux attach -t ncae_monitor"
echo "  Alerts:   tail -f /var/log/ncae_alerts.log"
echo "  IR:       sudo bash ${SCRIPT_DIR}/incident_response.sh"
echo "  Backup:   sudo bash ${SCRIPT_DIR}/backup_configs.sh"
echo ""
echo "[ FREE CTF FLAG - submit at 11:00 AM ]"
# NOTE: This flag is the public welcome flag from the competition platform.
echo "  c2ctf{welcomeToTheCyberGames!}"
