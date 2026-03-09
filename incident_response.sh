#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - incident_response.sh (FIXED v2)
#
# FIXES v2:
#   - kill_suspicious_connections: scoring engine IP guard before block
#   - purge_ssh_keys: explicit WARNING + requires typing "CONFIRM" for scoring user
#   - restart_all_services: use systemctl list-unit-files exact match
#   - status_snapshot: shows [DOWN] not just [UP]
# =============================================================================
LOGFILE="/vagrant/logs/ncae_ir_$(date +%Y%m%d_%H%M%S).log"
mkdir -p /vagrant/logs
touch "$LOGFILE" && chmod 600 "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[$(date)] === Incident Response START ==="
[[ $EUID -ne 0 ]] && { echo "Run as root."; exit 1; }

TEAM=$(ip addr show | grep -oP '192\.168\.\K[0-9]+' | grep -E '^[0-9]+$' | head -1 2>/dev/null || echo "1")
# Known safe IPs - scoring engine range and internal LAN
# These subnets contain the scoring engine, internal VMs, and loopback
# Blocking any IP in these ranges risks killing scored services
SAFE_SUBNETS=("172.18." "192.168." "127.0.")

banner() {
    echo ""
    echo "==================================================="
    echo " $1"
    echo "==================================================="
}

is_safe_ip() {
    local ip="$1"
    for subnet in "${SAFE_SUBNETS[@]}"; do
        [[ "$ip" == ${subnet}* ]] && return 0
    done
    return 1
}

# -- 1: Kill suspicious connections --------------------------------------------
kill_suspicious_connections() {
    banner "KILL SUSPICIOUS CONNECTIONS"
    echo "[*] Established connections:"
    ss -tunp state established
    echo ""
    read -rp "IP to block/kill (or 'skip'): " BAD_IP
    [[ "$BAD_IP" == "skip" || -z "$BAD_IP" ]] && return

    # FIXED: Guard against blocking scoring engine or internal IPs
    if is_safe_ip "$BAD_IP"; then
        echo ""
        echo "  [!!] WARNING: $BAD_IP is in a safe/scoring subnet (172.18.x or 192.168.x)"
        echo "       Blocking this IP may KILL SCORING and cost you points."
        echo ""
        read -rp "  Type OVERRIDE to block anyway, or anything else to cancel: " OVERRIDE
        [[ "$OVERRIDE" != "OVERRIDE" ]] && echo "Cancelled." && return
    fi

    echo "[*] Killing connections from $BAD_IP..."

    # Validate IP format before passing to firewall commands
    if ! [[ "$BAD_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        echo "[!] Invalid IP format: '$BAD_IP' - aborting to prevent injection"
        return
    fi
    # Extract PIDs of processes with connections to/from BAD_IP, then kill them
    # awk $NF gets the last field (the process info), grep -oP extracts just the PID number
    # xargs -r only runs kill if there is at least one PID (avoids "kill: no arguments" error)
    ss -tunp state established | grep "$BAD_IP" | awk '{print $NF}' | \
        grep -oP 'pid=\K[0-9]+' | xargs -r kill -9 2>/dev/null || true

    if command -v ufw &>/dev/null; then
        ufw deny from "$BAD_IP" comment "IR $(date +%H%M)"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='${BAD_IP}' reject"
        firewall-cmd --reload
    else
        iptables -I INPUT -s "$BAD_IP" -j DROP
        iptables -I OUTPUT -d "$BAD_IP" -j DROP
    fi
    echo "[+] $BAD_IP blocked"
    echo "IR_BLOCK: $BAD_IP @ $(date)" >> "$LOGFILE"
}

# -- 2: Reverse shell hunt ----------------------------------------------------
kill_reverse_shells() {
    banner "HUNT & KILL REVERSE SHELLS"
    echo "[*] Suspicious processes:"
    # shellcheck disable=SC2009  # ps|grep used intentionally for display output
    ps aux | grep -E '\bnc\b|\bncat\b|\bsocat\b|\bbash -i\b|\bsh -i\b|\bpython[23]? -c\b|\bperl -e\b' | \
        grep -v grep
    echo ""
    echo "[*] Non-service established connections:"
    ss -tunp state established | grep -vE 'sshd|apache|nginx|postgres|named|smbd|nmbd'
    echo ""
    read -rp "PID to kill (or 'skip'): " BAD_PID
    [[ "$BAD_PID" == "skip" || -z "$BAD_PID" ]] && return
    # Validate PID is numeric
    if ! [[ "$BAD_PID" =~ ^[0-9]+$ ]]; then
        echo "[!] Invalid PID: '$BAD_PID' - must be numeric"
        return
    fi
    kill -9 "$BAD_PID" 2>/dev/null && echo "[+] PID $BAD_PID killed" || echo "[!] Could not kill $BAD_PID"
}

# -- 3: Web shell removal ------------------------------------------------------
remove_web_shells() {
    banner "REMOVE WEB SHELLS"
    echo "[*] Scanning /var/www..."
    local SHELLS
    # -r=recursive -l=list filenames only -n=line numbers
    # We want filenames (-l) here so we can delete them; -n would add line numbers to paths
    SHELLS=$(grep -rln --include="*.php" --include="*.phtml" --include="*.py" \
        -E 'eval\(|base64_decode\(|exec\(|system\(|passthru\(|shell_exec\(' \
        /var/www/ 2>/dev/null)
    if [[ -z "$SHELLS" ]]; then
        echo "[+] No web shells found"
    else
        echo "[!] Suspicious files:"
        echo "$SHELLS"
        read -rp "Delete these? (yes/no): " CONFIRM
        if [[ "$CONFIRM" == "yes" ]]; then
            # xargs -r: only run rm if there are actually files to remove
    echo "$SHELLS" | xargs -r rm -f
            systemctl restart apache2 2>/dev/null || systemctl restart nginx 2>/dev/null || true
            echo "[+] Removed and web server restarted"
        fi
    fi
    echo ""
    echo "[*] Files modified in /var/www in last 30 min:"
    find /var/www -type f -mmin -30 2>/dev/null
}

# -- 4: Purge SSH keys --------------------------------------------------------
# FIXED: explicit scoring key warning, requires "CONFIRM" not just "yes"
purge_ssh_keys() {
    banner "PURGE UNAUTHORIZED SSH KEYS"
    for home in /root /home/*; do
        local keyfile="$home/.ssh/authorized_keys"
        [[ ! -f "$keyfile" ]] && continue
        local user
        user=$(basename "$home")
        echo ""
        echo "[ $keyfile ]"
        cat -n "$keyfile"
        echo ""

        if [[ "$user" == "scoring" ]]; then
            echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "  !! WARNING: This is the SCORING USER key file !!"
            echo "  !! Clearing this KILLS SSH scoring (1000pts)  !!"
            echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo ""
            read -rp "  Type CONFIRM to clear (or anything else to skip): " C
            [[ "$C" != "CONFIRM" ]] && echo "  Skipped scoring key." && continue
        else
            read -rp "  Clear all keys in this file? (yes/no): " CONFIRM
            [[ "$CONFIRM" != "yes" ]] && continue
        fi

        cp "$keyfile" "${keyfile}.bak.$(date +%s)"
        : > "$keyfile"
        echo "[+] Cleared $keyfile (backup: ${keyfile}.bak.*)"
        echo "    Re-add scoring key: echo 'PUBKEY' >> $keyfile"
    done
}

# -- 5: Purge cron ------------------------------------------------------------
purge_cron() {
    banner "PURGE UNAUTHORIZED CRON JOBS"
    echo "[*] /etc/cron.d/:"
    ls -la /etc/cron.d/ 2>/dev/null
    cat /etc/cron.d/* 2>/dev/null
    echo ""
    echo "[*] root crontab:"
    crontab -l 2>/dev/null || echo "(empty)"
    echo ""
    read -rp "Remove non-NCAE cron entries in /etc/cron.d/? (yes/no): " CONFIRM
    if [[ "$CONFIRM" == "yes" ]]; then
        # Remove all cron files that do NOT have "ncae" in the name
    # This preserves our watchdog crons while removing any red team persistence
    for f in /etc/cron.d/*; do
            [[ "$f" != *"ncae"* ]] && rm -f "$f" && echo "  Removed: $f"
        done
        echo "[+] Done. NCAE watchdogs preserved."
    fi
}

# -- 6: Re-harden -------------------------------------------------------------
re_harden() {
    banner "FORCE RE-HARDEN"
    echo "[*] Hardening scripts:"
    SCRIPT_DIRS="/root $(dirname "$0") /opt/ncae"
    for d in $SCRIPT_DIRS; do
        ls "$d"/harden_*.sh 2>/dev/null && break
    done || echo "  Not found in $SCRIPT_DIRS"
    read -rp "Script path (or 'skip'): " SCRIPT
    [[ "$SCRIPT" == "skip" || -z "$SCRIPT" ]] && return
    # Validate: must be absolute path to an existing file
    # Require absolute path to prevent directory traversal attacks
    # (e.g. someone typing "../../etc/cron.d/evil" in the prompt)
    if [[ ! "$SCRIPT" =~ ^/ ]]; then
        echo "[!] Must be an absolute path (e.g. /root/harden_www.sh)"
        return
    fi
    [[ -f "$SCRIPT" ]] && bash "$SCRIPT" || echo "[!] Not found: $SCRIPT"
}

# -- 7: Restore config --------------------------------------------------------
restore_config() {
    banner "RESTORE CONFIG FROM BACKUP"

    # Build list of available backup timestamps
    mapfile -t BACKUPS < <(find /root/ncae_config_backups/ -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    if [[ ${#BACKUPS[@]} -eq 0 ]]; then
        echo "[!] No local backups found in /root/ncae_config_backups/"
        return
    fi

    echo "[*] Available backups:"
    for i in "${!BACKUPS[@]}"; do
        echo "  $((i+1))) ${BACKUPS[$i]}"
    done
    echo ""
    read -rp "Select backup number (or 'skip'): " SEL
    [[ "$SEL" == "skip" || -z "$SEL" ]] && return
    if ! [[ "$SEL" =~ ^[0-9]+$ ]] || [[ $SEL -lt 1 ]] || [[ $SEL -gt ${#BACKUPS[@]} ]]; then
        echo "[!] Invalid selection"
        return
    fi
    TS="${BACKUPS[$((SEL-1))]}"
    echo ""
    echo "[*] Files in $TS:"
    ls "$TS"
    echo ""

    # Two types of restorables: directories (cp -r) and single files (cp)
    # Matches exactly what backup_configs.sh collects per VM:
    #   www:   apache2/ nginx/ ssh/ ufw/ ssl_ncae/ webroot/
    #   dns:   ssh/ bind/ var_named/ named.conf
    #   db:    ssh/ pg_hba.conf postgresql.conf
    #   shell: ssh/ smb.conf
    declare -A DIR_MAP=(
        ["apache2"]="/etc/apache2|apache2"
        ["nginx"]="/etc/nginx|nginx"
        ["ssh"]="/etc/ssh|ssh sshd"
        ["ufw"]="/etc/ufw|"
        ["ssl_ncae"]="/etc/ssl/ncae|"
        ["bind"]="/etc/bind|named bind9"
        ["var_named"]="/var/named|named bind9"
        ["webroot"]="/var/www/html|apache2 nginx"
    )
    declare -A FILE_MAP=(
        ["named.conf"]="/etc/named.conf|named bind9"
        ["smb.conf"]="/etc/samba/smb.conf|smb nmb"
        ["pg_hba.conf"]="|postgresql"
        ["postgresql.conf"]="|postgresql"
    )

    echo "[*] Restorable items found:"
    FOUND_DIRS=()
    FOUND_FILES=()

    for dname in "${!DIR_MAP[@]}"; do
        if [[ -d "$TS/$dname" ]]; then
            FOUND_DIRS+=("$dname")
            echo "  ${#FOUND_DIRS[@]}d) $dname/ -> ${DIR_MAP[$dname]%%|*}/"
        fi
    done
    for fname in "${!FILE_MAP[@]}"; do
        if [[ -f "$TS/$fname" ]]; then
            FOUND_FILES+=("$fname")
            echo "  ${#FOUND_FILES[@]}f) $fname"
        fi
    done
    echo ""
    [[ ${#FOUND_DIRS[@]} -eq 0 && ${#FOUND_FILES[@]} -eq 0 ]] &&         echo "[!] No restorable configs in this backup" && return
    echo "  a) Restore ALL above"
    echo ""

    read -rp "Select (e.g. 1d, 2f, a, or 'skip'): " FCHOICE
    [[ "$FCHOICE" == "skip" || -z "$FCHOICE" ]] && return

    do_restore_dir() {
        local dname="$1"
        local dest="${DIR_MAP[$dname]%%|*}"
        local svcs="${DIR_MAP[$dname]##*|}"
        echo "[*] Restoring $dname/ -> $dest/"
        mkdir -p "$dest"
        cp -r "$TS/$dname/." "$dest/"
        echo "  [+] Files copied"
        for svc in $svcs; do
            [[ -z "$svc" ]] && continue
            if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
                systemctl restart "$svc" 2>/dev/null && echo "  [+] $svc restarted" || echo "  [!] $svc restart failed"
                break
            fi
        done
    }

    do_restore_file() {
        local fname="$1"
        local svcs="${FILE_MAP[$fname]##*|}"
        local dest="${FILE_MAP[$fname]%%|*}"
        # pg_hba.conf/postgresql.conf: find actual versioned path
        if [[ "$fname" == pg_hba.conf || "$fname" == postgresql.conf ]]; then
            dest=$(find /etc/postgresql -name "$fname" 2>/dev/null | head -1)
            [[ -z "$dest" ]] && dest="/etc/postgresql/16/main/$fname"
        fi
        echo "[*] Restoring $fname -> $dest"
        mkdir -p "$(dirname "$dest")"
        cp "$TS/$fname" "$dest"
        echo "  [+] File copied"
        for svc in $svcs; do
            [[ -z "$svc" ]] && continue
            if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
                systemctl restart "$svc" 2>/dev/null && echo "  [+] $svc restarted" || echo "  [!] $svc restart failed"
                break
            fi
        done
    }

    if [[ "$FCHOICE" == "a" ]]; then
        for dname in "${FOUND_DIRS[@]}"; do do_restore_dir "$dname"; done
        for fname in "${FOUND_FILES[@]}"; do do_restore_file "$fname"; done
    elif [[ "$FCHOICE" =~ ^([0-9]+)d$ ]]; then
        idx="${BASH_REMATCH[1]}"
        if [[ $idx -ge 1 && $idx -le ${#FOUND_DIRS[@]} ]]; then
            do_restore_dir "${FOUND_DIRS[$((idx-1))]}"
        else
            echo "[!] Invalid selection"
        fi
    elif [[ "$FCHOICE" =~ ^([0-9]+)f$ ]]; then
        idx="${BASH_REMATCH[1]}"
        if [[ $idx -ge 1 && $idx -le ${#FOUND_FILES[@]} ]]; then
            do_restore_file "${FOUND_FILES[$((idx-1))]}"
        else
            echo "[!] Invalid selection"
        fi
    else
        echo "[!] Invalid selection - use 1d, 2f, a, or skip"
    fi
}

# -- 8: Restart all services ---------------------------------------------------
# Auto-detects which scored services are installed on this VM
restart_all_services() {
    banner "EMERGENCY RESTART ALL SCORED SERVICES"
    echo "  1) Sequential (safe, slower)"
    echo "  2) Parallel (faster, less output)"
    read -rp "Mode (1/2): " MODE
    for svc in apache2 nginx named bind9 postgresql smb nmb samba ssh sshd; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            if [[ "$MODE" == "2" ]]; then
                systemctl restart "$svc" 2>/dev/null &
            else
                echo "[*] Restarting $svc..."
                systemctl restart "$svc" 2>/dev/null || true
                systemctl is-active --quiet "$svc" 2>/dev/null && \
                    echo "  [+] $svc UP" || echo "  [!] $svc STILL DOWN"
            fi
        fi
    done
    if [[ "$MODE" == "2" ]]; then
        wait
        echo "[*] All restarts fired. Status:"
        for svc in apache2 nginx named bind9 postgresql smb nmb samba ssh sshd; do
            systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || continue
            systemctl is-active --quiet "$svc" 2>/dev/null && \
                echo "  [+] $svc UP" || echo "  [!] $svc DOWN"
        done
    fi
}

# -- 9: Status snapshot --------------------------------------------------------
# FIXED: shows [DOWN] not just [UP]
status_snapshot() {
    banner "STATUS SNAPSHOT @ $(date '+%H:%M:%S')"
    echo "[ SERVICES ]"
    for svc in apache2 nginx named bind9 postgresql smb samba ssh sshd; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            systemctl is-active --quiet "$svc" 2>/dev/null && \
                echo "  [UP]   $svc" || echo "  [DOWN] $svc"
        fi
    done
    echo ""
    echo "[ CONNECTIONS ]"
    ss -tunp state established 2>/dev/null
    echo ""
    echo "[ DISK ]"
    df -h /
    echo ""
    echo "[ LOAD ]"
    uptime
    echo ""
    echo "[ RECENT FAILURES ]"
    journalctl -u sshd -u ssh --since "5 minutes ago" 2>/dev/null | \
        grep -i "fail\|invalid" | tail -10 || \
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 || true
    echo ""
    echo "[ RECENT ALERTS ]"
    tail -10 /var/log/ncae_alerts.log 2>/dev/null || echo "  None"
}

# -- Main menu -----------------------------------------------------------------
while true; do
    banner "NCAE INCIDENT RESPONSE - Team $TEAM - $(date '+%H:%M:%S')"
    echo "  1) Kill suspicious connections / block IP"
    echo "  2) Hunt & kill reverse shells"
    echo "  3) Remove web shells"
    echo "  4) Purge unauthorized SSH keys"
    echo "  5) Purge unauthorized cron jobs"
    echo "  6) Force re-harden this VM"
    echo "  7) Restore config from backup"
    echo "  8) Emergency restart all services"
    echo "  9) Status snapshot"
    echo "  0) Exit"
    echo ""
    read -rp "Choice: " CHOICE
    case "$CHOICE" in
        1) kill_suspicious_connections ;;
        2) kill_reverse_shells ;;
        3) remove_web_shells ;;
        4) purge_ssh_keys ;;
        5) purge_cron ;;
        6) re_harden ;;
        7) restore_config ;;
        8) restart_all_services ;;
        9) status_snapshot ;;
        0) echo "Exiting."; break ;;
        *) echo "Invalid." ;;
    esac
done

echo "[$(date)] === IR Session END ==="
