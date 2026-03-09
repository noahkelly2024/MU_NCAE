#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 - monitor.sh
# Continuous monitoring for suspicious activity
# Run in tmux: sudo tmux new -s ncae_monitor "bash monitor.sh"
# =============================================================================

ALERT_LOG="/var/log/ncae_alerts.log"
touch "$ALERT_LOG" && chmod 600 "$ALERT_LOG"

log_alert() {
    echo "[$(date)] ALERT: $*" | tee -a "$ALERT_LOG"
}

echo "[$(date)] === NCAE Monitor Started ===" >> "$ALERT_LOG"

# Create baselines on first run
if [ ! -f "/tmp/suid_baseline.txt" ]; then
    find / -type f -perm -4000 2>/dev/null | sort > /tmp/suid_baseline.txt
    log_alert "SUID baseline created"
fi

if [ -d "/var/www/html" ] && [ ! -f "/tmp/web_baseline.txt" ]; then
    find /var/www/html -type f -exec sha256sum {} \; 2>/dev/null | sort > /tmp/web_baseline.txt
    log_alert "Web root baseline created"
fi

if [ ! -f "/tmp/cron_baseline.txt" ]; then
    ls -la /etc/cron.* 2>/dev/null > /tmp/cron_baseline.txt
    crontab -l 2>/dev/null >> /tmp/cron_baseline.txt
    log_alert "Cron baseline created"
fi

# Detect scored services
SERVICES=()
systemctl is-active --quiet apache2 && SERVICES+=("apache2")
systemctl is-active --quiet nginx && SERVICES+=("nginx")
systemctl is-active --quiet named && SERVICES+=("named")
systemctl is-active --quiet postgresql && SERVICES+=("postgresql")
systemctl is-active --quiet smb && SERVICES+=("smb")
systemctl is-active --quiet nmb && SERVICES+=("nmb")
systemctl is-active --quiet sshd && SERVICES+=("sshd")
systemctl is-active --quiet ssh && SERVICES+=("ssh")

echo "[*] Monitoring services: ${SERVICES[*]}"

# Main monitoring loop
COUNTER=0
while true; do
    ((COUNTER++))
    
    # Check services every loop (1 sec)
    for SVC in "${SERVICES[@]}"; do
        if ! systemctl is-active --quiet "$SVC"; then
            log_alert "$SVC is DOWN - attempting restart"
            systemctl restart "$SVC" 2>&1 | tee -a "$ALERT_LOG"
            if systemctl is-active --quiet "$SVC"; then
                log_alert "$SVC restarted successfully"
            else
                log_alert "$SVC FAILED TO RESTART - manual intervention required"
            fi
        fi
    done
    
    # Check for new SUID binaries (every 10 min = 600 sec)
    if [ $((COUNTER % 600)) -eq 0 ]; then
        find / -type f -perm -4000 2>/dev/null | sort > /tmp/suid_current.txt
        if ! diff -q /tmp/suid_baseline.txt /tmp/suid_current.txt &>/dev/null; then
            log_alert "NEW SUID BINARY DETECTED:"
            comm -13 /tmp/suid_baseline.txt /tmp/suid_current.txt | tee -a "$ALERT_LOG"
        fi
    fi
    
    # Check web root integrity (every 5 min = 300 sec)
    if [ -f "/tmp/web_baseline.txt" ] && [ $((COUNTER % 300)) -eq 0 ]; then
        find /var/www/html -type f -exec sha256sum {} \; 2>/dev/null | sort > /tmp/web_current.txt
        if ! diff -q /tmp/web_baseline.txt /tmp/web_current.txt &>/dev/null; then
            log_alert "WEB CONTENT MODIFIED:"
            diff /tmp/web_baseline.txt /tmp/web_current.txt | grep '^[<>]' | head -20 | tee -a "$ALERT_LOG"
        fi
    fi
    
    # Check for suspicious connections (every 30 sec)
    if [ $((COUNTER % 30)) -eq 0 ]; then
        # Flag connections NOT from scoring subnets (not 172.18.x, 192.168.x, 127.x, 10.0.2.x VirtualBox NAT)
        SUSPICIOUS=$(ss -tunp state established 2>/dev/null | grep -v 'State\|127.0.0.1\|127.0.0.0\|::1' | grep -v -E '172\.18\.|192\.168\.|10\.0\.2\.')
        if [ -n "$SUSPICIOUS" ]; then
            log_alert "SUSPICIOUS CONNECTION (not from scoring subnet):"
            echo "$SUSPICIOUS" | tee -a "$ALERT_LOG"
        fi
    fi
    
    # Check for new cron jobs (every 5 min = 300 sec)
    if [ $((COUNTER % 300)) -eq 0 ]; then
        ls -la /etc/cron.* 2>/dev/null > /tmp/cron_current.txt
        crontab -l 2>/dev/null >> /tmp/cron_current.txt
        if ! diff -q /tmp/cron_baseline.txt /tmp/cron_current.txt &>/dev/null; then
            log_alert "NEW CRON JOB DETECTED:"
            diff /tmp/cron_baseline.txt /tmp/cron_current.txt | grep '^[<>]' | tee -a "$ALERT_LOG"
        fi
    fi
    
    # Display status dashboard (every 60 sec)
    if [ $((COUNTER % 60)) -eq 0 ]; then
        clear
        echo "╔════════════════════════════════════════════════════════╗"
        echo "║         NCAE Monitor - $(date '+%H:%M:%S')                   ║"
        echo "╚════════════════════════════════════════════════════════╝"
        echo ""
        echo "Services Status:"
        for SVC in "${SERVICES[@]}"; do
            if systemctl is-active --quiet "$SVC"; then
                echo "  ✓ $SVC"
            else
                echo "  ✗ $SVC (DOWN)"
            fi
        done
        echo ""
        echo "Recent Alerts (last 5):"
        tail -5 "$ALERT_LOG" | grep ALERT || echo "  No recent alerts"
        echo ""
        echo "Active Connections:"
        ss -tunp state established 2>/dev/null | grep -c ESTAB | xargs echo "  Total:"
        echo ""
        echo "Disk Usage:"
        df -h / | tail -1 | awk '{print "  "$5" used"}'
        echo ""
        echo "Memory:"
        free -h | awk 'NR==2{print "  "$3"/"$2" used"}'
        echo ""
        echo "Full log: tail -f $ALERT_LOG"
        echo "Detach: Ctrl+B then D"
    fi
    
    sleep 1
done
