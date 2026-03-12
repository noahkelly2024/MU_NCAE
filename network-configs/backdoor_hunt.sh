#!/usr/bin/env bash
# =============================================================================
# NCAE Cyber Games 2026 — backdoor_hunt.sh
# Team Messiah | Full persistence/backdoor sweep
#
# Covers: cron, systemd, PAM, SUID, SSH keys, shell profiles, rc.local,
#         motd, LD_PRELOAD, kernel modules, /tmp/dev/shm, web shells,
#         suspicious files in /root, bind/reverse shells, alias backdoors
#
# Run as root on every VM at competition start and after any red team activity.
# Safe to re-run. Output logged to /var/log/ncae_backdoor_hunt.log
# =============================================================================
set -uo pipefail

LOG="/vagrant/logs/ncae_backdoor_hunt.log"
FINDINGS=0
mkdir -p /vagrant/logs
exec > >(tee -a "$LOG") 2>&1

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

flag()  { echo -e "${RED}[!] SUSPICIOUS: $1${NC}"; FINDINGS=$((FINDINGS+1)); }
warn()  { echo -e "${YEL}[?] REVIEW:     $1${NC}"; }
ok()    { echo -e "${GRN}[+] CLEAN:      $1${NC}"; }
head()  { echo -e "\n========== $1 =========="; }

echo "======================================================"
echo " NCAE Backdoor Hunt — $(date)"
echo " Host: $(hostname) | $(id)"
echo "======================================================"

# ── 1. ROOT FILES ─────────────────────────────────────────────────────────────
head "ROOT HOME FILES"
echo "[*] Files in /root modified in last 7 days:"
find /root -maxdepth 3 -type f -newer /root/.bashrc 2>/dev/null \
  | grep -v -E '\.(log|hist)$' \
  | while read -r f; do
      warn "$f  (mtime: $(stat -c '%y' "$f" 2>/dev/null))"
    done

echo "[*] Checking /root/.ssh/authorized_keys:"
if [[ -f /root/.ssh/authorized_keys ]]; then
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        comment=$(echo "$line" | awk '{print $NF}')
        warn "Key found → $comment"
        # Forced-command check on root keys specifically
        if echo "$line" | grep -qE '^command='; then
            flag "FORCED-COMMAND on root key → $comment (reverse shell risk)"
        fi
    done < /root/.ssh/authorized_keys
else
    ok "No /root authorized_keys"
fi

# ── 2. ALL USER AUTHORIZED_KEYS ───────────────────────────────────────────────
head "SSH AUTHORIZED_KEYS — ALL USERS"
while IFS=: read -r user _ uid _ _ homedir _; do
    [[ $uid -lt 500 && $uid -ne 0 ]] && continue
    keyfile="$homedir/.ssh/authorized_keys"
    [[ ! -f "$keyfile" ]] && continue
    count=$(grep -vc '^\s*#\|^\s*$' "$keyfile" 2>/dev/null || true)
    warn "User $user has $count key(s) in $keyfile"
    grep -v '^\s*#\|^\s*$' "$keyfile" | awk '{print "  KEY:", $NF}'
    # Check for forced-command keys — these execute arbitrary commands on SSH connect
    # regardless of what the client requests. Pattern: command="..." ssh-rsa AAAA...
    # Red teams use this to plant persistent reverse shells that fire on every SSH login
    # even after the backdoor process is killed, as long as the key stays in the file.
    if grep -qE '^command=' "$keyfile" 2>/dev/null; then
        flag "FORCED-COMMAND key in $keyfile — executes arbitrary command on SSH connect"
        grep -nE '^command=' "$keyfile" | sed 's/^/  /'
    fi
done < /etc/passwd

# ── 3. CRON JOBS ──────────────────────────────────────────────────────────────
head "CRON JOBS"

echo "[*] /etc/crontab:"
if grep -vE '^\s*#|^\s*$' /etc/crontab 2>/dev/null | grep -v 'run-parts\|anacron'; then
    flag "Non-standard entries in /etc/crontab (see above)"
else
    ok "/etc/crontab looks standard"
fi

echo "[*] /etc/cron.d/ entries:"
for f in /etc/cron.d/*; do
    [[ ! -f "$f" ]] && continue
    suspicious=$(grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | grep -vE 'run-parts|0anacron' || true)
    if [[ -n "$suspicious" ]]; then
        flag "$f contains: $suspicious"
    fi
done

echo "[*] User crontabs:"
while IFS= read -r user; do
    ctab=$(crontab -u "$user" -l 2>/dev/null | grep -vE '^\s*#|^\s*$' || true)
    if [[ -n "$ctab" ]]; then
        flag "Crontab for $user: $ctab"
    fi
done < <(cut -d: -f1 /etc/passwd)

echo "[*] /etc/cron.{hourly,daily,weekly,monthly} executables:"
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    find "$dir" -type f -executable 2>/dev/null | while read -r f; do
        warn "$f (verify it's legitimate)"
    done
done

# ── 4. SYSTEMD SERVICES & TIMERS ─────────────────────────────────────────────
head "SYSTEMD — SUSPICIOUS SERVICES & TIMERS"

echo "[*] Services added/modified in last 7 days:"
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
     -type f -name '*.service' -newer /etc/hostname 2>/dev/null \
  | while read -r f; do
      flag "Recently modified service: $f"
      grep -E 'ExecStart|ExecStartPre|ExecStop' "$f" | sed 's/^/    /'
    done

echo "[*] Active timers (look for unexpected ones):"
systemctl list-timers --all 2>/dev/null | grep -v 'ACTIVATES\|---\|^$' \
  | awk '{print "  " $0}' \
  | grep -vE 'apt|dpkg|fwupd|systemd|logrotate|man-db|shadow|mlocate|e2scrub|phpsessionclean|motd|sysstat' \
  | while read -r line; do warn "$line"; done

echo "[*] Services with /tmp or /dev/shm in ExecStart:"
grep -rl 'ExecStart.*\(/tmp\|/dev/shm\|/var/tmp\)' \
    /etc/systemd/system /lib/systemd/system 2>/dev/null \
  | while read -r f; do flag "Service executes from temp path: $f"; done

echo "[*] Systemd drop-in override directories (ExecStartPre / ExecStart injection):"
# Drop-in overrides live in /etc/systemd/system/<service>.service.d/override.conf
# Red teams use these to inject ExecStartPre commands that run before the real service starts
# without modifying the main .service file — so file-mtime checks on the main unit miss it
find /etc/systemd/system -type d -name '*.service.d' 2>/dev/null | while read -r dropdir; do
    find "$dropdir" -type f -name '*.conf' 2>/dev/null | while read -r override; do
        warn "Drop-in found: $override"
        # Flag if the override contains executable directives
        if grep -qE '^\s*(ExecStart|ExecStartPre|ExecStop|ExecStopPost|ExecReload)\s*=' "$override" 2>/dev/null; then
            flag "Drop-in $override modifies exec chain:"
            grep -E '^\s*(ExecStart|ExecStartPre|ExecStop|ExecStopPost|ExecReload)\s*=' "$override" | sed 's/^/  /'
        fi
    done
done

# ── 5. PAM MODULES ────────────────────────────────────────────────────────────
head "PAM MODULE INTEGRITY"

PAM_SO=$(find /lib/security /lib/x86_64-linux-gnu/security \
              /lib64/security /usr/lib/security \
              -name 'pam_unix.so' 2>/dev/null | head -1)

if [[ -n "$PAM_SO" ]]; then
    echo "[*] Checking pam_unix.so for hardcoded passwords:"
    if strings "$PAM_SO" 2>/dev/null | grep -qiE '(password|pass|secret|backdoor|ncae|hack)'; then
        flag "Suspicious strings in pam_unix.so — may be patched PAM backdoor"
        strings "$PAM_SO" | grep -iE '(password|pass|secret|backdoor|ncae|hack)' | head -10 | sed 's/^/  /'
    else
        ok "pam_unix.so strings look clean"
    fi
else
    warn "Could not locate pam_unix.so"
fi

echo "[*] Checking for pam_exec entries (can run arbitrary scripts on auth):"
if grep -rE 'pam_exec' /etc/pam.d/ 2>/dev/null; then
    flag "pam_exec found in PAM config — verify script is legitimate"
else
    ok "No pam_exec in /etc/pam.d/"
fi

echo "[*] /etc/pam.d/ files modified recently:"
find /etc/pam.d -newer /etc/hostname -type f 2>/dev/null \
  | while read -r f; do flag "Recently modified PAM config: $f"; done

# ── 5b. LINUX CAPABILITIES ────────────────────────────────────────────────────
head "LINUX CAPABILITIES (cap_setuid / cap_dac_override)"

echo "[*] Scanning all files for elevated capabilities:"
if command -v getcap &>/dev/null; then
    # getcap -r / recursively scans the entire filesystem for capability-enabled binaries
    # Capabilities are a red team favorite for priv esc because they bypass SUID detection:
    # a binary with cap_setuid+ep can set UID to 0 without the SUID bit being set
    # Common dangerous caps:
    #   cap_setuid    - can change UID to root
    #   cap_dac_override - bypass file read/write/execute permission checks
    #   cap_sys_admin - broad system administration (nearly equivalent to root)
    #   cap_net_raw   - raw socket access (packet sniffing)
    DANGEROUS_CAPS="cap_setuid|cap_dac_override|cap_sys_admin|cap_net_raw|cap_chown|cap_fowner"
    CAP_OUTPUT=$(getcap -r / 2>/dev/null)
    if [[ -n "$CAP_OUTPUT" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -qE "$DANGEROUS_CAPS"; then
                flag "DANGEROUS CAPABILITY: $line"
            else
                warn "Capability set: $line"
            fi
        done <<< "$CAP_OUTPUT"
    else
        ok "No capability-enabled binaries found"
    fi
else
    warn "getcap not available (install libcap2-bin on Ubuntu / libcap on Rocky)"
fi

# ── 6. SUID / SGID BINARIES ───────────────────────────────────────────────────
head "SUID/SGID BINARIES"

echo "[*] All SUID binaries (review for unexpected entries):"
KNOWN_SUID=(
    /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/newgrp
    /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/mount
    /usr/bin/umount /usr/bin/pkexec /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper /bin/su /bin/mount
    /bin/umount /usr/sbin/pam_extrausers_chkpwd
    /usr/lib/policykit-1/polkit-agent-helper-1
    /usr/bin/at /usr/bin/crontab /usr/bin/ssh-agent
    /usr/libexec/openssh/ssh-keysign
)

while IFS= read -r -d '' f; do
    known=0
    for k in "${KNOWN_SUID[@]}"; do
        [[ "$f" == "$k" ]] && { known=1; break; }
    done
    if [[ $known -eq 0 ]]; then
        flag "Unexpected SUID binary: $f  ($(stat -c '%U %G %a' "$f"))"
    fi
done < <(find / -xdev -type f -perm /4000 -print0 2>/dev/null)

# ── 7. SHELL PROFILES & STARTUP FILES ────────────────────────────────────────
head "SHELL STARTUP FILE BACKDOORS"

PROFILE_FILES=(
    /etc/profile
    /etc/bash.bashrc
    /etc/environment
    /etc/profile.d/*.sh
)

echo "[*] Checking global profiles for reverse shell indicators:"
for f in "${PROFILE_FILES[@]}"; do
    for match in $f; do
        [[ ! -f "$match" ]] && continue
        if grep -qE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|php.*socket|/tmp/|/dev/shm/)' "$match" 2>/dev/null; then
            flag "Suspicious content in $match"
            grep -nE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|php.*socket|/tmp/|/dev/shm/)' "$match" | sed 's/^/  /'
        fi
    done
done

echo "[*] User .bashrc / .profile backdoors:"
while IFS=: read -r user _ uid _ _ homedir _; do
    [[ $uid -lt 500 && $uid -ne 0 ]] && continue
    for dotfile in "$homedir/.bashrc" "$homedir/.profile" "$homedir/.bash_profile" "$homedir/.zshrc"; do
        [[ ! -f "$dotfile" ]] && continue
        if grep -qE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|alias sudo|/tmp/|/dev/shm/)' "$dotfile" 2>/dev/null; then
            flag "Suspicious content in $dotfile"
            grep -nE '(/dev/tcp|nc |ncat |bash -i|python.*socket|perl.*socket|alias sudo|/tmp/|/dev/shm/)' "$dotfile" | sed 's/^/  /'
        fi
    done
done < /etc/passwd

# ── 8. RC.LOCAL & MOTD ────────────────────────────────────────────────────────
head "RC.LOCAL AND MOTD"

if [[ -f /etc/rc.local ]]; then
    content=$(grep -vE '^\s*#|^\s*$|^exit' /etc/rc.local 2>/dev/null || true)
    if [[ -n "$content" ]]; then
        flag "/etc/rc.local has active content: $content"
    else
        ok "/etc/rc.local is empty/default"
    fi
fi

echo "[*] /etc/update-motd.d/ executables:"
find /etc/update-motd.d -type f -executable 2>/dev/null | while read -r f; do
    if grep -qE '(/dev/tcp|nc |bash -i|/tmp/|/dev/shm/)' "$f" 2>/dev/null; then
        flag "Malicious MOTD script: $f"
    else
        warn "MOTD script (verify): $f"
    fi
done

# ── 9. LD_PRELOAD HOOKS ────────────────────────────────────────────────────────
head "LD_PRELOAD / LIBRARY HOOKS"

if [[ -f /etc/ld.so.preload ]]; then
    content=$(cat /etc/ld.so.preload 2>/dev/null)
    if [[ -n "$content" ]]; then
        flag "/etc/ld.so.preload is set: $content"
    fi
else
    ok "/etc/ld.so.preload not present"
fi

echo "[*] Checking LD_PRELOAD in systemd service files:"
grep -rl 'LD_PRELOAD' /etc/systemd/system /lib/systemd/system 2>/dev/null \
  | while read -r f; do flag "LD_PRELOAD in service: $f"; done

# ── 10. SUSPICIOUS FILES IN TEMP LOCATIONS ───────────────────────────────────
head "SUSPICIOUS FILES IN /tmp /var/tmp /dev/shm"

for tmpdir in /tmp /var/tmp /dev/shm; do
    echo "[*] Executables in $tmpdir:"
    find "$tmpdir" -type f -executable 2>/dev/null | while read -r f; do
        flag "Executable in $tmpdir: $f"
    done
    echo "[*] Hidden files in $tmpdir:"
    find "$tmpdir" -name '.*' 2>/dev/null | while read -r f; do
        flag "Hidden file: $f"
    done
done

# ── 11. KERNEL MODULES ────────────────────────────────────────────────────────
head "KERNEL MODULES (ROOTKIT CHECK)"

echo "[*] Non-standard kernel modules:"
lsmod 2>/dev/null | tail -n +2 | awk '{print $1}' | while read -r mod; do
    modpath=$(modinfo "$mod" 2>/dev/null | grep '^filename' | awk '{print $2}')
    if [[ -n "$modpath" ]] && echo "$modpath" | grep -qvE '^/lib/modules|^/usr/lib/modules|(builtin)'; then
        flag "Module loaded from unusual path: $mod → $modpath"
    fi
done | sort -u

# ── 12. ACTIVE NETWORK CONNECTIONS (BIND/REVERSE SHELLS) ─────────────────────
head "SUSPICIOUS NETWORK CONNECTIONS"

echo "[*] Listening on unexpected ports (not 22/80/443/53/21/3306/5432/445/139):"
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4, $6}' | while read -r addr proc; do
    port=$(echo "$addr" | awk -F: '{print $NF}')
    if ! echo "22 80 443 53 21 3306 5432 445 139 3389" | grep -qw "$port"; then
        flag "Unexpected listener on port $port  [$proc]"
    fi
done

echo "[*] Established outbound connections to non-RFC1918 addresses:"
ss -tnp 2>/dev/null | grep ESTAB | while read -r line; do
    remote=$(echo "$line" | awk '{print $5}')
    ip=$(echo "$remote" | cut -d: -f1)
    if ! echo "$ip" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)'; then
        flag "Outbound connection to external IP: $line"
    fi
done

# ── 13. WEB SHELLS ────────────────────────────────────────────────────────────
head "WEB SHELL DETECTION"

echo "[*] Scanning /var/www for common web shell indicators:"
find /var/www -type f \( -name '*.php' -o -name '*.py' -o -name '*.pl' -o -name '*.sh' \) 2>/dev/null \
  | while read -r f; do
      # shellcheck disable=SC2016  # $_ vars are grep regex literals, not bash expansions
      if grep -qilE '(eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec|exec\s*\(|popen|proc_open|\$_REQUEST|\$_GET|\$_POST.*eval)' "$f" 2>/dev/null; then
          flag "Possible web shell: $f"
          grep -niE '(eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec)' "$f" | head -3 | sed 's/^/  /'
      fi
    done

# ── 14. PASSWD/SHADOW — UID 0 AND EXTRA SUDO ─────────────────────────────────
head "PASSWD / SUDO PRIVILEGE ESCALATION"

echo "[*] All UID 0 accounts:"
awk -F: '($3 == 0) {print $1}' /etc/passwd | while read -r u; do
    if [[ "$u" != "root" ]]; then
        flag "Non-root UID 0 account: $u"
    else
        ok "root UID 0 — expected"
    fi
done

echo "[*] Users in sudo/wheel group:"
getent group sudo wheel 2>/dev/null | while read -r line; do
    warn "$line"
done

echo "[*] /etc/sudoers NOPASSWD entries:"
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r line; do
    flag "NOPASSWD sudo: $line"
done

# ── 15. RECENTLY MODIFIED SYSTEM BINARIES ─────────────────────────────────────
head "RECENTLY MODIFIED SYSTEM BINARIES"

echo "[*] System binaries modified in last 3 days (possible binary replacement):"
find /usr/bin /usr/sbin /bin /sbin -type f -newer /etc/hostname 2>/dev/null \
  | while read -r f; do
      flag "Modified system binary: $f  ($(stat -c 'mtime: %y size: %s' "$f"))"
    done

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
if [[ $FINDINGS -gt 0 ]]; then
    echo -e "${RED} HUNT COMPLETE — $FINDINGS FINDING(S) REQUIRE ATTENTION${NC}"
    echo " Full log: $LOG"
else
    echo -e "${GRN} HUNT COMPLETE — No suspicious indicators found${NC}"
fi
echo "======================================================"
