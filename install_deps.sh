#!/bin/bash
# install_deps.sh - Install common utilities
# Usage: sudo ./install_deps.sh

apt-get update -qq

PACKAGES=(
    curl wget git vim
    ufw fail2ban
    auditd
    net-tools
)

for pkg in "${PACKAGES[@]}"; do
    apt-get install -y "$pkg" && echo "[OK] $pkg" || echo "[FAIL] $pkg"
done
