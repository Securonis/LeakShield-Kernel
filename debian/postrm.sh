#!/bin/bash

# Exit on error
set -e

# Get kernel version
KERNEL_VERSION=$1

# Verify kernel version
if [ -z "$KERNEL_VERSION" ]; then
    echo "Error: Kernel version not provided"
    exit 1
fi

# Stop and disable services
systemctl stop pcp.service 2>/dev/null || true
systemctl stop memoryleakguard.service 2>/dev/null || true
systemctl stop privacyguard.service 2>/dev/null || true
systemctl disable pcp.service 2>/dev/null || true
systemctl disable memoryleakguard.service 2>/dev/null || true
systemctl disable privacyguard.service 2>/dev/null || true

# Remove module configuration
rm -f /etc/modules-load.d/leakshield.conf

# Clean up log files (but keep the directory)
find /var/log/leakshield -type f -name "*.log" -delete

# Remove configuration files if purging
if [ "$2" = "purge" ]; then
    rm -rf /etc/leakshield
    rm -rf /var/log/leakshield
fi

# Rebuild initramfs without our modules
update-initramfs -u -k "$KERNEL_VERSION"

# Reload systemd
systemctl daemon-reload

exit 0 