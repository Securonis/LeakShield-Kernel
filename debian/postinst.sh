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

# Create modules configuration directory if it doesn't exist
mkdir -p /etc/modules-load.d

# Create modules configuration with new package name
MODULES_CONF="/etc/modules-load.d/leakshield.conf"
echo "# LeakShield kernel modules configuration" > "$MODULES_CONF"
echo "pcp" >> "$MODULES_CONF"
echo "memoryleakguard" >> "$MODULES_CONF"
echo "privacyguard" >> "$MODULES_CONF"

# Create log directory with proper permissions
mkdir -p /var/log/leakshield
chmod 750 /var/log/leakshield

# Verify module files exist
for module in pcp memoryleakguard privacyguard; do
    if [ ! -f "/lib/modules/$KERNEL_VERSION/updates/dkms/leakshield/$module.ko" ]; then
        echo "Warning: Module $module not found for kernel $KERNEL_VERSION"
    fi
done

# Rebuild initramfs for the new kernel
update-initramfs -u -k "$KERNEL_VERSION"

# Reload systemd to recognize new services
systemctl daemon-reload

# Enable services for next boot
systemctl enable pcp.service
systemctl enable memoryleakguard.service
systemctl enable privacyguard.service

# Create default configuration files if they don't exist
for conf in pcp memoryleakguard privacyguard; do
    if [ ! -f "/etc/leakshield/$conf.conf" ]; then
        mkdir -p /etc/leakshield
        cp "/usr/share/leakshield/default/$conf.conf" "/etc/leakshield/$conf.conf"
    fi
done

exit 0 