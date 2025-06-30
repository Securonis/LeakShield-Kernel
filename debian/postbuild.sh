#!/bin/bash

# Get kernel version
KERNEL_VERSION=$1

# Verify modules were built
for module in pcp memoryleakguard privacyguard; do
    if [ ! -f "/var/lib/dkms/${PACKAGE_NAME}/${PACKAGE_VERSION}/${KERNEL_VERSION}/x86_64/${module}.ko" ]; then
        echo "Error: Module $module not built correctly"
        exit 1
    fi
done

exit 0 