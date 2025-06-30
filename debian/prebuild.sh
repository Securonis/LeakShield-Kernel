#!/bin/bash

# Get kernel version
KERNEL_VERSION=$1

# Check kernel headers
if [ ! -d "/lib/modules/$KERNEL_VERSION/build" ]; then
    echo "Error: Kernel headers not found for version $KERNEL_VERSION"
    exit 1
fi

# Check build dependencies
if ! dpkg -l | grep -q "^ii.*build-essential"; then
    echo "Error: build-essential package not installed"
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "/var/lib/dkms/${PACKAGE_NAME}/${PACKAGE_VERSION}/build"

exit 0 