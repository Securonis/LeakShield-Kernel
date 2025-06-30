# LeakShield - Advanced Kernel Security Suite

---------------------
# WARNING

**LeakShield Kernel** is currently under development and has not been fully tested.  
Using it without advanced knowledge may cause kernel instability, system crashes, or data loss.  
Proceed with caution and only use if you understand the risks involved.

--------------------

A comprehensive kernel security suite for Debian systems that provides enterprise-grade security and privacy features. LeakShield is designed to protect your system against various security threats while maintaining optimal performance.

## Maintainer
- **Name**: root0emir
- **Contact**: root0emir@protonmail.com

## Overview

LeakShield integrates multiple security modules that work together to provide a robust security framework for your Linux kernel. Each module is designed to address specific security concerns while maintaining system stability.

## Core Modules

### Process Credential Protection (PCP)
The PCP module provides real-time protection against process credential manipulation and privilege escalation attacks.

#### Features:
- Red-black tree implementation for efficient process tracking
- Real-time credential verification
- Protection against unauthorized privilege escalation
- Minimal performance overhead
- Comprehensive audit logging

#### Technical Details:
- Uses kernel's RB-tree implementation
- Hooks into process creation and credential modification paths
- Maintains separate security context for each process

### Memory Leak Detection (MemoryLeakGuard)
MemoryLeakGuard provides comprehensive memory leak detection and prevention capabilities.

#### Features:
- Real-time memory leak detection
- Stack trace recording for memory allocations
- Detailed memory access pattern analysis
- Integration with kernel's memory management subsystem

#### Technical Details:
- Uses kretprobes for kmalloc/kfree tracking
- Maintains allocation history with stack traces
- Periodic memory usage analysis
- Configurable memory thresholds

### Privacy Protection (PrivacyGuard)
PrivacyGuard ensures system-wide privacy by controlling information disclosure and protecting sensitive data.

#### Features:
- Granular control over information disclosure
- Protection of sensitive system information
- Privacy-focused memory management
- Configurable privacy policies

#### Technical Details:
- Hooks into system call interface
- Memory sanitization on deallocation
- Protected memory regions for sensitive data
- Policy-based information access control

## Installation

### Prerequisites
- Debian-based Linux distribution
- Linux kernel version 5.x or 6.x
- DKMS (Dynamic Kernel Module Support)
- build-essential package
- Root access

### Step-by-Step Installation

1. Install required dependencies:
```bash
sudo apt-get update
sudo apt-get install build-essential dkms
```

2. Install LeakShield package:
```bash
sudo dpkg -i leakshield_1.0_amd64.deb
```

3. Verify installation:
```bash
dkms status
```

## Module Management

### Systemd Service Control
Each module can be independently managed using systemd:

#### PCP Module
```bash
# Start PCP service
sudo systemctl start pcp
# Enable PCP service at boot
sudo systemctl enable pcp
# Check PCP status
sudo systemctl status pcp
```

#### MemoryLeakGuard Module
```bash
# Start MemoryLeakGuard service
sudo systemctl start memoryleakguard
# Enable MemoryLeakGuard service at boot
sudo systemctl enable memoryleakguard
# Check MemoryLeakGuard status
sudo systemctl status memoryleakguard
```

#### PrivacyGuard Module
```bash
# Start PrivacyGuard service
sudo systemctl start privacyguard
# Enable PrivacyGuard service at boot
sudo systemctl enable privacyguard
# Check PrivacyGuard status
sudo systemctl status privacyguard
```

## Configuration

Each module has its own configuration file located in `/etc/leakshield/`:
- PCP: `/etc/leakshield/pcp.conf`
- MemoryLeakGuard: `/etc/leakshield/memoryleakguard.conf`
- PrivacyGuard: `/etc/leakshield/privacyguard.conf`

### Sample Configurations

#### PCP Configuration
```conf
# Process Credential Protection configuration
LOG_LEVEL=INFO
AUDIT_MODE=1
MAX_PROCESSES=10000
CREDENTIAL_CHECK_INTERVAL=1000
```

#### MemoryLeakGuard Configuration
```conf
# Memory Leak Guard configuration
DETECTION_THRESHOLD=1024
STACK_TRACE_DEPTH=10
SCAN_INTERVAL=60
REPORT_PATH=/var/log/leakshield/memoryleaks.log
```

#### PrivacyGuard Configuration
```conf
# Privacy Guard configuration
PRIVACY_LEVEL=HIGH
SANITIZE_MEMORY=1
PROTECT_PROC=1
AUDIT_ACCESS=1
```

## Troubleshooting

### Common Issues

1. Module Loading Failures
   - Check kernel version compatibility
   - Verify DKMS installation
   - Review system logs: `journalctl -xe`

2. Performance Impact
   - Adjust configuration parameters
   - Monitor system resources
   - Use selective module enabling

3. Log Analysis
   - All logs are stored in `/var/log/leakshield/`
   - Use `journalctl -u [service-name]` for service-specific logs

## Security Considerations

- All modules require root privileges
- Regular security audits recommended
- Keep the system and modules updated
- Monitor system logs for security events

## Contributing

We welcome contributions! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

LeakShield is licensed under the GNU General Public License v3.0 (GPL-3.0).
See the LICENSE file for more details.

## Support

For bug reports and feature requests, please contact the maintainer:
- Email: root0emir@protonmail.com

## Building and Packaging

### Prerequisites for Building
- Debian/Ubuntu build environment
- Build tools: `build-essential`, `dkms`, `debhelper`, `devscripts`
- Kernel headers for your target kernel version
- Git (for version control)

### Installing Build Dependencies
```bash
# Install required build tools
sudo apt-get update
sudo apt-get install build-essential dkms debhelper devscripts \
    linux-headers-$(uname -r) git fakeroot dpkg-dev

# For cross-compilation (optional)
sudo apt-get install crossbuild-essential-amd64  # For amd64
sudo apt-get install crossbuild-essential-arm64  # For arm64
```

### Building the Package
1. Clone the repository:
```bash
git clone https://github.com/Securonis/leakshield.git
cd leakshield
```

2. Create source package:
```bash
# Update changelog if needed
dch -i "New release version"

# Create source package
dpkg-buildpackage -S -us -uc
```

3. Build binary package:
```bash
# For current architecture
dpkg-buildpackage -b -us -uc

# For specific architecture (example: arm64)
dpkg-buildpackage -b -us -uc -aarm64
```

4. Build DKMS package:
```bash
# Create DKMS tarball
make -f debian/rules dkms-pkg

# Build DKMS package
dpkg-buildpackage -b -us -uc
```

### Package Structure
```
leakshield_1.0_amd64.deb
├── DEBIAN/
│   ├── control
│   ├── postinst
│   ├── postrm
│   └── prerm
├── etc/
│   ├── leakshield/
│   │   ├── pcp.conf
│   │   ├── memoryleakguard.conf
│   │   └── privacyguard.conf
│   └── modules-load.d/
│       └── leakshield.conf
├── lib/
│   └── systemd/
│       └── system/
│           ├── pcp.service
│           ├── memoryleakguard.service
│           └── privacyguard.service
└── usr/
    ├── share/
    │   └── leakshield/
    │       └── default/
    │           ├── pcp.conf
    │           ├── memoryleakguard.conf
    │           └── privacyguard.conf
    └── src/
        └── leakshield/
            ├── pcp.c
            ├── memoryleakguard.c
            └── privacyguard.c
```

### Verifying the Package
After building, verify the package integrity:

```bash
# Check package contents
dpkg -c leakshield_1.0_amd64.deb

# Verify package metadata
dpkg -I leakshield_1.0_amd64.deb

# Validate package dependencies
lintian leakshield_1.0_amd64.deb
```

### Multi-Architecture Support
LeakShield supports building for multiple architectures:

```bash
# For amd64 (x86_64)
DEB_BUILD_OPTIONS="parallel=$(nproc)" dpkg-buildpackage -b -us -uc -aamd64

# For arm64 (aarch64)
DEB_BUILD_OPTIONS="parallel=$(nproc)" dpkg-buildpackage -b -us -uc -aarm64

# For armhf
DEB_BUILD_OPTIONS="parallel=$(nproc)" dpkg-buildpackage -b -us -uc -aarmhf
```

### Repository Integration
To add the package to a Debian repository:

1. Sign the package (if you have a GPG key):
```bash
dpkg-sig --sign builder leakshield_1.0_amd64.deb
```

2. Add to repository:
```bash
# Add to local repo
reprepro -b /path/to/repo includedeb stable leakshield_1.0_amd64.deb

# Or use dput for remote repositories
dput ppa:root0emir/leakshield leakshield_1.0_amd64.changes
```

### Troubleshooting Package Build
Common issues and solutions:

1. Missing dependencies:
```bash
# Install all build dependencies
mk-build-deps -i debian/control
```

2. DKMS build failures:
```bash
# Check DKMS status
dkms status

# View build logs
cat /var/lib/dkms/leakshield/1.0/build/make.log
```

3. Lintian warnings:
```bash
# Run detailed lintian checks
lintian -i -I --show-overrides leakshield_1.0_amd64.changes
``` 