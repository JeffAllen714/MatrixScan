# MatrixScan

MatrixScan is a comprehensive Linux privilege escalation checker with a Matrix-inspired theme. It systematically analyzes your system for potential privilege escalation vectors, security misconfigurations, and vulnerabilities that could be exploited to gain higher privileges. Unlike other security tools, MatrixScan presents its findings within the metaphor of "The Matrix," making security assessments more engaging while remaining thorough and professional.

## Features

- **Comprehensive Analysis**: Performs over 200 individual security checks across 15 categories
- **Matrix-Themed Output**: Engaging feedback with references to "The Matrix" movie
- **Detailed Reporting**: Generates complete reports with findings and recommendations
- **Red Pill Mode**: Verbose output option that shows "how deep the rabbit hole goes"
- **Color-Coded Results**: Easy identification of security issues by severity
- **Lightweight**: No dependencies beyond standard Linux utilities
- **CTF-Focused**: Especially useful for Capture The Flag competitions and security exercises

## Security Checks

MatrixScan performs checks in the following areas:

- System information (kernel, OS versions, environment variables)
- User privileges and group memberships
- Mounted and unmounted drives
- Installed software and vulnerable versions
- Network configuration and open ports
- Running processes and their privileges
- File and folder permissions (SUID, SGID, world-writable)
- Scheduled tasks (cron jobs, systemd timers)
- Systemd services and socket configurations
- Sudo permissions and misconfigurations
- Capabilities and ACLs
- Open shell sessions (screen, tmux)
- SSH keys and configurations
- Sensitive files and potential password stores
- Special exploits (NFS, restricted shells, etc.)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/MatrixScan.git

# Navigate to the directory
cd MatrixScan

# Make the script executable
chmod +x MatrixScan.sh

# Run it!
./MatrixScan.sh
```

## Usage

### Basic Scan
```bash
./MatrixScan.sh
```

### Red Pill (Verbose Output)
```bash
./MatrixScan.sh --redpill
# or
./MatrixScan.sh -r
```

### Custom Output File
```bash
./MatrixScan.sh --output custom_report.txt
# or
./MatrixScan.sh -o custom_report.txt
```

### Help Menu
```bash
./MatrixScan.sh --help
# or
./MatrixScan.sh -h
```

## Understanding the Output

MatrixScan organizes its findings into several categories:

- **Matrix Core (System Information)**: Basic system details and kernel information
- **Matrix Constructs (Drives and Mounts)**: Information about filesystems
- **Matrix Programs (Installed Software)**: Analysis of installed applications
- **Matrix Connection Pathways (Network)**: Network configurations and services
- **Matrix Identities (User Information)**: User accounts and privileges
- **Matrix Access Controls (Permissions)**: File and folder permission issues
- **Matrix Anomalies (Vulnerabilities)**: Detected security issues
- **Ways to Break Free (Privilege Escalation Paths)**: Potential vectors for escalation

Each finding is marked with one of these labels:

- `[INFO]`: General information
- `[WARNING]`: Potential security concerns
- `[ANOMALY]`: Confirmed vulnerabilities
- `[SECTION]`: Section headers
- `[SUBSECTION]`: Subsection headers

## Common Privilege Escalation Paths

MatrixScan specifically checks for these privilege escalation vectors:

1. **Kernel Exploits**: DirtyCow, overlayfs, and other kernel vulnerabilities
2. **Sudo Misconfigurations**: NOPASSWD options, sudo token reuse
3. **SUID Binaries**: Exploitable setuid executables
4. **Writable Files**: Critical system files with unsafe permissions
5. **Cron Jobs**: Exploitable scheduled tasks
6. **Capabilities**: Binaries with dangerous capabilities
7. **Group Memberships**: Membership in privileged groups like docker, sudo
8. **NFS Shares**: no_root_squash misconfigurations
9. **Passwords in Files**: Credentials stored in config files
10. **Environment Variables**: LD_PRELOAD and other variable exploits
11. **Service Exploits**: Vulnerable services running with elevated privileges
12. **Python Library Hijacking**: Writable Python libraries
13. **Log Files Exploitation**: Log poisoning attacks

## Contributing & License

Contributions are welcome! Please feel free to submit a Pull Request.


This project is licensed under the MIT License


"I can only show you the door. You're the one that has to walk through it."
