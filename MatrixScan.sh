#!/bin/bash

# MatrixScan - A Matrix-themed Linux privilege escalation checker
# "Red pill for your system"

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color
MATRIX_GREEN='\033[38;5;46m'

# Global variables
redPill=false # Verbose mode (red pill shows you how deep the rabbit hole goes)
blueprintFile="matrixscan_report.txt" # Report file (the blueprint of the Matrix)
htmlReport="matrixscan_report.html" # HTML report file
anomalies=() # Found vulnerabilities (anomalies in the Matrix)
searchPatterns=() # Checklist (patterns to search for in the Matrix)
privEscVectors=() # Identified privilege escalation vectors

# Severity levels
CRITICAL="CRITICAL"
HIGH="HIGH"
MEDIUM="MEDIUM"
LOW="LOW"
INFO="INFO"

# Banner function
showBanner() {
    echo -e "${MATRIX_GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                      ║"
    echo "║  ███╗   ███╗ █████╗ ████████╗██████╗ ██╗██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗  ║"
    echo "║  ████╗ ████║██╔══██╗╚══██╔══╝██╔══██╗██║╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║  ║"
    echo "║  ██╔████╔██║███████║   ██║   ██████╔╝██║ ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║  ║"
    echo "║  ██║╚██╔╝██║██╔══██║   ██║   ██╔══██╗██║ ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║  ║"
    echo "║  ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║██║██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║  ║"
    echo "║  ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ║"
    echo "║                                                                      ║"
    echo "║                    \"Red pill for your system\"                        ║"
    echo "║                                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${MATRIX_GREEN}Tool for discovering privilege escalation paths in Linux${NC}"
    echo ""
}

# Usage function - Morpheus explains how to use the tool
morpheusGuide() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help             Show this help message and exit"
    echo "  -r, --redpill          Take the red pill (enable verbose output)"
    echo "  -o, --output FILE      Save the blueprint to specified file (default: matrixscan_report.txt)"
    echo "  --html                 Generate HTML report in addition to text (default: matrixscan_report.html)"
    echo ""
}

# Parse command line arguments
parseArgs() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                morpheusGuide
                exit 0
                ;;
            -r|--redpill)
                redPill=true
                shift
                ;;
            -o|--output)
                blueprintFile="$2"
                shift
                shift
                ;;
            --html)
                generateHtml=true
                if [ ! -z "$2" ] && [[ "$2" != -* ]]; then
                    htmlReport="$2"
                    shift
                fi
                shift
                ;;
            *)
                echo "Unknown option: $1"
                morpheusGuide
                exit 1
                ;;
        esac
    done
}

# Log function for output
logMessage() {
    local level="$1"
    local message="$2"
    local color=""
    
    case $level in
        "INFO")
            color="${GREEN}"
            ;;
        "WARNING")
            color="${YELLOW}"
            ;;
        "ANOMALY")
            color="${RED}"
            ;;
        "SECTION")
            color="${MATRIX_GREEN}"
            ;;
        "SUBSECTION")
            color="${CYAN}"
            ;;
        "CRITICAL")
            color="${RED}${BOLD}"
            ;;
        "HIGH")
            color="${RED}"
            ;;
        "MEDIUM")
            color="${YELLOW}"
            ;;
        "LOW")
            color="${BLUE}"
            ;;
        *)
            color="${WHITE}"
            ;;
    esac
    
    # Print to console
    echo -e "${color}[${level}]${NC} ${message}"
    
    # Add to report file
    echo "[${level}] ${message}" >> "$blueprintFile"
}

# Add to checklist (searching patterns in the Matrix)
addToPattern() {
    local item="$1"
    local status="$2"
    local detail="$3"
    
    searchPatterns+=("${item}|${status}|${detail}")
}

# Add to vulnerabilities (anomalies in the Matrix)
addToAnomalies() {
    local anomaly="$1"
    local detail="$2"
    local severity="$3"
    local vector="$4"
    local remediation="$5"
    
    anomalies+=("${anomaly}|${detail}|${severity}|${vector}|${remediation}")
}

# Add to privilege escalation vectors
addToPrivEscVectors() {
    local vector="$1"
    local description="$2"
    local severity="$3"
    local exploitation="$4"
    
    privEscVectors+=("${vector}|${description}|${severity}|${exploitation}")
}

# Verbose output function (taking the red pill shows you more of the Matrix)
showWithRedPill() {
    local message="$1"
    
    if [ "$redPill" = true ]; then
        echo -e "${PURPLE}[DEEP_MATRIX]${NC} ${message}"
        echo "[DEEP_MATRIX] ${message}" >> "$blueprintFile"
    fi
}

# Run command and get output (interrogating the Matrix)
interrogateMatrix() {
    local cmd="$1"
    local output=""
    
    showWithRedPill "Running command: $cmd"
    output=$(eval "$cmd" 2>/dev/null)
    
    echo "$output"
}

# Check system information (the foundation of the Matrix)
analyzeMatrixCore() {
    logMessage "SECTION" "System Information (Matrix Core)"
    
    # Kernel information
    logMessage "SUBSECTION" "Kernel Information (Matrix Version)"
    kernelInfo=$(interrogateMatrix "uname -a")
    echo "$kernelInfo"
    addToPattern "Kernel Information" "ANALYZED" "$kernelInfo"
    
    # Check for kernel exploits
    kernelVersion=$(uname -r)
    showWithRedPill "Kernel version: $kernelVersion"
    
    # Check for common kernel exploits
    if [[ "$kernelVersion" =~ ^2\.6\. ]]; then
        addToAnomalies "Kernel Exploit" "Kernel version 2.6.x detected, potentially vulnerable to DirtyCow (CVE-2016-5195)" "$CRITICAL" "KERNEL_EXPLOIT" "Upgrade the kernel to the latest version"
        addToPrivEscVectors "Kernel Exploitation" "The system is running kernel version 2.6.x which is vulnerable to DirtyCow (CVE-2016-5195). This can be exploited to gain root privileges." "$CRITICAL" "Straightforward with publicly available exploits"
    fi
    
    if [[ "$kernelVersion" =~ ^3\.1[0-9]\. ]]; then
        addToAnomalies "Kernel Exploit" "Kernel version 3.1x.x detected, potentially vulnerable to overlayfs (CVE-2015-1328)" "$CRITICAL" "KERNEL_EXPLOIT" "Upgrade the kernel to the latest version"
        addToPrivEscVectors "Kernel Exploitation" "The system is running kernel version 3.1x.x which is vulnerable to overlayfs (CVE-2015-1328). This can be exploited to gain root privileges." "$CRITICAL" "Straightforward with publicly available exploits"
    fi
    
    if [[ "$kernelVersion" =~ ^4\.[0-9]\. ]]; then
        addToAnomalies "Kernel Exploit" "Kernel version 4.x.x detected, check for eBPF or other 4.x kernel exploits" "$HIGH" "KERNEL_EXPLOIT" "Upgrade the kernel to the latest version"
        addToPrivEscVectors "Kernel Exploitation" "The system is running kernel version 4.x.x which might be vulnerable to eBPF exploits. Version-specific checking is required." "$HIGH" "Requires version-specific exploit code"
    fi
    
    # OS information
    logMessage "SUBSECTION" "OS Information (Matrix Architecture)"
    osInfo=$(interrogateMatrix "cat /etc/issue")
    osRelease=$(interrogateMatrix "cat /etc/*-release")
    echo "$osInfo"
    echo "$osRelease"
    addToPattern "OS Information" "ANALYZED" "$osInfo"
    
    # PATH information
    logMessage "SUBSECTION" "PATH Information (Pathways in the Matrix)"
    pathInfo=$(interrogateMatrix "echo $PATH | tr \":\" \"\n\"")
    echo "$pathInfo"
    
    # Check for writable directories in PATH
    while IFS= read -r directory; do
        if [ -w "$directory" ]; then
            addToAnomalies "Writable PATH" "Directory in PATH is writable: $directory" "$HIGH" "WRITABLE_PATH" "Remove write permissions from the directory or remove it from PATH"
            addToPrivEscVectors "Writable PATH Abuse" "A directory in the PATH ($directory) is writable. This allows for creating or modifying executables that may be run by other users including root." "$HIGH" "Create a malicious executable with the same name as a commonly used command"
        fi
    done <<< "$pathInfo"
    
    addToPattern "Writable PATH Check" "ANALYZED" ""
    
    # Environment variables
    logMessage "SUBSECTION" "Environment Variables (Matrix Code Parameters)"
    envInfo=$(interrogateMatrix "env")
    showWithRedPill "$envInfo"
    
    # Check for sensitive information in environment variables
    if echo "$envInfo" | grep -i "key\|password\|secret\|token\|credential" > /dev/null; then
        addToAnomalies "Sensitive Environment Variables" "Found sensitive information in environment variables" "$MEDIUM" "SENSITIVE_INFO" "Remove sensitive information from environment variables"
    fi
    
    addToPattern "Environment Variables Check" "ANALYZED" ""
    
    # sudo version
    logMessage "SUBSECTION" "Sudo Version (Agent Program Version)"
    sudoVersion=$(interrogateMatrix "sudo -V | head -n 1")
    echo "$sudoVersion"
    
    # Check for vulnerable sudo versions
    if [[ "$sudoVersion" =~ 1\.8\.[0-9]\. ]]; then
        addToAnomalies "Sudo Vulnerability" "Sudo version potentially vulnerable to CVE-2019-14287 (sudo < 1.8.28)" "$HIGH" "SUDO_VULNERABILITY" "Upgrade sudo to version 1.8.28 or later"
        addToPrivEscVectors "Sudo Vulnerability Exploitation" "The system is running a sudo version potentially vulnerable to CVE-2019-14287. This can be exploited to gain root privileges by using a user ID of -1 or 4294967295." "$HIGH" "Requires sudo privileges with specific configuration"
    fi
    
    if [[ "$sudoVersion" =~ 1\.8\.2[0-7] ]]; then
        addToAnomalies "Sudo Vulnerability" "Sudo version potentially vulnerable to CVE-2019-18634 (sudo < 1.8.26)" "$HIGH" "SUDO_VULNERABILITY" "Upgrade sudo to version 1.8.26 or later"
        addToPrivEscVectors "Sudo Vulnerability Exploitation" "The system is running a sudo version potentially vulnerable to CVE-2019-18634 (buffer overflow). This can be exploited to gain root privileges." "$HIGH" "Requires specific sudo configuration"
    fi
    
    addToPattern "Sudo Version Check" "ANALYZED" "$sudoVersion"
    
    # Signature verification
    logMessage "SUBSECTION" "Signature Verification (Matrix Authentication)"
    dmesgSig=$(interrogateMatrix "dmesg | grep -i \"signature\"")
    if [[ "$dmesgSig" == *"signature verification failed"* ]]; then
        addToAnomalies "Signature Verification Failed" "System may be vulnerable to module loading exploits" "$MEDIUM" "MODULE_LOADING" "Ensure module signature verification is enabled and working correctly"
    fi
    addToPattern "Signature Verification Check" "ANALYZED" ""
}

# Check drives and mounts (the physical constructs of the Matrix)
analyzeDrives() {
    logMessage "SECTION" "Drives and Mounts (Matrix Constructs)"
    
    # List mounted drives
    logMessage "SUBSECTION" "Mounted Drives (Active Constructs)"
    mountedDrives=$(interrogateMatrix "mount")
    showWithRedPill "$mountedDrives"
    
    # Check for NFS shares with no_root_squash
    if echo "$mountedDrives" | grep "no_root_squash" > /dev/null; then
        addToAnomalies "NFS no_root_squash" "Found NFS share with no_root_squash option" "$HIGH" "NFS_PRIVILEGE_ESCALATION" "Reconfigure NFS to use root_squash option"
        addToPrivEscVectors "NFS Privilege Escalation" "NFS share with no_root_squash option detected. This can be exploited to gain root privileges by creating SUID binaries on the NFS share." "$HIGH" "Requires access to the NFS mount point"
    fi
    
    addToPattern "Mounted Drives Check" "ANALYZED" ""
    
    # Check for unmounted drives
    logMessage "SUBSECTION" "Unmounted Drives (Dormant Constructs)"
    if [ -f "/etc/fstab" ]; then
        fstabEntries=$(interrogateMatrix "cat /etc/fstab")
        showWithRedPill "$fstabEntries"
        
        # Check for credentials in fstab
        if echo "$fstabEntries" | grep -i "user\|password\|credentials" > /dev/null; then
            addToAnomalies "FSTAB Credentials" "Found credentials in /etc/fstab" "$MEDIUM" "SENSITIVE_INFO" "Remove credentials from fstab or use a more secure authentication method"
        fi
        
        # Look for unmounted drives
        currentMounts=$(mount | awk '{print $1}')
        while read -r line; do
            if [[ $line =~ ^[^#] ]]; then
                device=$(echo "$line" | awk '{print $1}')
                if ! echo "$currentMounts" | grep -q "$device"; then
                    addToAnomalies "Unmounted Drive" "Drive in fstab not currently mounted: $device" "$LOW" "ENUMERATION" "This is informational only"
                fi
            fi
        done <<< "$fstabEntries"
    fi
    
    addToPattern "FSTAB Check" "ANALYZED" ""
}

# Check installed software (programs within the Matrix)
analyzePrograms() {
    logMessage "SECTION" "Installed Software (Matrix Programs)"
    
    # Check for useful software
    logMessage "SUBSECTION" "Useful Software (Helpful Programs)"
    usefulSoftware=("gcc" "g++" "python" "python3" "perl" "ruby" "nmap" "netcat" "nc" "wget" "curl" "ssh" "telnet" "ftp" "tcpdump" "wireshark" "john" "hydra" "mysql" "psql")
    
    for software in "${usefulSoftware[@]}"; do
        if command -v "$software" &> /dev/null; then
            showWithRedPill "Found useful software: $software ($(which "$software"))"
        fi
    done
    
    addToPattern "Useful Software Check" "ANALYZED" ""
    
    # Check for vulnerable software versions
    logMessage "SUBSECTION" "Software Versions (Program Versions)"
    
    # Check OpenSSH version
    sshVersion=$(interrogateMatrix "ssh -V 2>&1")
    showWithRedPill "OpenSSH version: $sshVersion"
    
    # Check Apache version
    apacheVersion=$(interrogateMatrix "apache2 -v 2>&1 || httpd -v 2>&1")
    showWithRedPill "Apache version: $apacheVersion"
    
    # Check MySQL version
    mysqlVersion=$(interrogateMatrix "mysql --version 2>&1")
    showWithRedPill "MySQL version: $mysqlVersion"
    
    # List installed packages
    logMessage "SUBSECTION" "Installed Packages (Loaded Programs)"
    
    # For Debian-based systems
    debPackages=$(interrogateMatrix "dpkg -l | grep '^ii'")
    if [ ! -z "$debPackages" ]; then
        showWithRedPill "Debian packages installed"
    fi
    
    # For Red Hat-based systems
    rpmPackages=$(interrogateMatrix "rpm -qa")
    if [ ! -z "$rpmPackages" ]; then
        showWithRedPill "RPM packages installed"
    fi
    
    addToPattern "Software Versions Check" "ANALYZED" ""
}

# Check network information (the connections within the Matrix)
analyzeNetwork() {
    logMessage "SECTION" "Network Information (Matrix Connection Pathways)"
    
    # IP configuration
    logMessage "SUBSECTION" "IP Configuration (Digital Identities)"
    ipConfig=$(interrogateMatrix "ifconfig -a 2>/dev/null || ip a")
    echo "$ipConfig"
    addToPattern "IP Configuration Check" "ANALYZED" ""
    
    # Network routes
    logMessage "SUBSECTION" "Network Routes (Matrix Pathways)"
    routes=$(interrogateMatrix "route -n 2>/dev/null || ip route")
    showWithRedPill "$routes"
    addToPattern "Network Routes Check" "ANALYZED" ""
    
    # DNS resolver
    logMessage "SUBSECTION" "DNS Configuration (Name Resolution System)"
    dnsInfo=$(interrogateMatrix "cat /etc/resolv.conf")
    showWithRedPill "$dnsInfo"
    addToPattern "DNS Configuration Check" "ANALYZED" ""
    
    # ARP table
    logMessage "SUBSECTION" "ARP Table (Known Entities)"
    arpTable=$(interrogateMatrix "arp -en 2>/dev/null || ip neigh")
    showWithRedPill "$arpTable"
    addToPattern "ARP Table Check" "ANALYZED" ""
    
    # Active connections
    logMessage "SUBSECTION" "Active Connections (Open Communication Channels)"
    connections=$(interrogateMatrix "netstat -auntp 2>/dev/null || ss -tunlp")
    showWithRedPill "$connections"
    
    # Check for interesting open ports
    if echo "$connections" | grep "LISTEN" | grep -v "127.0.0.1" > /dev/null; then
        addToAnomalies "Open Ports" "Found potentially interesting listening ports" "$MEDIUM" "NETWORK_SERVICES" "Review and secure network services"
    fi
    
    addToPattern "Active Connections Check" "ANALYZED" ""
    
    # Network Manager
    logMessage "SUBSECTION" "Network Manager Credentials (Access Codes)"
    nmConnections=$(interrogateMatrix "cat /etc/NetworkManager/system-connections/* 2>/dev/null | grep -E \"^id|^psk\"")
    
    if [ ! -z "$nmConnections" ]; then
        showWithRedPill "$nmConnections"
        addToAnomalies "Network Manager Credentials" "Found credentials in Network Manager connections" "$MEDIUM" "SENSITIVE_INFO" "Restrict access to NetworkManager configuration files"
    fi
    
    addToPattern "Network Manager Credentials Check" "ANALYZED" ""
    
    # Check if we can sniff traffic
    logMessage "SUBSECTION" "Network Sniffing (Watching the Matrix Code)"
    if command -v tcpdump &> /dev/null; then
        showWithRedPill "tcpdump is available, potentially can sniff traffic"
    fi
    addToPattern "Network Sniffing Check" "ANALYZED" ""
}

# Check user information (identities within the Matrix)
analyzeIdentities() {
    logMessage "SECTION" "User Information (Matrix Identities)"
    
    # Current user
    logMessage "SUBSECTION" "Current User (Your Digital Self)"
    currentUser=$(interrogateMatrix "id")
    echo "$currentUser"
    addToPattern "Current User Check" "ANALYZED" "$currentUser"
    
    # Last logged on users
    logMessage "SUBSECTION" "Last Logged On Users (Recent Visitors)"
    lastLoggedOn=$(interrogateMatrix "lastlog | grep -v \"**Never logged in**\"")
    showWithRedPill "$lastLoggedOn"
    addToPattern "Last Logged On Users Check" "ANALYZED" ""
    
    # Currently logged on users
    logMessage "SUBSECTION" "Currently Logged On Users (Active Entities)"
    currentlyLoggedOn=$(interrogateMatrix "w")
    showWithRedPill "$currentlyLoggedOn"
    addToPattern "Currently Logged On Users Check" "ANALYZED" ""
    
    # All users with UID and GUID
    logMessage "SUBSECTION" "All Users with UID and GUID (Entity Identifiers)"
    allUsers=$(interrogateMatrix "for user in \$(cat /etc/passwd | cut -f1 -d \":\"); do id \$user 2>/dev/null; done")
    showWithRedPill "$allUsers"
    
    # Check for users with UID 0 (root equivalent)
    rootUsers=$(interrogateMatrix "cat /etc/passwd | cut -f1,3,4 -d\":\" | grep \"0:0\" | cut -f1 -d\":\"")
    
    if [ "$(echo "$rootUsers" | wc -l)" -gt 1 ]; then
        addToAnomalies "Root Equivalent Users" "Found users with UID 0 (root equivalent): $rootUsers" "$CRITICAL" "ROOT_USERS" "Remove root privileges from non-root users"
        addToPrivEscVectors "Root Equivalent Users" "Multiple users with UID 0 detected. These accounts have full root privileges and can be used to gain complete system access." "$CRITICAL" "Direct root access via the identified accounts"
    fi
    
    addToPattern "Users with UID 0 Check" "ANALYZED" ""
    
    # Check for high UID (potential CVE-2021-4034 - PwnKit)
    myUID=$(id -u)
    if [ "$myUID" -gt 1000000 ]; then
        addToAnomalies "High UID" "Current user has a very high UID ($myUID), potential PwnKit vulnerability" "$HIGH" "PWNKIT" "Update the polkit package to a patched version"
        addToPrivEscVectors "PwnKit Vulnerability" "The current user has a very high UID ($myUID), which might be exploitable via the PwnKit vulnerability (CVE-2021-4034) affecting polkit." "$HIGH" "Straightforward with publicly available exploits"
    fi
    
    # Check if current user belongs to interesting groups
    groups=$(groups)
    
    for group in docker disk lxd adm sudo wheel admin; do
        if echo "$groups" | grep -w "$group" > /dev/null; then
            addToAnomalies "Privileged Group" "Current user belongs to privileged group: $group" "$HIGH" "PRIVILEGED_GROUPS" "Review group memberships and remove unnecessary privileges"
            
            case $group in
                "docker")
                    addToPrivEscVectors "Docker Group Privileges" "The current user belongs to the docker group, which effectively grants root access via container features." "$HIGH" "Run a container that mounts the host filesystem"
                    ;;
                "disk")
                    addToPrivEscVectors "Disk Group Privileges" "The current user belongs to the disk group, which allows direct access to disk devices, potentially enabling access to all data and privilege escalation." "$HIGH" "Access raw disk devices to read/write system files"
                    ;;
                "lxd")
                    addToPrivEscVectors "LXD Group Privileges" "The current user belongs to the lxd group, which can be used to escalate privileges via container features." "$HIGH" "Create a privileged container that mounts the host filesystem"
                    ;;
                "sudo"|"wheel"|"admin")
                    addToPrivEscVectors "Admin Group Privileges" "The current user belongs to the $group group, which may grant sudo access depending on the sudo configuration." "$HIGH" "Check sudo permissions with 'sudo -l'"
                    ;;
            esac
        fi
    done
    
    addToPattern "Privileged Groups Check" "ANALYZED" ""
    
    # Password policy
    logMessage "SUBSECTION" "Password Policy (Access Code Rules)"
    if [ -f "/etc/login.defs" ]; then
        passwdPolicy=$(interrogateMatrix "grep PASS /etc/login.defs")
        showWithRedPill "$passwdPolicy"
    fi
    addToPattern "Password Policy Check" "ANALYZED" ""
    
    # Clipboard data (if available)
    if command -v xclip &> /dev/null; then
        clipboardData=$(interrogateMatrix "xclip -o -selection clipboard 2>/dev/null")
        if [ ! -z "$clipboardData" ]; then
            showWithRedPill "Found clipboard data"
        fi
    fi
    addToPattern "Clipboard Check" "ANALYZED" ""
}

# Check running processes (active programs in the Matrix)
analyzeActivePrograms() {
    logMessage "SECTION" "Running Processes (Active Matrix Programs)"
    
    # List all processes
    logMessage "SUBSECTION" "All Processes (All Running Programs)"
    allProcesses=$(interrogateMatrix "ps auxwww")
    showWithRedPill "$allProcesses"
    addToPattern "All Processes Check" "ANALYZED" ""
    
    # Processes running as root
    logMessage "SUBSECTION" "Processes Running as Root (Admin Programs)"
    rootProcesses=$(interrogateMatrix "ps -u root")
    showWithRedPill "$rootProcesses"
    
    # Check for interesting processes
    for process in mysql apache2 nginx tomcat postgres weblogic jboss jenkins; do
        if echo "$allProcesses" | grep -i "$process" > /dev/null; then
            showWithRedPill "Found interesting process: $process"
            addToAnomalies "Interesting Process" "Found $process process running" "$MEDIUM" "SERVICE_ENUMERATION" "Ensure the service is properly secured and up-to-date"
        fi
    done
    
    addToPattern "Root Processes Check" "ANALYZED" ""
    
    # Processes running as current user
    logMessage "SUBSECTION" "Processes Running as Current User (Your Programs)"
    userProcesses=$(interrogateMatrix "ps -u $USER")
    showWithRedPill "$userProcesses"
    addToPattern "User Processes Check" "ANALYZED" ""
    
    # Check for processes with higher privileges
    logMessage "SUBSECTION" "Process Privileges (Program Permissions)"
    # This is a simplified check, looking for setuid processes
    setuidProcs=$(interrogateMatrix "ps -ef | grep -v grep | grep -i \"setuid\"")
    if [ ! -z "$setuidProcs" ]; then
        showWithRedPill "$setuidProcs"
        addToAnomalies "Privileged Process" "Found processes potentially running with elevated privileges" "$MEDIUM" "PROCESS_PRIVILEGES" "Review and restrict process privileges"
    fi
    addToPattern "Process Privileges Check" "ANALYZED" ""
    
    # Check process memory for credentials
    logMessage "SUBSECTION" "Process Memory (Program Code Storage)"
    if command -v strings &> /dev/null; then
        showWithRedPill "strings command is available for memory inspection"
    fi
    addToPattern "Process Memory Check" "ANALYZED" ""
}

# Check file and folder permissions (access controls in the Matrix)
analyzePermissions() {
    logMessage "SECTION" "File and Folder Permissions (Matrix Access Controls)"
    
    # Can we read shadow?
    logMessage "SUBSECTION" "Shadow File Access (Accessing Restricted Data)"
    shadowAccess=$(interrogateMatrix "cat /etc/shadow")
    
    if [ ! -z "$shadowAccess" ]; then
        addToAnomalies "Shadow File Access" "Current user can read /etc/shadow" "$HIGH" "SENSITIVE_FILE_ACCESS" "Fix permissions on /etc/shadow to restrict access"
        addToPrivEscVectors "Shadow File Access" "The current user can read /etc/shadow, which contains password hashes. These can be cracked offline to gain access to other accounts." "$HIGH" "Copy password hashes and crack them offline"
    fi
    
    addToPattern "Shadow File Access Check" "ANALYZED" ""
    
    # Find sticky bit
    logMessage "SUBSECTION" "Sticky Bit Files/Directories (Protected Constructs)"
    stickyBit=$(interrogateMatrix "find / -perm -1000 -type d 2>/dev/null")
    showWithRedPill "$stickyBit"
    addToPattern "Sticky Bit Check" "ANALYZED" ""
    
    # Find SUID binaries
    logMessage "SUBSECTION" "SUID Binaries (Programs with Special Access)"
    suidBins=$(interrogateMatrix "find / -perm -u=s -type f 2>/dev/null")
    showWithRedPill "$suidBins"
    
    # Check for interesting SUID binaries
    for binary in nmap vim nano find cp less more bash zsh ksh dash pkexec doas su sudo python perl ruby php; do
        if echo "$suidBins" | grep -w "$binary" > /dev/null; then
            addToAnomalies "Interesting SUID Binary" "Found SUID binary: $binary" "$HIGH" "SUID_BINARY" "Remove SUID bit if not required"
            addToPrivEscVectors "SUID Binary Exploitation" "The $binary binary has the SUID bit set. This can potentially be exploited to gain elevated privileges." "$HIGH" "Execute the binary with specific arguments or in a specific way to gain elevated access"
        fi
    done
    
    addToPattern "SUID Binaries Check" "ANALYZED" ""
    
    # Find SGID binaries
    logMessage "SUBSECTION" "SGID Binaries (Group-Powered Programs)"
    sgidBins=$(interrogateMatrix "find / -perm -g=s -type f 2>/dev/null")
    showWithRedPill "$sgidBins"
    addToPattern "SGID Binaries Check" "ANALYZED" ""
    
    # Find world-writable files
    logMessage "SUBSECTION" "World-Writable Files (Universally Modifiable Data)"
    worldWritable=$(interrogateMatrix "find / -perm -2 -type f -not -path \"/proc/*\" -not -path \"/sys/*\" 2>/dev/null")
    showWithRedPill "$worldWritable"
    
    # Check for interesting writable files
    for file in /etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab /etc/ssh/sshd_config; do
        if echo "$worldWritable" | grep -w "$file" > /dev/null; then
            addToAnomalies "Writable Critical File" "Found writable critical file: $file" "$CRITICAL" "WRITABLE_CRITICAL_FILE" "Fix permissions on $file to prevent unauthorized modifications"
            addToPrivEscVectors "Critical File Write Access" "The $file file is writable, which allows for direct privilege escalation or system compromise." "$CRITICAL" "Modify the file to add privileged users or change security settings"
        fi
    done
    
    addToPattern "World-Writable Files Check" "ANALYZED" ""
    
    # Check configuration files for passwords
    logMessage "SUBSECTION" "Configuration Files with Sensitive Information (Access Code Storage)"
    passInConf=$(interrogateMatrix "grep -l 'pass' /etc/*.conf 2>/dev/null")
    keyInConf=$(interrogateMatrix "grep -l 'key' /etc/*.conf 2>/dev/null")
    secretInConf=$(interrogateMatrix "grep -l 'secret' /etc/*.conf 2>/dev/null")
    
    if [ ! -z "$passInConf" ] || [ ! -z "$keyInConf" ] || [ ! -z "$secretInConf" ]; then
        addToAnomalies "Sensitive Information in Config Files" "Found configuration files with sensitive information" "$MEDIUM" "SENSITIVE_INFO" "Remove sensitive information from configuration files or restrict access to them"
    fi
    
    addToPattern "Configuration Files Check" "ANALYZED" ""
    
    # Can we list contents of root directory?
    logMessage "SUBSECTION" "Root Directory Access (The One's Home)"
    rootDirAccess=$(interrogateMatrix "ls -als /root/")
    
    if [ ! -z "$rootDirAccess" ]; then
        showWithRedPill "$rootDirAccess"
        addToAnomalies "Root Directory Access" "Current user can list contents of /root/" "$MEDIUM" "UNAUTHORIZED_ACCESS" "Fix permissions on /root directory to prevent unauthorized access"
    fi
    
    addToPattern "Root Directory Access Check" "ANALYZED" ""
    
    # History files
    logMessage "SUBSECTION" "History Files (Command Memories)"
    historyFiles=$(interrogateMatrix "find /* -name *.*history* -print 2>/dev/null")
    showWithRedPill "$historyFiles"
    
    if [ ! -z "$historyFiles" ]; then
        addToAnomalies "History Files" "Found history files which may contain sensitive information" "$LOW" "SENSITIVE_INFO" "Clear history files containing sensitive information"
    fi
    
    addToPattern "History Files Check" "ANALYZED" ""
}

# Check cron jobs (scheduled tasks within the Matrix)
analyzeScheduledTasks() {
    logMessage "SECTION" "Cron Jobs (Matrix Scheduled Events)"
    
    # System crontab
    logMessage "SUBSECTION" "System Crontab (Master Schedule)"
    systemCron=$(interrogateMatrix "cat /etc/crontab")
    showWithRedPill "$systemCron"
    addToPattern "System Crontab Check" "ANALYZED" ""
    
    # Cron directories
    logMessage "SUBSECTION" "Cron Directories (Schedule Repositories)"
    cronDirs=$(interrogateMatrix "ls -als /etc/cron.*")
    showWithRedPill "$cronDirs"
    addToPattern "Cron Directories Check" "ANALYZED" ""
    
    # Check for world-writable cron jobs
    logMessage "SUBSECTION" "World-Writable Cron Jobs (Modifiable Scheduled Events)"
    writableCron=$(interrogateMatrix "find /etc/cron* -type f -perm -o+w -exec ls -l {} \;")
    
    if [ ! -z "$writableCron" ]; then
        showWithRedPill "$writableCron"
        addToAnomalies "Writable Cron Jobs" "Found world-writable cron jobs" "$CRITICAL" "WRITABLE_CRON" "Remove write permissions from cron job files"
        addToPrivEscVectors "Writable Cron Jobs" "One or more cron job files are world-writable. These can be modified to execute arbitrary commands as the user who owns the cron job (potentially root)." "$CRITICAL" "Modify the cron job to execute a malicious command"
    fi
    
    addToPattern "World-Writable Cron Jobs Check" "ANALYZED" ""
    
    # Check for PATH modification in cron
    if echo "$systemCron" | grep "PATH" > /dev/null; then
        cronPath=$(echo "$systemCron" | grep "PATH" | head -1)
        showWithRedPill "Cron PATH: $cronPath"
        
        # Extract directories from the PATH
        cronPathDirs=$(echo "$cronPath" | cut -d= -f2 | tr ":" "\n")
        
        while IFS= read -r directory; do
            if [ -w "$directory" ]; then
                addToAnomalies "Writable Cron PATH" "Directory in cron PATH is writable: $directory" "$HIGH" "WRITABLE_CRON_PATH" "Remove write permissions from the directory or remove it from cron PATH"
                addToPrivEscVectors "Writable Cron PATH" "A directory in the cron PATH ($directory) is writable. This allows for creating or modifying executables that will be run by cron jobs." "$HIGH" "Create a malicious executable with the same name as a command used in a cron job"
            fi
        done <<< "$cronPathDirs"
    fi
    
    addToPattern "Cron PATH Check" "ANALYZED" ""
    
    # Check for wildcard usage in cron jobs
    if echo "$systemCron" | grep -E '[*]' | grep -v "^#" | grep -v "^[0-9].*[*]" > /dev/null; then
        addToAnomalies "Cron Wildcard" "Found potential wildcard usage in cron jobs" "$HIGH" "CRON_WILDCARD" "Review cron jobs for wildcard command injection vulnerabilities"
        addToPrivEscVectors "Cron Wildcard Injection" "One or more cron jobs appear to use wildcards in command arguments. This may be exploitable via wildcard injection techniques." "$HIGH" "Create files with specific names that get interpreted as command arguments"
    fi
    
    addToPattern "Cron Wildcard Check" "ANALYZED" ""
    
    # Frequently running cron jobs (potential targets)
    logMessage "SUBSECTION" "Frequently Running Cron Jobs (Rapid Matrix Events)"
    frequentCrons=$(echo "$systemCron" | grep -E "^[*]|^[0-9][0-9]?/[0-9]|^[*]/[0-9]" | grep -v "^#")
    if [ ! -z "$frequentCrons" ]; then
        showWithRedPill "$frequentCrons"
        addToAnomalies "Frequent Cron Jobs" "Found cron jobs that run frequently" "$MEDIUM" "FREQUENT_CRON" "Review frequently running cron jobs for security risks"
    fi
    addToPattern "Frequent Cron Jobs Check" "ANALYZED" ""
}

# Check systemd services and timers (system services within the Matrix)
analyzeSystemServices() {
    logMessage "SECTION" "Systemd Services and Timers (Matrix System Services)"
    
    # Check if systemd is in use
    if command -v systemctl &> /dev/null; then
        # List all services
        logMessage "SUBSECTION" "Systemd Services (Running Services)"
        services=$(interrogateMatrix "systemctl list-units --type=service --all")
        showWithRedPill "$services"
        
        # Check for writable service files
        writableServices=$(interrogateMatrix "find /etc/systemd/system -writable -name \"*.service\" 2>/dev/null")
        if [ ! -z "$writableServices" ]; then
            showWithRedPill "$writableServices"
            addToAnomalies "Writable Service Files" "Found writable systemd service files" "$CRITICAL" "WRITABLE_SERVICE" "Remove write permissions from systemd service files"
            addToPrivEscVectors "Writable Systemd Service Files" "One or more systemd service files are writable. These can be modified to execute arbitrary commands, potentially as root." "$CRITICAL" "Modify a service file to execute a malicious command, then restart the service"
        fi
        
        # Check for writable binaries executed by services
        logMessage "SUBSECTION" "Service Binaries (Service Executables)"
        serviceFiles=$(interrogateMatrix "find /etc/systemd/system -name \"*.service\" -exec cat {} \; 2>/dev/null | grep -E \"^ExecStart=\" | cut -d= -f2")
        
        for binary in $serviceFiles; do
            if [ -w "$binary" ]; then
                addToAnomalies "Writable Service Binary" "Found writable binary executed by a service: $binary" "$CRITICAL" "WRITABLE_SERVICE_BINARY" "Remove write permissions from the service binary"
                addToPrivEscVectors "Writable Service Binary" "A binary executed by a systemd service ($binary) is writable. This can be modified to execute arbitrary commands when the service runs." "$CRITICAL" "Replace the binary with a malicious version"
            fi
        done
        
        # List timers
        logMessage "SUBSECTION" "Systemd Timers (Service Timers)"
        timers=$(interrogateMatrix "systemctl list-timers --all")
        showWithRedPill "$timers"
        
        # Check for writable timer files
        writableTimers=$(interrogateMatrix "find /etc/systemd/system -writable -name \"*.timer\" 2>/dev/null")
        if [ ! -z "$writableTimers" ]; then
            showWithRedPill "$writableTimers"
            addToAnomalies "Writable Timer Files" "Found writable systemd timer files" "$CRITICAL" "WRITABLE_TIMER" "Remove write permissions from systemd timer files"
            addToPrivEscVectors "Writable Systemd Timer Files" "One or more systemd timer files are writable. These can be modified to execute services more frequently or redirect to malicious services." "$CRITICAL" "Modify a timer file to execute a service more frequently or point to a different service"
        fi
    fi
    
    addToPattern "Systemd Services Check" "ANALYZED" ""
    addToPattern "Systemd Timers Check" "ANALYZED" ""
}

# Check for D-Bus and sockets (communication channels within the Matrix)
analyzeCommChannels() {
    logMessage "SECTION" "D-Bus and Sockets (Matrix Communication Channels)"
    
    # Check for D-Bus
    if command -v dbus-send &> /dev/null; then
        logMessage "SUBSECTION" "D-Bus (Inter-Process Communication)"
        dbusList=$(interrogateMatrix "dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null")
        showWithRedPill "$dbusList"
    fi
    addToPattern "D-Bus Check" "ANALYZED" ""
    
    # Check for sockets
    logMessage "SUBSECTION" "Sockets (Connection Points)"
    socketList=$(interrogateMatrix "find / -type s -not -path \"/proc/*\" 2>/dev/null")
    showWithRedPill "$socketList"
    
    # Check for writable socket files
    writableSockets=$(interrogateMatrix "find /etc/systemd/system -writable -name \"*.socket\" 2>/dev/null")
    if [ ! -z "$writableSockets" ]; then
        showWithRedPill "$writableSockets"
        addToAnomalies "Writable Socket Files" "Found writable systemd socket files" "$HIGH" "WRITABLE_SOCKET" "Remove write permissions from systemd socket files"
        addToPrivEscVectors "Writable Socket Files" "One or more systemd socket files are writable. These can be modified to redirect services or execute arbitrary commands." "$HIGH" "Modify a socket file to redirect to a malicious service"
    fi
    
    # Check for HTTP sockets
    httpSockets=$(interrogateMatrix "netstat -an | grep -i \"http\"")
    if [ ! -z "$httpSockets" ]; then
        showWithRedPill "$httpSockets"
        addToAnomalies "HTTP Sockets" "Found HTTP sockets that might contain interesting information" "$MEDIUM" "NETWORK_SERVICES" "Review HTTP services for security issues"
    fi
    
    addToPattern "Sockets Check" "ANALYZED" ""
}

# Check for sudo permissions (special access within the Matrix)
analyzeSpecialPermissions() {
    logMessage "SECTION" "Sudo Permissions (Agent-Level Access Permissions)"
    
    # List sudo permissions
    logMessage "SUBSECTION" "Sudo Permissions for Current User (Your Special Access)"
    sudoPerms=$(interrogateMatrix "sudo -l")
    
    if [ ! -z "$sudoPerms" ]; then
        echo "$sudoPerms"
        
        # Check for interesting sudo permissions using GTFOBins
        for cmd in cp find vim nano perl python ruby bash sh dash ksh zsh php netcat nc ncat less more awk nmap docker; do
            if echo "$sudoPerms" | grep -w "$cmd" > /dev/null; then
                addToAnomalies "Interesting Sudo Permission" "Can execute $cmd with sudo (potential GTFOBins vector)" "$HIGH" "SUDO_GTFOBINS" "Restrict sudo permissions to only necessary commands"
                addToPrivEscVectors "Sudo GTFOBins" "The current user can execute $cmd with sudo privileges. This command is known to have methods to escape restricted environments or escalate privileges." "$HIGH" "Execute $cmd with specific arguments to gain elevated privileges"
            fi
        done
        
        # Check for sudo commands without full path
        if echo "$sudoPerms" | grep -E "\([a-zA-Z0-9_-]+\) NOPASSWD: [^/]" > /dev/null; then
            addToAnomalies "Sudo Without Path" "Found sudo permissions for commands without full path" "$HIGH" "SUDO_PATH" "Use full paths in sudo configuration"
            addToPrivEscVectors "Sudo PATH Abuse" "Sudo is configured to allow execution of commands without specifying the full path. This can be exploited by manipulating the PATH environment variable." "$HIGH" "Create a malicious version of the command in a directory earlier in the PATH"
        fi
        
        # Check for ALL permission
        if echo "$sudoPerms" | grep "ALL" > /dev/null; then
            addToAnomalies "Sudo ALL Permission" "User has ALL sudo permissions" "$CRITICAL" "SUDO_ALL" "Restrict sudo permissions to only necessary commands"
            addToPrivEscVectors "Sudo ALL Access" "The current user has unrestricted sudo access (ALL). This effectively grants full root privileges." "$CRITICAL" "Execute 'sudo su' to get a root shell"
        fi
        
        # Check for NOPASSWD
        if echo "$sudoPerms" | grep "NOPASSWD" > /dev/null; then
            addToAnomalies "Sudo NOPASSWD" "User has NOPASSWD sudo permissions" "$HIGH" "SUDO_NOPASSWD" "Remove NOPASSWD option from sudo configuration"
            addToPrivEscVectors "Sudo NOPASSWD" "The user can execute sudo commands without providing a password. This reduces the security of sudo and makes privilege escalation easier." "$HIGH" "Execute sudo commands without needing authentication"
        fi
        
        # Check for LD_PRELOAD in env_keep
        if echo "$sudoPerms" | grep "LD_PRELOAD" > /dev/null; then
            addToAnomalies "Sudo LD_PRELOAD" "LD_PRELOAD is kept in sudo, potential for privilege escalation" "$HIGH" "SUDO_LD_PRELOAD" "Remove LD_PRELOAD from env_keep in sudo configuration"
            addToPrivEscVectors "Sudo LD_PRELOAD" "LD_PRELOAD is preserved in the sudo environment. This can be exploited to inject arbitrary code into processes run with sudo." "$HIGH" "Create a malicious shared object and set LD_PRELOAD to point to it when running sudo"
        fi
    fi
    
    addToPattern "Sudo Permissions Check" "ANALYZED" ""
    
    # Check sudoers files
    logMessage "SUBSECTION" "Sudoers Files (Special Access Configurations)"
    sudoersFile=$(interrogateMatrix "cat /etc/sudoers 2>/dev/null")
    sudoersDir=$(interrogateMatrix "ls -la /etc/sudoers.d/ 2>/dev/null")
    
    if [ ! -z "$sudoersFile" ] || [ ! -z "$sudoersDir" ]; then
        showWithRedPill "Sudoers file: $sudoersFile"
        showWithRedPill "Sudoers.d directory: $sudoersDir"
        
        # Check if sudoers files are writable
        sudoersWritable=$(interrogateMatrix "find /etc/sudoers /etc/sudoers.d/ -writable 2>/dev/null")
        
        if [ ! -z "$sudoersWritable" ]; then
            addToAnomalies "Writable Sudoers Files" "Found writable sudoers files: $sudoersWritable" "$CRITICAL" "WRITABLE_SUDOERS" "Fix permissions on sudoers files to prevent unauthorized modifications"
            addToPrivEscVectors "Writable Sudoers Files" "One or more sudoers files are writable. These can be modified to grant sudo privileges to any user or command." "$CRITICAL" "Modify sudoers to grant full sudo access to the current user"
        fi
    fi
    
    addToPattern "Sudoers Files Check" "ANALYZED" ""
    
    # Check for sudo token reuse
    logMessage "SUBSECTION" "Sudo Token Reuse (Access Token Hijacking)"
    sudoToken=$(interrogateMatrix "find /var/run/sudo -name \"*$USER*\" 2>/dev/null")
    
    if [ ! -z "$sudoToken" ]; then
        showWithRedPill "$sudoToken"
        addToAnomalies "Sudo Token Reuse" "Found sudo token for current user" "$MEDIUM" "SUDO_TOKEN" "Set shorter sudo token timeout in sudo configuration"
        addToPrivEscVectors "Sudo Token Reuse" "A sudo authentication token exists for the current user. This can potentially be exploited to execute sudo commands without re-authentication." "$MEDIUM" "Use techniques to extend or reuse the sudo token"
    fi
    
    addToPattern "Sudo Token Reuse Check" "ANALYZED" ""
    
    # Check for OpenBSD DOAS (alternative to sudo)
    if [ -f "/etc/doas.conf" ]; then
        logMessage "SUBSECTION" "OpenBSD DOAS (Alternate Access Control)"
        doasConf=$(interrogateMatrix "cat /etc/doas.conf")
        showWithRedPill "$doasConf"
        
        if [ ! -z "$doasConf" ]; then
            addToAnomalies "DOAS Configuration" "System uses DOAS, check configuration for privilege escalation" "$MEDIUM" "DOAS_CONFIG" "Review DOAS configuration for security issues"
            addToPrivEscVectors "DOAS Configuration" "The system uses DOAS (an alternative to sudo). Check the configuration for potential privilege escalation vectors." "$MEDIUM" "Analyze the DOAS configuration for permissive rules"
        fi
    fi
    
    addToPattern "DOAS Check" "ANALYZED" ""
    
    # Check for writable /etc/ld.so.conf.d/
    if [ -d "/etc/ld.so.conf.d/" ]; then
        ldsoConfWritable=$(interrogateMatrix "find /etc/ld.so.conf.d/ -writable 2>/dev/null")
        if [ ! -z "$ldsoConfWritable" ]; then
            addToAnomalies "Writable ld.so.conf.d" "Found writable files in /etc/ld.so.conf.d/" "$HIGH" "WRITABLE_LDSO" "Fix permissions on /etc/ld.so.conf.d/ to prevent unauthorized modifications"
            addToPrivEscVectors "Writable ld.so.conf.d" "Files in /etc/ld.so.conf.d/ are writable. These can be modified to change the library search path and potentially load malicious libraries." "$HIGH" "Create or modify files in ld.so.conf.d to load malicious libraries"
        fi
    fi
    
    addToPattern "ld.so.conf.d Check" "ANALYZED" ""
}

# Check for capabilities (special abilities within the Matrix)
analyzeCapabilities() {
    logMessage "SECTION" "Capabilities (Matrix Special Abilities)"
    
    # Check if getcap is available
    if command -v getcap &> /dev/null; then
        # List capabilities
        logMessage "SUBSECTION" "Files with Capabilities (Programs with Special Powers)"
        capabilities=$(interrogateMatrix "getcap -r / 2>/dev/null")
        
        if [ ! -z "$capabilities" ]; then
            echo "$capabilities"
            
            # Check for interesting capabilities
            for cap in cap_setuid cap_setgid cap_sys_admin; do
                if echo "$capabilities" | grep "$cap" > /dev/null; then
                    binary=$(echo "$capabilities" | grep "$cap" | awk '{print $1}')
                    addToAnomalies "Interesting Capability" "Found file with $cap capability: $binary" "$HIGH" "CAPABILITIES" "Review and remove unnecessary capabilities"
                    addToPrivEscVectors "File Capabilities" "One or more binaries have the $cap capability. This can be exploited to escalate privileges." "$HIGH" "Execute the binary with specific arguments to gain elevated privileges"
                fi
            done
        fi
    else
        logMessage "WARNING" "getcap not available, skipping capabilities check"
    fi
    
    addToPattern "Capabilities Check" "ANALYZED" ""
}

# Check for ACLs (fine-grained permissions in the Matrix)
analyzeACLs() {
    logMessage "SECTION" "ACLs (Matrix Access Control Lists)"
    
    # Check if getfacl is available
    if command -v getfacl &> /dev/null; then
        # Check ACLs on important directories
        logMessage "SUBSECTION" "Important Directory ACLs (Advanced Permissions)"
        for dir in /etc /var /opt /home /root /usr/bin /usr/sbin; do
            aclInfo=$(interrogateMatrix "getfacl -R $dir 2>/dev/null | grep -v \"^#\" | grep -v \"^$\"")
            if [ ! -z "$aclInfo" ]; then
                showWithRedPill "Found ACLs on $dir"
                # Look for unusual ACLs (this is a simple check)
                if echo "$aclInfo" | grep -E "user:[^:]+:rwx|group:[^:]+:rwx" > /dev/null; then
                    addToAnomalies "Interesting ACL" "Found ACL with full rwx permissions on $dir" "$MEDIUM" "UNUSUAL_ACL" "Review and restrict ACLs on sensitive directories"
                    addToPrivEscVectors "Unusual ACLs" "Full rwx permissions granted via ACLs on sensitive directories. This may allow unauthorized access to sensitive files or directories." "$MEDIUM" "Access sensitive files or directories using the permissive ACLs"
                fi
            fi
        done
    else
        logMessage "WARNING" "getfacl not available, skipping ACL check"
    fi
    
    addToPattern "ACLs Check" "ANALYZED" ""
}

# Check for open shell sessions (active terminal sessions in the Matrix)
analyzeShellSessions() {
    logMessage "SECTION" "Open Shell Sessions (Active Terminal Interfaces)"
    
    # Check for screen sessions
    logMessage "SUBSECTION" "Screen Sessions (Persistent Terminals)"
    screenSessions=$(interrogateMatrix "screen -ls")
    if [ ! -z "$screenSessions" ] && ! echo "$screenSessions" | grep "No Sockets found" > /dev/null; then
        showWithRedPill "$screenSessions"
        addToAnomalies "Screen Sessions" "Found active screen sessions" "$MEDIUM" "SHELL_SESSIONS" "Review active screen sessions and terminate if not needed"
        addToPrivEscVectors "Screen Sessions" "Active screen sessions detected. These might contain sensitive information or provide access to elevated privileges." "$MEDIUM" "Attach to the screen sessions to access potentially privileged shells"
    fi
    addToPattern "Screen Sessions Check" "ANALYZED" ""
    
    # Check for tmux sessions
    logMessage "SUBSECTION" "Tmux Sessions (Multi-Terminals)"
    tmuxSessions=$(interrogateMatrix "tmux list-sessions 2>/dev/null")
    if [ ! -z "$tmuxSessions" ]; then
        showWithRedPill "$tmuxSessions"
        addToAnomalies "Tmux Sessions" "Found active tmux sessions" "$MEDIUM" "SHELL_SESSIONS" "Review active tmux sessions and terminate if not needed"
        addToPrivEscVectors "Tmux Sessions" "Active tmux sessions detected. These might contain sensitive information or provide access to elevated privileges." "$MEDIUM" "Attach to the tmux sessions to access potentially privileged shells"
    fi
    addToPattern "Tmux Sessions Check" "ANALYZED" ""
}

# Check SSH configuration (secure access to the Matrix)
analyzeSecureAccess() {
    logMessage "SECTION" "SSH Configuration (Matrix Secure Access)"
    
    # Check for SSH keys
    logMessage "SUBSECTION" "SSH Keys (Digital Access Keys)"
    sshKeys=$(interrogateMatrix "find / -name \"id_rsa*\" -o -name \"id_dsa*\" -o -name \"*.pem\" -o -name \"authorized_keys\" 2>/dev/null")
    if [ ! -z "$sshKeys" ]; then
        showWithRedPill "$sshKeys"
        addToAnomalies "SSH Keys" "Found SSH keys that may allow unauthorized access" "$MEDIUM" "SSH_KEYS" "Review SSH keys and remove unnecessary ones"
        addToPrivEscVectors "SSH Key Access" "SSH keys were found on the system. These could potentially be used to gain access to other systems or accounts." "$MEDIUM" "Use the SSH keys to authenticate to other systems"
    fi
    
    addToPattern "SSH Keys Check" "ANALYZED" ""
    
    # Check SSH configuration
    logMessage "SUBSECTION" "SSH Configuration (Secure Shell Settings)"
    sshConfig=$(interrogateMatrix "cat /etc/ssh/sshd_config 2>/dev/null")
    if [ ! -z "$sshConfig" ]; then
        showWithRedPill "$sshConfig"
        
        # Check for interesting SSH configuration values
        if echo "$sshConfig" | grep -i "PermitRootLogin yes" > /dev/null; then
            addToAnomalies "SSH Root Login" "Root login is allowed via SSH" "$HIGH" "SSH_ROOT_LOGIN" "Disable direct root login via SSH"
            addToPrivEscVectors "SSH Root Login" "Direct root login is allowed via SSH. This increases the risk of brute force attacks against the root account." "$HIGH" "Attempt to brute force the root password for SSH access"
        fi
        
        if echo "$sshConfig" | grep -i "PasswordAuthentication yes" > /dev/null; then
            addToAnomalies "SSH Password Auth" "Password authentication is enabled for SSH" "$MEDIUM" "SSH_PASSWORD_AUTH" "Consider using key-based authentication only"
        fi
    fi
    
    # Check for Debian OpenSSL Predictable PRNG (CVE-2008-0166)
    if [ -f "/etc/debian_version" ]; then
        sshVersion=$(ssh -V 2>&1)
        if [[ "$sshVersion" =~ OpenSSH_4 ]] || [[ "$sshVersion" =~ OpenSSH_5.0 ]]; then
            addToAnomalies "Debian OpenSSL Vulnerability" "Potentially vulnerable to CVE-2008-0166 (Predictable PRNG)" "$HIGH" "SSH_DEBIAN_OPENSSL" "Upgrade OpenSSH and OpenSSL packages"
            addToPrivEscVectors "Debian OpenSSL Vulnerability" "The system is potentially vulnerable to CVE-2008-0166 (Debian OpenSSL Predictable PRNG). This affects SSH keys generated on Debian systems between 2006 and 2008." "$HIGH" "Use a known list of weak keys to attempt SSH authentication"
        fi
    fi
    
    addToPattern "SSH Configuration Check" "ANALYZED" ""
}

# Check for interesting files (valuable data in the Matrix)
analyzeValuableFiles() {
    logMessage "SECTION" "Interesting Files (Valuable Matrix Data)"
    
    # Check profile files
    logMessage "SUBSECTION" "Profile Files (Environment Setup Files)"
    profileFiles=$(interrogateMatrix "find /etc -name \"*.sh\" -o -name \"*profile*\" -o -name \"*bashrc*\" 2>/dev/null")
    showWithRedPill "$profileFiles"
    
    # Check if profile files are writable
    writableProfiles=$(interrogateMatrix "find /etc -writable -name \"*.sh\" -o -writable -name \"*profile*\" -o -writable -name \"*bashrc*\" 2>/dev/null")
    if [ ! -z "$writableProfiles" ]; then
        addToAnomalies "Writable Profile Files" "Found writable profile files that can be used for privilege escalation" "$HIGH" "WRITABLE_PROFILE" "Fix permissions on profile files to prevent unauthorized modifications"
        addToPrivEscVectors "Writable Profile Files" "One or more system-wide profile files (/etc/*profile*, /etc/*bashrc*) are writable. These can be modified to execute arbitrary commands when users log in or start new shells." "$HIGH" "Modify profile files to add malicious commands that will be executed by users (including root)"
    fi
    
    addToPattern "Profile Files Check" "ANALYZED" ""
    
    # Check passwd/shadow files
    logMessage "SUBSECTION" "Password Files (Identity Storage)"
    passwdWritable=$(interrogateMatrix "find /etc/passwd -writable 2>/dev/null")
    shadowWritable=$(interrogateMatrix "find /etc/shadow -writable 2>/dev/null")
    
    if [ ! -z "$passwdWritable" ]; then
        addToAnomalies "Writable passwd File" "The /etc/passwd file is writable" "$CRITICAL" "WRITABLE_PASSWD" "Fix permissions on /etc/passwd to prevent unauthorized modifications"
        addToPrivEscVectors "Writable /etc/passwd" "The /etc/passwd file is writable. This can be exploited to add a new user with root privileges." "$CRITICAL" "Add a new user with UID 0 to gain root access"
    fi
    
    if [ ! -z "$shadowWritable" ]; then
        addToAnomalies "Writable shadow File" "The /etc/shadow file is writable" "$CRITICAL" "WRITABLE_SHADOW" "Fix permissions on /etc/shadow to prevent unauthorized modifications"
        addToPrivEscVectors "Writable /etc/shadow" "The /etc/shadow file is writable. This can be exploited to modify password hashes for any user, including root." "$CRITICAL" "Modify the root password hash to a known value"
    fi
    
    addToPattern "Password Files Check" "ANALYZED" ""
}

# Check for writable files (mutable objects in the Matrix)
analyzeWritableFiles() {
    logMessage "SECTION" "Writable Files (Mutable Matrix Objects)"
    
    # Check for writable Python libraries
    logMessage "SUBSECTION" "Python Libraries (Scripting Libraries)"
    pythonPath=$(interrogateMatrix "python -c 'import sys; print(sys.path)' 2>/dev/null || python3 -c 'import sys; print(sys.path)' 2>/dev/null")
    
    if [ ! -z "$pythonPath" ]; then
        showWithRedPill "Python path: $pythonPath"
        
        # Extract paths from Python path
        pythonPaths=$(echo "$pythonPath" | tr -d "[],' " | tr ":" "\n")
        
        for path in $pythonPaths; do
            if [ -d "$path" ]; then
                writablePyLibs=$(interrogateMatrix "find $path -writable -name \"*.py\" 2>/dev/null")
                if [ ! -z "$writablePyLibs" ]; then
                    showWithRedPill "$writablePyLibs"
                    addToAnomalies "Writable Python Libraries" "Found writable Python libraries" "$HIGH" "WRITABLE_PYTHON_LIB" "Fix permissions on Python libraries to prevent unauthorized modifications"
                    addToPrivEscVectors "Writable Python Libraries" "One or more Python libraries are writable. These can be modified to execute arbitrary code when imported by scripts run by other users (potentially including root)." "$HIGH" "Modify a Python library to include malicious code that will be executed when the library is imported"
                fi
            fi
        done
    fi
    
    addToPattern "Python Libraries Check" "ANALYZED" ""
    
    # Check for writable log files (potential LogRotate exploit)
    logMessage "SUBSECTION" "Writable Log Files (System Logs)"
    writableLogs=$(interrogateMatrix "find /var/log -writable -type f 2>/dev/null")
    
    if [ ! -z "$writableLogs" ]; then
        showWithRedPill "$writableLogs"
        addToAnomalies "Writable Log Files" "Found writable log files (potential LogRotate exploit)" "$HIGH" "WRITABLE_LOGS" "Fix permissions on log files to prevent unauthorized modifications"
        addToPrivEscVectors "Writable Log Files" "One or more log files in /var/log are writable. These might be exploitable via the Logtotten vulnerability if logrotate is used." "$HIGH" "Exploit the Logtotten vulnerability if logrotate is used"
    fi
    
    addToPattern "Writable Log Files Check" "ANALYZED" ""
    
    # Check for writable network-scripts (CentOS/RHEL)
    if [ -d "/etc/sysconfig/network-scripts" ]; then
        logMessage "SUBSECTION" "Network Scripts (Network Configuration)"
        writableNetScripts=$(interrogateMatrix "find /etc/sysconfig/network-scripts -writable 2>/dev/null")
        
        if [ ! -z "$writableNetScripts" ]; then
            showWithRedPill "$writableNetScripts"
            addToAnomalies "Writable Network Scripts" "Found writable files in /etc/sysconfig/network-scripts/ (CentOS/RHEL exploit)" "$HIGH" "WRITABLE_NETWORK_SCRIPTS" "Fix permissions on network scripts to prevent unauthorized modifications"
            addToPrivEscVectors "Writable Network Scripts" "Files in /etc/sysconfig/network-scripts are writable. On CentOS/RHEL systems, this can be exploited to gain root privileges via specific script features." "$HIGH" "Modify network scripts to include malicious code that will be executed as root"
        fi
    fi
    
    addToPattern "Network Scripts Check" "ANALYZED" ""
    
    # Check for writable init scripts
    logMessage "SUBSECTION" "Init Scripts (Startup Scripts)"
    writableInit=$(interrogateMatrix "find /etc/init.d -writable 2>/dev/null")
    writableSystemd=$(interrogateMatrix "find /etc/systemd -writable 2>/dev/null")
    writableRc=$(interrogateMatrix "find /etc/rc.d -writable 2>/dev/null")
    
    if [ ! -z "$writableInit" ] || [ ! -z "$writableSystemd" ] || [ ! -z "$writableRc" ]; then
        if [ ! -z "$writableInit" ]; then showWithRedPill "$writableInit"; fi
        if [ ! -z "$writableSystemd" ]; then showWithRedPill "$writableSystemd"; fi
        if [ ! -z "$writableRc" ]; then showWithRedPill "$writableRc"; fi
        
        addToAnomalies "Writable Init Scripts" "Found writable initialization scripts" "$CRITICAL" "WRITABLE_INIT" "Fix permissions on initialization scripts to prevent unauthorized modifications"
        addToPrivEscVectors "Writable Init Scripts" "One or more initialization scripts are writable. These can be modified to execute arbitrary commands during system startup or service restarts." "$CRITICAL" "Modify init scripts to include malicious code that will be executed as root during system startup or service restart"
    fi
    
    addToPattern "Init Scripts Check" "ANALYZED" ""
    
    # Check commonly interesting folders
    logMessage "SUBSECTION" "Interesting Folders (Important Data Locations)"
    interestingFolders="/tmp /var/tmp /dev/shm /var/www /var/backups /opt /usr/local/bin"
    
    for folder in $interestingFolders; do
        if [ -d "$folder" ]; then
            folderContents=$(interrogateMatrix "ls -la $folder 2>/dev/null")
            showWithRedPill "Contents of $folder"
            showWithRedPill "$folderContents"
        fi
    done
    
    addToPattern "Interesting Folders Check" "ANALYZED" ""
    
    # Check for files owned by current user in unusual locations
    logMessage "SUBSECTION" "Files Owned by Current User (Your Data Objects)"
    userFiles=$(interrogateMatrix "find / -user $USER -not -path \"/proc/*\" -not -path \"/sys/*\" -not -path \"/run/*\" -not -path \"/home/*\" 2>/dev/null")
    showWithRedPill "$userFiles"
    addToPattern "User-Owned Files Check" "ANALYZED" ""
    
    # Check for recently modified files
    logMessage "SUBSECTION" "Recently Modified Files (Recent Changes)"
    recentFiles=$(interrogateMatrix "find / -type f -mmin -60 -not -path \"/proc/*\" -not -path \"/sys/*\" -not -path \"/run/*\" 2>/dev/null")
    showWithRedPill "$recentFiles"
    addToPattern "Recently Modified Files Check" "ANALYZED" ""
    
    # Check for SQLite databases
    logMessage "SUBSECTION" "SQLite Databases (Local Data Stores)"
    sqliteDbs=$(interrogateMatrix "find / -name \"*.db\" -o -name \"*.sqlite\" -o -name \"*.sqlite3\" 2>/dev/null")
    showWithRedPill "$sqliteDbs"
    addToPattern "SQLite Databases Check" "ANALYZED" ""
    
    # Check for hidden files in home directories
    logMessage "SUBSECTION" "Hidden Files (Concealed Data)"
    hiddenFiles=$(interrogateMatrix "find /home -name \".*\" -type f 2>/dev/null")
    showWithRedPill "$hiddenFiles"
    addToPattern "Hidden Files Check" "ANALYZED" ""
    
    # Check for script/binaries in PATH
    logMessage "SUBSECTION" "Executables in PATH (Available Commands)"
    pathDirs=$(echo $PATH | tr ':' ' ')
    for dir in $pathDirs; do
        if [ -d "$dir" ]; then
            execsInPath=$(interrogateMatrix "find $dir -type f -executable 2>/dev/null")
            showWithRedPill "Executables in $dir"
            showWithRedPill "$execsInPath"
        fi
    done
    addToPattern "Executables in PATH Check" "ANALYZED" ""
    
    # Check for web files
    logMessage "SUBSECTION" "Web Files (Web Content)"
    webFiles=$(interrogateMatrix "find / -name \"*.php\" -o -name \"*.html\" -o -name \"*.js\" -o -name \"*.conf\" -path \"*/www/*\" 2>/dev/null")
    showWithRedPill "$webFiles"
    addToPattern "Web Files Check" "ANALYZED" ""
    
    # Check for backup files
    logMessage "SUBSECTION" "Backup Files (Data Backups)"
    backupFiles=$(interrogateMatrix "find / -name \"*.bak\" -o -name \"*.backup\" -o -name \"*~\" -o -name \"*.old\" 2>/dev/null")
    showWithRedPill "$backupFiles"
    addToPattern "Backup Files Check" "ANALYZED" ""
    
    # Generic file search for passwords
    logMessage "SUBSECTION" "Files Containing Passwords (Access Code Storage)"
    passwordsInFiles=$(interrogateMatrix "grep -r \"password\" --include=\"*.txt\" --include=\"*.ini\" --include=\"*.conf\" /etc/ 2>/dev/null")
    showWithRedPill "$passwordsInFiles"
    addToPattern "Password Files Check" "ANALYZED" ""
}

# Generate an executive summary of the findings
generateExecutiveSummary() {
    local criticalCount=0
    local highCount=0
    local mediumCount=0
    local lowCount=0
    local infoCount=0
    
    # Count findings by severity
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation <<< "$anomaly"
        case $severity in
            "$CRITICAL") ((criticalCount++)) ;;
            "$HIGH") ((highCount++)) ;;
            "$MEDIUM") ((mediumCount++)) ;;
            "$LOW") ((lowCount++)) ;;
            "$INFO") ((infoCount++)) ;;
        esac
    done
    
    echo -e "${MATRIX_GREEN}${BOLD}EXECUTIVE SUMMARY${NC}"
    echo -e "${BOLD}==================${NC}"
    echo ""
    echo -e "MatrixScan has completed analysis of the system and identified potential privilege escalation vectors."
    echo ""
    echo -e "${BOLD}Findings Summary:${NC}"
    echo -e "${RED}${BOLD}Critical: $criticalCount${NC}"
    echo -e "${RED}High: $highCount${NC}"
    echo -e "${YELLOW}Medium: $mediumCount${NC}"
    echo -e "${BLUE}Low: $lowCount${NC}"
    echo -e "${GREEN}Info: $infoCount${NC}"
    echo ""
    
    # Print privilege escalation vectors if any were found
    if [ ${#privEscVectors[@]} -gt 0 ]; then
        echo -e "${BOLD}Identified Privilege Escalation Vectors:${NC}"
        for vector in "${privEscVectors[@]}"; do
            IFS='|' read -r name description severity exploitation <<< "$vector"
            
            case $severity in
                "$CRITICAL") color="${RED}${BOLD}" ;;
                "$HIGH") color="${RED}" ;;
                "$MEDIUM") color="${YELLOW}" ;;
                "$LOW") color="${BLUE}" ;;
                "$INFO") color="${GREEN}" ;;
                *) color="${WHITE}" ;;
            esac
            
            echo -e "${color}[$severity] $name${NC}"
            echo "  - $description"
            echo "  - Exploitation: $exploitation"
            echo ""
        done
    else
        echo -e "${GREEN}No clear privilege escalation vectors were identified.${NC}"
    fi
    
    echo -e "${BOLD}Recommendations:${NC}"
    echo "1. Address all Critical and High severity findings immediately."
    echo "2. Review Medium severity findings as part of a regular security maintenance process."
    echo "3. Implement security best practices to prevent future vulnerabilities."
    echo ""
    echo -e "${BOLD}Detailed findings are available in the full report.${NC}"
    echo ""
}

# Generate a text report with findings categorized by severity
generateTextReport() {
    # Initialize the report file
    > "$blueprintFile"
    
    # Header
    echo "===========================================================================" >> "$blueprintFile"
    echo "                           MATRIXSCAN REPORT                                " >> "$blueprintFile"
    echo "===========================================================================" >> "$blueprintFile"
    echo "Scan date: $(date)" >> "$blueprintFile"
    echo "Hostname: $(hostname)" >> "$blueprintFile"
    echo "User: $USER" >> "$blueprintFile"
    echo "===========================================================================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    # Executive Summary
    echo "EXECUTIVE SUMMARY" >> "$blueprintFile"
    echo "==================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    # Count findings by severity
    local criticalCount=0
    local highCount=0
    local mediumCount=0
    local lowCount=0
    local infoCount=0
    
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation <<< "$anomaly"
        case $severity in
            "$CRITICAL") ((criticalCount++)) ;;
            "$HIGH") ((highCount++)) ;;
            "$MEDIUM") ((mediumCount++)) ;;
            "$LOW") ((lowCount++)) ;;
            "$INFO") ((infoCount++)) ;;
        esac
    done
    
    echo "Findings Summary:" >> "$blueprintFile"
    echo "Critical: $criticalCount" >> "$blueprintFile"
    echo "High: $highCount" >> "$blueprintFile"
    echo "Medium: $mediumCount" >> "$blueprintFile"
    echo "Low: $lowCount" >> "$blueprintFile"
    echo "Info: $infoCount" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    # Privilege Escalation Vectors
    echo "IDENTIFIED PRIVILEGE ESCALATION VECTORS" >> "$blueprintFile"
    echo "=======================================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    if [ ${#privEscVectors[@]} -gt 0 ]; then
        for vector in "${privEscVectors[@]}"; do
            IFS='|' read -r name description severity exploitation <<< "$vector"
            echo "[$severity] $name" >> "$blueprintFile"
            echo "  - $description" >> "$blueprintFile"
            echo "  - Exploitation: $exploitation" >> "$blueprintFile"
            echo "" >> "$blueprintFile"
        done
    else
        echo "No clear privilege escalation vectors were identified." >> "$blueprintFile"
        echo "" >> "$blueprintFile"
    fi
    
    # Detailed Findings by Severity
    echo "DETAILED FINDINGS" >> "$blueprintFile"
    echo "=================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    # Critical Findings
    echo "CRITICAL SEVERITY FINDINGS" >> "$blueprintFile"
    echo "=========================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    local criticalFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation <<< "$anomaly"
        if [ "$severity" = "$CRITICAL" ]; then
            criticalFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            echo "" >> "$blueprintFile"
        fi
    done
    
    if [ "$criticalFound" = false ]; then
        echo "No critical severity findings identified." >> "$blueprintFile"
        echo "" >> "$blueprintFile"
    fi
    
    # High Severity Findings
    echo "HIGH SEVERITY FINDINGS" >> "$blueprintFile"
    echo "=====================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    local highFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation <<< "$anomaly"
        if [ "$severity" = "$HIGH" ]; then
            highFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            echo "" >> "$blueprintFile"
        fi
    done
    
    if [ "$highFound" = false ]; then
        echo "No high severity findings identified." >> "$blueprintFile"
        echo "" >> "$blueprintFile"
    fi
    
    # Medium Severity Findings
    echo "MEDIUM SEVERITY FINDINGS" >> "$blueprintFile"
    echo "=======================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    local mediumFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation <<< "$anomaly"
        if [ "$severity" = "$MEDIUM" ]; then
            mediumFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            echo "" >> "$blueprintFile"
        fi
    done
    
    if [ "$mediumFound" = false ]; then
        echo "No medium severity findings identified." >> "$blueprintFile"
        echo "" >> "$blueprintFile"
    fi
    
    # Low Severity Findings
    echo "LOW SEVERITY FINDINGS" >> "$blueprintFile"
    echo "====================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    local lowFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation <<< "$anomaly"
        if [ "$severity" = "$LOW" ]; then
            lowFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            echo "" >> "$blueprintFile"
        fi
    done
    
    if [ "$lowFound" = false ]; then
        echo "No low severity findings identified." >> "$blueprintFile"
        echo "" >> "$blueprintFile"
    fi
    
    # System Information
    echo "SYSTEM INFORMATION" >> "$blueprintFile"
    echo "=================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    echo "Kernel: $(uname -r)" >> "$blueprintFile"
    echo "OS: $(cat /etc/issue 2>/dev/null)" >> "$blueprintFile"
    echo "User: $(id)" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    # Scan Summary
    echo "SCAN SUMMARY" >> "$blueprintFile"
    echo "===========" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    echo "Total checks performed: ${#searchPatterns[@]}" >> "$blueprintFile"
    echo "Total findings: ${#anomalies[@]}" >> "$blueprintFile"
    echo "Scan completed at $(date)" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    echo "\"Remember: All I'm offering is the truth, nothing more.\"" >> "$blueprintFile"
}

# Main function to orchestrate the execution
main() {
    # Show the banner
    showBanner
    
    # Parse command line arguments
    parseArgs "$@"
    
    # If help flag is provided, only show help and exit
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        morpheusGuide
        exit 0
    fi
    
    # Initialize arrays
    anomalies=()
    searchPatterns=()
    privEscVectors=()
    
    echo -e "${MATRIX_GREEN}Matrix scan started at $(date)${NC}"
    echo -e "${GREEN}Taking the red pill to show you how deep the rabbit hole goes...${NC}"
    echo ""
    
    # Call all analysis functions in sequence
    analyzeMatrixCore
    analyzeDrives
    analyzePrograms
    analyzeNetwork
    analyzeIdentities
    analyzeActivePrograms
    analyzePermissions
    analyzeScheduledTasks
    analyzeSystemServices
    analyzeCommChannels
    analyzeSpecialPermissions
    analyzeCapabilities
    analyzeACLs
    analyzeShellSessions
    analyzeSecureAccess
    analyzeValuableFiles
    analyzeWritableFiles
    
    # Generate executive summary for the console
    echo ""
    generateExecutiveSummary
    
    # Generate a detailed text report
    generateTextReport
    
    # Generate HTML report if requested
    if [ "$generateHtml" = true ]; then
        generateHtmlReport
    fi
    
    echo ""
    echo -e "${MATRIX_GREEN}Matrix scan complete. Results saved to: $blueprintFile${NC}"
    if [ "$generateHtml" = true ]; then
        echo -e "${MATRIX_GREEN}HTML report saved to: $htmlReport${NC}"
    fi
    echo -e "${MATRIX_GREEN}Remember: All I'm offering is the truth, nothing more.${NC}"
}

# Execute the main function with all arguments
main "$@"
