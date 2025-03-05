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
NC='\033[0m' # No Color
MATRIX_GREEN='\033[38;5;46m'

# Global variables
redPill=false # Verbose mode (red pill shows you how deep the rabbit hole goes)
blueprintFile="matrixscan_report.txt" # Report file (the blueprint of the Matrix)
anomalies=() # Found vulnerabilities (anomalies in the Matrix)
searchPatterns=() # Checklist (patterns to search for in the Matrix)

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
    echo ""
    echo "\"I can only show you the door. You're the one that has to walk through it.\""
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
    
    anomalies+=("${anomaly}|${detail}")
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
        addToAnomalies "Kernel Exploit" "Kernel version 2.6.x detected, potentially vulnerable to DirtyCow (CVE-2016-5195) - a significant glitch in the Matrix"
    fi
    
    if [[ "$kernelVersion" =~ ^3\.1[0-9]\. ]]; then
        addToAnomalies "Kernel Exploit" "Kernel version 3.1x.x detected, potentially vulnerable to overlayfs (CVE-2015-1328) - a path to become The One"
    fi
    
    if [[ "$kernelVersion" =~ ^4\.[0-9]\. ]]; then
        addToAnomalies "Kernel Exploit" "Kernel version 4.x.x detected, check for eBPF or other 4.x kernel exploits - potential glitches to exploit"
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
            addToAnomalies "Writable PATH" "Directory in PATH is writable: $directory - can be used to bend the rules of the Matrix"
        fi
    done <<< "$pathInfo"
    
    addToPattern "Writable PATH Check" "ANALYZED" ""
    
    # Environment variables
    logMessage "SUBSECTION" "Environment Variables (Matrix Code Parameters)"
    envInfo=$(interrogateMatrix "env")
    showWithRedPill "$envInfo"
    
    # Check for sensitive information in environment variables
    if echo "$envInfo" | grep -i "key\|password\|secret\|token\|credential" > /dev/null; then
        addToAnomalies "Sensitive Environment Variables" "Found sensitive information in environment variables - access keys to restricted Matrix areas"
    fi
    
    addToPattern "Environment Variables Check" "ANALYZED" ""
    
    # sudo version
    logMessage "SUBSECTION" "Sudo Version (Agent Program Version)"
    sudoVersion=$(interrogateMatrix "sudo -V | head -n 1")
    echo "$sudoVersion"
    
    # Check for vulnerable sudo versions
    if [[ "$sudoVersion" =~ 1\.8\.[0-9]\. ]]; then
        addToAnomalies "Sudo Vulnerability" "Sudo version potentially vulnerable to CVE-2019-14287 (sudo < 1.8.28) - an Agent weakness"
    fi
    
    if [[ "$sudoVersion" =~ 1\.8\.2[0-7] ]]; then
        addToAnomalies "Sudo Vulnerability" "Sudo version potentially vulnerable to CVE-2019-18634 (sudo < 1.8.26) - another Agent weakness"
    fi
    
    addToPattern "Sudo Version Check" "ANALYZED" "$sudoVersion"
    
    # Signature verification
    logMessage "SUBSECTION" "Signature Verification (Matrix Authentication)"
    dmesgSig=$(interrogateMatrix "dmesg | grep -i \"signature\"")
    if [[ "$dmesgSig" == *"signature verification failed"* ]]; then
        addToAnomalies "Signature Verification Failed" "System may be vulnerable to module loading exploits - a door in the Matrix"
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
        addToAnomalies "NFS no_root_squash" "Found NFS share with no_root_squash option - a backdoor in the Matrix"
    fi
    
    addToPattern "Mounted Drives Check" "ANALYZED" ""
    
    # Check for unmounted drives
    logMessage "SUBSECTION" "Unmounted Drives (Dormant Constructs)"
    if [ -f "/etc/fstab" ]; then
        fstabEntries=$(interrogateMatrix "cat /etc/fstab")
        showWithRedPill "$fstabEntries"
        
        # Check for credentials in fstab
        if echo "$fstabEntries" | grep -i "user\|password\|credentials" > /dev/null; then
            addToAnomalies "FSTAB Credentials" "Found credentials in /etc/fstab - keys to unlock Matrix doors"
        fi
        
        # Look for unmounted drives
        currentMounts=$(mount | awk '{print $1}')
        while read -r line; do
            if [[ $line =~ ^[^#] ]]; then
                device=$(echo "$line" | awk '{print $1}')
                if ! echo "$currentMounts" | grep -q "$device"; then
                    addToAnomalies "Unmounted Drive" "Drive in fstab not currently mounted: $device - an abandoned construct"
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
            showWithRedPill "Found useful software: $software ($(which "$software")) - a tool that can manipulate the Matrix"
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
        showWithRedPill "Debian packages installed - many Matrix programs detected"
    fi
    
    # For Red Hat-based systems
    rpmPackages=$(interrogateMatrix "rpm -qa")
    if [ ! -z "$rpmPackages" ]; then
        showWithRedPill "RPM packages installed - many Matrix programs detected"
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
        addToAnomalies "Open Ports" "Found potentially interesting listening ports - open doors to the Matrix"
    fi
    
    addToPattern "Active Connections Check" "ANALYZED" ""
    
    # Network Manager
    logMessage "SUBSECTION" "Network Manager Credentials (Access Codes)"
    nmConnections=$(interrogateMatrix "cat /etc/NetworkManager/system-connections/* 2>/dev/null | grep -E \"^id|^psk\"")
    
    if [ ! -z "$nmConnections" ]; then
        showWithRedPill "$nmConnections"
        addToAnomalies "Network Manager Credentials" "Found credentials in Network Manager connections - passwords to Matrix networks"
    fi
    
    addToPattern "Network Manager Credentials Check" "ANALYZED" ""
    
    # Check if we can sniff traffic
    logMessage "SUBSECTION" "Network Sniffing (Watching the Matrix Code)"
    if command -v tcpdump &> /dev/null; then
        showWithRedPill "tcpdump is available, potentially can sniff traffic - ability to see the green code"
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
        addToAnomalies "Root Equivalent Users" "Found users with UID 0 (root equivalent): $rootUsers - multiple 'Ones' in the Matrix"
    fi
    
    addToPattern "Users with UID 0 Check" "ANALYZED" ""
    
    # Check for high UID (potential CVE-2021-4034 - PwnKit)
    myUID=$(id -u)
    if [ "$myUID" -gt 1000000 ]; then
        addToAnomalies "High UID" "Current user has a very high UID ($myUID), potential PwnKit vulnerability - a Prime Program anomaly"
    fi
    
    # Check if current user belongs to interesting groups
    groups=$(groups)
    
    for group in docker disk lxd adm sudo wheel admin; do
        if echo "$groups" | grep -w "$group" > /dev/null; then
            addToAnomalies "Privileged Group" "Current user belongs to privileged group: $group - membership in a powerful Matrix faction"
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
            showWithRedPill "Found clipboard data - residual code fragments"
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
            showWithRedPill "Found interesting process: $process - a significant Matrix program"
            addToAnomalies "Interesting Process" "Found $process process running - potential gateway program"
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
        addToAnomalies "Privileged Process" "Found processes potentially running with elevated privileges - Agent programs"
    fi
    addToPattern "Process Privileges Check" "ANALYZED" ""
    
    # Check process memory for credentials
    logMessage "SUBSECTION" "Process Memory (Program Code Storage)"
    if command -v strings &> /dev/null; then
        showWithRedPill "strings command is available for memory inspection - tool to read the Matrix code directly"
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
        addToAnomalies "Shadow File Access" "Current user can read /etc/shadow - can see through the Matrix shadows"
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
            addToAnomalies "Interesting SUID Binary" "Found SUID binary: $binary - a program that can bend the Matrix rules"
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
            addToAnomalies "Writable Critical File" "Found writable critical file: $file - a mutable Matrix control file"
        fi
    done
    
    addToPattern "World-Writable Files Check" "ANALYZED" ""
    
    # Check configuration files for passwords
    logMessage "SUBSECTION" "Configuration Files with Sensitive Information (Access Code Storage)"
    passInConf=$(interrogateMatrix "grep -l 'pass' /etc/*.conf 2>/dev/null")
    keyInConf=$(interrogateMatrix "grep -l 'key' /etc/*.conf 2>/dev/null")
    secretInConf=$(interrogateMatrix "grep -l 'secret' /etc/*.conf 2>/dev/null")
    
    if [ ! -z "$passInConf" ] || [ ! -z "$keyInConf" ] || [ ! -z "$secretInConf" ]; then
        addToAnomalies "Sensitive Information in Config Files" "Found configuration files with sensitive information - Matrix access codes stored in plain sight"
    fi
    
    addToPattern "Configuration Files Check" "ANALYZED" ""
    
    # Can we list contents of root directory?
    logMessage "SUBSECTION" "Root Directory Access (The One's Home)"
    rootDirAccess=$(interrogateMatrix "ls -als /root/")
    
    if [ ! -z "$rootDirAccess" ]; then
        showWithRedPill "$rootDirAccess"
        addToAnomalies "Root Directory Access" "Current user can list contents of /root/ - can see into The One's domain"
    fi
    
    addToPattern "Root Directory Access Check" "ANALYZED" ""
    
    # History files
    logMessage "SUBSECTION" "History Files (Command Memories)"
    historyFiles=$(interrogateMatrix "find /* -name *.*history* -print 2>/dev/null")
    showWithRedPill "$historyFiles"
    
    if [ ! -z "$historyFiles" ]; then
        addToAnomalies "History Files" "Found history files which may contain sensitive information - archived Matrix interactions"
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
        addToAnomalies "Writable Cron Jobs" "Found world-writable cron jobs - Matrix events that can be reprogrammed"
    fi
    
    addToPattern "World-Writable Cron Jobs Check" "ANALYZED" ""
    
    # Check for PATH modification in cron
    if echo "$systemCron" | grep "PATH" > /dev/null; then
        cronPath=$(echo "$systemCron" | grep "PATH" | head -1)
        showWithRedPill "Cron PATH: $cronPath - the path for scheduled Matrix events"
        
        # Extract directories from the PATH
        cronPathDirs=$(echo "$cronPath" | cut -d= -f2 | tr ":" "\n")
        
        while IFS= read -r directory; do
            if [ -w "$directory" ]; then
                addToAnomalies "Writable Cron PATH" "Directory in cron PATH is writable: $directory - can manipulate the Matrix scheduler's path"
            fi
        done <<< "$cronPathDirs"
    fi
    
    addToPattern "Cron PATH Check" "ANALYZED" ""
    
    # Check for wildcard usage in cron jobs
    if echo "$systemCron" | grep -E '[*]' | grep -v "^#" | grep -v "^[0-9].*[*]" > /dev/null; then
        addToAnomalies "Cron Wildcard" "Found potential wildcard usage in cron jobs - a Matrix wildcard vulnerability"
    fi
    
    addToPattern "Cron Wildcard Check" "ANALYZED" ""
    
    # Frequently running cron jobs (potential targets)
    logMessage "SUBSECTION" "Frequently Running Cron Jobs (Rapid Matrix Events)"
    frequentCrons=$(echo "$systemCron" | grep -E "^[*]|^[0-9][0-9]?/[0-9]|^[*]/[0-9]" | grep -v "^#")
    if [ ! -z "$frequentCrons" ]; then
        showWithRedPill "$frequentCrons"
        addToAnomalies "Frequent Cron Jobs" "Found cron jobs that run frequently - quick-cycle Matrix events"
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
            addToAnomalies "Writable Service Files" "Found writable systemd service files - modifiable Matrix service definitions"
        }
        
        # Check for writable binaries executed by services
        logMessage "SUBSECTION" "Service Binaries (Service Executables)"
        serviceFiles=$(interrogateMatrix "find /etc/systemd/system -name \"*.service\" -exec cat {} \; 2>/dev/null | grep -E \"^ExecStart=\" | cut -d= -f2")
        
        for binary in $serviceFiles; do
            if [ -w "$binary" ]; then
                addToAnomalies "Writable Service Binary" "Found writable binary executed by a service: $binary - an alterable Matrix service"
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
            addToAnomalies "Writable Timer Files" "Found writable systemd timer files - modifiable Matrix timers"
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
        addToAnomalies "Writable Socket Files" "Found writable systemd socket files - modifiable Matrix connection points"
    fi
    
    # Check for HTTP sockets
    httpSockets=$(interrogateMatrix "netstat -an | grep -i \"http\"")
    if [ ! -z "$httpSockets" ]; then
        showWithRedPill "$httpSockets"
        addToAnomalies "HTTP Sockets" "Found HTTP sockets that might contain interesting information - web portals in the Matrix"
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
                addToAnomalies "Interesting Sudo Permission" "Can execute $cmd with sudo (potential GTFOBins vector) - a program that can bend the Matrix rules"
            fi
        done
        
        # Check for sudo commands without full path
        if echo "$sudoPerms" | grep -E "\([a-zA-Z0-9_-]+\) NOPASSWD: [^/]" > /dev/null; then
            addToAnomalies "Sudo Without Path" "Found sudo permissions for commands without full path - a path manipulation vulnerability"
        fi
        
        # Check for ALL permission
        if echo "$sudoPerms" | grep "ALL" > /dev/null; then
            addToAnomalies "Sudo ALL Permission" "User has ALL sudo permissions - has powers of The One"
        fi
        
        # Check for NOPASSWD
        if echo "$sudoPerms" | grep "NOPASSWD" > /dev/null; then
            addToAnomalies "Sudo NOPASSWD" "User has NOPASSWD sudo permissions - no access code needed for elevation"
        fi
        
        # Check for LD_PRELOAD in env_keep
        if echo "$sudoPerms" | grep "LD_PRELOAD" > /dev/null; then
            addToAnomalies "Sudo LD_PRELOAD" "LD_PRELOAD is kept in sudo, potential for privilege escalation - a way to inject code into the Matrix"
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
            addToAnomalies "Writable Sudoers Files" "Found writable sudoers files: $sudoersWritable - editable access control files"
        fi
    fi
    
    addToPattern "Sudoers Files Check" "ANALYZED" ""
    
    # Check for sudo token reuse
    logMessage "SUBSECTION" "Sudo Token Reuse (Access Token Hijacking)"
    sudoToken=$(interrogateMatrix "find /var/run/sudo -name \"*$USER*\" 2>/dev/null")
    
    if [ ! -z "$sudoToken" ]; then
        showWithRedPill "$sudoToken"
        addToAnomalies "Sudo Token Reuse" "Found sudo token for current user - an active access token"
    fi
    
    addToPattern "Sudo Token Reuse Check" "ANALYZED" ""
    
    # Check for OpenBSD DOAS (alternative to sudo)
    if [ -f "/etc/doas.conf" ]; then
        logMessage "SUBSECTION" "OpenBSD DOAS (Alternate Access Control)"
        doasConf=$(interrogateMatrix "cat /etc/doas.conf")
        showWithRedPill "$doasConf"
        
        if [ ! -z "$doasConf" ]; then
            addToAnomalies "DOAS Configuration" "System uses DOAS, check configuration for privilege escalation - alternative pathway to elevation"
        fi
    fi
    
    addToPattern "DOAS Check" "ANALYZED" ""
    
    # Check for writable /etc/ld.so.conf.d/
    if [ -d "/etc/ld.so.conf.d/" ]; then
        ldsoConfWritable=$(interrogateMatrix "find /etc/ld.so.conf.d/ -writable 2>/dev/null")
        if [ ! -z "$ldsoConfWritable" ]; then
            addToAnomalies "Writable ld.so.conf.d" "Found writable files in /etc/ld.so.conf.d/ - library path manipulation opportunity"
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
                    addToAnomalies "Interesting Capability" "Found file with $cap capability - a program with special Matrix abilities"
                fi
            done
        fi
    else
        logMessage "WARNING" "getcap not available, skipping capabilities check - cannot identify special abilities"
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
                showWithRedPill "Found ACLs on $dir - specialized access rules"
                # Look for unusual ACLs (this is a simple check)
                if echo "$aclInfo" | grep -E "user:[^:]+:rwx|group:[^:]+:rwx" > /dev/null; then
                    addToAnomalies "Interesting ACL" "Found ACL with full rwx permissions on $dir - a path with unusual permissions"
                fi
            fi
        done
    else
        logMessage "WARNING" "getfacl not available, skipping ACL check - cannot identify specialized permissions"
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
        addToAnomalies "Screen Sessions" "Found active screen sessions - persistent terminals you might hijack"
    fi
    addToPattern "Screen Sessions Check" "ANALYZED" ""
    
    # Check for tmux sessions
    logMessage "SUBSECTION" "Tmux Sessions (Multi-Terminals)"
    tmuxSessions=$(interrogateMatrix "tmux list-sessions 2>/dev/null")
    if [ ! -z "$tmuxSessions" ]; then
        showWithRedPill "$tmuxSessions"
        addToAnomalies "Tmux Sessions" "Found active tmux sessions - another form of persistent terminals"
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
        addToAnomalies "SSH Keys" "Found SSH keys that may allow unauthorized access - keys to other Matrix systems"
    }
    addToPattern "SSH Keys Check" "ANALYZED" ""
    
    # Check SSH configuration
    logMessage "SUBSECTION" "SSH Configuration (Secure Shell Settings)"
    sshConfig=$(interrogateMatrix "cat /etc/ssh/sshd_config 2>/dev/null")
    if [ ! -z "$sshConfig" ]; then
        showWithRedPill "$sshConfig"
        
        # Check for interesting SSH configuration values
        if echo "$sshConfig" | grep -i "PermitRootLogin yes" > /dev/null; then
            addToAnomalies "SSH Root Login" "Root login is allowed via SSH - The One can connect directly"
        fi
        
        if echo "$sshConfig" | grep -i "PasswordAuthentication yes" > /dev/null; then
            addToAnomalies "SSH Password Auth" "Password authentication is enabled for SSH - access codes can be used for login"
        fi
    }
    
    # Check for Debian OpenSSL Predictable PRNG (CVE-2008-0166)
    if [ -f "/etc/debian_version" ]; then
        sshVersion=$(ssh -V 2>&1)
        if [[ "$sshVersion" =~ OpenSSH_4 ]] || [[ "$sshVersion" =~ OpenSSH_5.0 ]]; then
            addToAnomalies "Debian OpenSSL Vulnerability" "Potentially vulnerable to CVE-2008-0166 (Predictable PRNG) - a predictable Matrix randomness flaw"
        fi
    }
    
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
        addToAnomalies "Writable Profile Files" "Found writable profile files that can be used for privilege escalation - modifiable environment scripts"
    }
    
    addToPattern "Profile Files Check" "ANALYZED" ""
    
    # Check passwd/shadow files
    logMessage "SUBSECTION" "Password Files (Identity Storage)"
    passwdWritable=$(interrogateMatrix "find /etc/passwd -writable 2>/dev/null")
    shadowWritable=$(interrogateMatrix "find /etc/shadow -writable 2>/dev/null")
    
    if [ ! -z "$passwdWritable" ]; then
        addToAnomalies "Writable passwd File" "The /etc/passwd file is writable - can create new Matrix identities"
    }
    
    if [ ! -z "$shadowWritable" ]; then
        addToAnomalies "Writable shadow File" "The /etc/shadow file is writable - can modify access codes"
    }
    
    addToPattern "Password Files Check" "ANALYZED" ""
    
    # Check commonly interesting folders
    logMessage "SUBSECTION" "Interesting Folders (Important Data Locations)"
    interestingFolders="/tmp /var/tmp /dev/shm /var/www /var/backups /opt /usr/local/bin"
    
    for folder in $interestingFolders; do
        if [ -d "$folder" ]; then
            folderContents=$(interrogateMatrix "ls -la $folder 2>/dev/null")
            showWithRedPill "Contents of $folder - a significant Matrix location:"
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
            showWithRedPill "Executables in $dir - commands available in the Matrix:"
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

# Check for writable files (mutable objects in the Matrix)
analyzeWritableFiles() {
    logMessage "SECTION" "Writable Files (Mutable Matrix Objects)"
    
    # Check for writable Python libraries
    logMessage "SUBSECTION" "Python Libraries (Scripting Libraries)"
    pythonPath=$(interrogateMatrix "python -c 'import sys; print(sys.path)' 2>/dev/null || python3 -c 'import sys; print(sys.path)' 2>/dev/null")
    
    if [ ! -z "$pythonPath" ]; then
        showWithRedPill "Python path: $pythonPath - locations of Python Matrix modules"
        
        # Extract paths from Python path
        pythonPaths=$(echo "$pythonPath" | tr -d "[],' " | tr ":" "\n")
        
        for path in $pythonPaths; do
            if [ -d "$path" ]; then
                writablePyLibs=$(interrogateMatrix "find $path -writable -name \"*.py\" 2>/dev/null")
                if [ ! -z "$writablePyLibs" ]; then
                    showWithRedPill "$writablePyLibs"
                    addToAnomalies "Writable Python Libraries" "Found writable Python libraries - can modify Matrix programming"
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
        addToAnomalies "Writable Log Files" "Found writable log files (potential LogRotate exploit) - can manipulate the Matrix event logs"
    fi
    
    addToPattern "Writable Log Files Check" "ANALYZED" ""
    
    # Check for writable network-scripts (CentOS/RHEL)
    if [ -d "/etc/sysconfig/network-scripts" ]; then
        logMessage "SUBSECTION" "Network Scripts (Network Configuration)"
        writableNetScripts=$(interrogateMatrix "find /etc/sysconfig/network-scripts -writable 2>/dev/null")
        
        if [ ! -z "$writableNetScripts" ]; then
            showWithRedPill "$writableNetScripts"
            addToAnomalies "Writable Network Scripts" "Found writable files in /etc/sysconfig/network-scripts/ (CentOS/RHEL exploit) - can alter Matrix network controls"
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
        
        addToAnomalies "Writable Init Scripts" "Found writable initialization scripts - can alter Matrix startup processes"
    fi
    
    addToPattern "Init Scripts Check" "ANALYZED" ""
}

# Check for NFS shares and other tricks (special Matrix exploits)
analyzeSpecialExploits() {
    logMessage "SECTION" "Other Tricks (Special Matrix Exploits)"
    
    # Check for NFS shares
    logMessage "SUBSECTION" "NFS Shares (Network Filesystems)"
    nfsShares=$(interrogateMatrix "showmount -e 127.0.0.1 2>/dev/null")
    
    if [ ! -z "$nfsShares" ]; then
        showWithRedPill "$nfsShares"
        addToAnomalies "NFS Shares" "Found NFS shares that might be exploitable - external Matrix connections"
    }
    
    addToPattern "NFS Shares Check" "ANALYZED" ""
    
    # Check if we're in a restricted shell
    logMessage "SUBSECTION" "Restricted Shell (Limited Terminal)"
    if [ -z "$BASH" ] || [ "$SHELL" != "/bin/bash" ]; then
        currentShell=$(echo $SHELL)
        showWithRedPill "Current shell: $currentShell - a restricted Matrix interface"
        addToAnomalies "Restricted Shell" "User might be in a restricted shell - trapped in a Matrix construct"
    fi
    
    addToPattern "Restricted Shell Check" "ANALYZED" ""
}

# Generate final report - Summarizing what we found in the Matrix
generateBlueprint() {
    logMessage "SECTION" "MatrixScan Report Summary"
    
    # Report vulnerabilities (Matrix anomalies)
    logMessage "SUBSECTION" "Potential Vulnerabilities (Matrix Anomalies)"
    
    if [ ${#anomalies[@]} -eq 0 ]; then
        logMessage "INFO" "No potential vulnerabilities found - Matrix integrity appears intact"
    else
        for anomaly in "${anomalies[@]}"; do
            IFS="|" read -r type detail <<< "$anomaly"
            logMessage "ANOMALY" "$type: $detail"
        done
    fi
    
    # Report checklist (patterns we've analyzed)
    logMessage "SUBSECTION" "Checklist Summary (Analyzed Matrix Patterns)"
    
    for item in "${searchPatterns[@]}"; do
        IFS="|" read -r check status detail <<< "$item"
        if [ -z "$detail" ]; then
            logMessage "INFO" "[$status] $check"
        else
            logMessage "INFO" "[$status] $check: $detail"
        fi
    done
    
    # Privilege escalation paths (ways to escape the Matrix)
    logMessage "SECTION" "Common Privilege Escalation Paths (Ways to Break Free)"
    
    logMessage "INFO" "1. Kernel Exploits - Identify and exploit kernel vulnerabilities (DirtyCow, overlayfs, etc.) - 'There is a difference between knowing the path and walking the path'"
    logMessage "INFO" "2. Sudo Misconfiguration - Abusing sudo privileges, NOPASSWD options, or sudo tokens - 'What you know you can't explain, but you feel it'"
    logMessage "INFO" "3. SUID Binaries - Exploiting SUID binaries via GTFOBins (nmap, vim, find, etc.) - 'Free your mind'"
    logMessage "INFO" "4. Writable Files - Modifying service files, cron jobs, or other critical files - 'The Matrix is a system. That system is our enemy'"
    logMessage "INFO" "5. Cron Jobs - Exploiting writable cron jobs, PATH abuse, or wildcards - 'Everything that has a beginning has an end'"
    logMessage "INFO" "6. Capabilities - Using capabilities like cap_setuid to escalate privileges - 'I can only show you the door. You're the one that has to walk through it'"
    logMessage "INFO" "7. Group Memberships - Leveraging docker, lxd, wheel, sudo, adm groups - 'Welcome to the real world'"
    logMessage "INFO" "8. NFS Shares - Exploiting no_root_squash to gain root privileges - 'There is no spoon'"
    logMessage "INFO" "9. Passwords in Files - Finding credentials in config files, history, or memory - 'The Matrix is everywhere. It is all around us'"
    logMessage "INFO" "10. Environment Variables - Exploiting LD_PRELOAD or LD_LIBRARY_PATH - 'Unfortunately, no one can be told what the Matrix is. You have to see it for yourself'"
    logMessage "INFO" "11. Service Exploits - Finding vulnerable versions of services (MySQL, Apache, etc.) - 'You take the red pill, and I show you how deep the rabbit hole goes'"
    logMessage "INFO" "12. Python Library Hijacking - Modifying writable Python libraries used by privileged processes - 'The Matrix has you'"
    logMessage "INFO" "13. Log Files Exploitation - Using techniques like Logtotten to inject code - 'Follow the white rabbit'"
    
    logMessage "SECTION" "MatrixScan Completed"
    
    echo ""
    echo -e "${MATRIX_GREEN}Blueprint saved to: ${blueprintFile}${NC}"
    echo -e "${MATRIX_GREEN}Remember: 'Red pill for your system'${NC}"
}

# Main function - The entrypoint to our Matrix scanning journey
main() {
    showBanner
    parseArgs "$@"
    
    # Initialize report file (The Matrix blueprint)
    echo "" > "$blueprintFile"
    
    echo -e "${MATRIX_GREEN}[*] Jacking into the Matrix... scanning for vulnerabilities...${NC}"
    echo ""
    
    # Run all checks - Analyze every aspect of the Matrix
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
    analyzeSpecialExploits
    
    # Generate final report - Create the Matrix blueprint
    generateBlueprint
}

# Run main function - Begin our journey into the Matrix
main "$@"
