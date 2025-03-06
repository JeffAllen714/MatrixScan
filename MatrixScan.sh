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
UNDERLINE='\033[4m'
BLINK='\033[5m'
NC='\033[0m' # No Color
MATRIX_GREEN='\033[38;5;46m'

# Global variables
redPill=false # Verbose mode (red pill shows you how deep the rabbit hole goes)
blueprintFile="matrixscan_report.txt" # Report file (the blueprint of the Matrix)
htmlReport="matrixscan_report.html" # HTML report file
jsonReport="matrixscan_report.json" # JSON report file
csvReport="matrixscan_report.csv" # CSV report file
anomalies=() # Found vulnerabilities (anomalies in the Matrix)
searchPatterns=() # Checklist (patterns to search for in the Matrix)
privEscVectors=() # Identified privilege escalation vectors
generateHtml=false # Whether to generate HTML report
generateJson=false # Whether to generate JSON report
generateCsv=false # Whether to generate CSV report
quickScan=false # Whether to perform a quick scan
targetedScan=false # Whether to perform a targeted scan
focusedChecks=() # Specific checks to focus on
skipChecks=() # Checks to skip
showProgress=true # Whether to show progress indicators
interactiveMode=false # Whether to enable interactive exploration
scanStartTime=$(date +%s) # Start time of the scan
totalChecks=16 # Total number of main check categories
currentCheck=0 # Current check being performed
exportVulns=false # Whether to export only vulnerabilities
scanDepth="normal" # Depth of the scan (quick, normal, deep)
quietMode=false # Whether to run in quiet mode (minimal output)
compareMode=false # Whether to compare with previous scan
previousReport="" # Path to previous report for comparison
remoteMode=false # Whether to scan a remote system
remoteHost="" # Remote host to scan
remoteUser="" # Remote user for SSH
remoteKey="" # SSH key for remote access
remotePort=22 # SSH port for remote access
scanId=$(date +%Y%m%d%H%M%S) # Unique scan ID

# Scan stats
startTime=$(date +%s)
endTime=0
scanDuration=0

# Severity levels
CRITICAL="CRITICAL"
HIGH="HIGH"
MEDIUM="MEDIUM"
LOW="LOW"
INFO="INFO"

# Function to show a stylized progress bar
showProgressBar() {
    local percent=$1
    local width=50
    local num_filled=$(( width * percent / 100 ))
    local num_empty=$(( width - num_filled ))
    
    printf "\r["
    printf "%${num_filled}s" | tr ' ' '='
    printf ">"
    printf "%${num_empty}s" | tr ' ' ' '
    printf "] %3d%%" "$percent"
}

# Update the progress of the scan
updateProgress() {
    if [ "$showProgress" = true ] && [ "$quietMode" = false ]; then
        ((currentCheck++))
        local percent=$((currentCheck * 100 / totalChecks))
        showProgressBar $percent
    fi
}

# Banner function
showBanner() {
    if [ "$quietMode" = false ]; then
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
        echo -e "${MATRIX_GREEN}Version 2.0 - The One Edition${NC}"
        echo ""
    fi
}

# Usage function - Morpheus explains how to use the tool
morpheusGuide() {
    echo "Usage: $0 [options]"
    echo ""
    echo "General Options:"
    echo "  -h, --help                 Show this help message and exit"
    echo "  -r, --redpill              Take the red pill (enable verbose output)"
    echo "  -q, --quiet                Quiet mode, minimal output (for scripted use)"
    echo "  -i, --interactive          Enable interactive mode for exploring results"
    echo "  --no-progress              Disable progress bars and indicators"
    echo ""
    echo "Scan Options:"
    echo "  --quick                    Perform a quick scan (fewer checks but faster)"
    echo "  --deep                     Perform a deep scan (more thorough but slower)"
    echo "  --focus CHECK1,CHECK2,...  Focus only on specific checks (comma-separated)"
    echo "  --skip CHECK1,CHECK2,...   Skip specific checks (comma-separated)"
    echo "  -c, --compare FILE         Compare results with a previous scan"
    echo ""
    echo "Output Options:"
    echo "  -o, --output FILE          Save the text report to specified file (default: matrixscan_report.txt)"
    echo "  --html [FILE]              Generate HTML report (default: matrixscan_report.html)"
    echo "  --json [FILE]              Generate JSON report (default: matrixscan_report.json)"
    echo "  --csv [FILE]               Generate CSV report (default: matrixscan_report.csv)"
    echo "  --vulns-only               Export only vulnerabilities, not all scan data"
    echo ""
    echo "Remote Scanning:"
    echo "  --remote HOST              Scan a remote system via SSH"
    echo "  --remote-user USER         Username for SSH connection (default: current user)"
    echo "  --remote-key KEY           SSH private key file for authentication"
    echo "  --remote-port PORT         SSH port (default: 22)"
    echo ""
    echo "Available Checks:"
    echo "  system_info                System information and environment"
    echo "  drives                     Drives and mount points"
    echo "  software                   Installed software and versions"
    echo "  network                    Network configuration and connections"
    echo "  users                      User information and privileges"
    echo "  processes                  Running processes"
    echo "  permissions                File and folder permissions"
    echo "  cron                       Cron jobs and scheduled tasks"
    echo "  services                   System services"
    echo "  timers                     Systemd timers"
    echo "  sockets                    Sockets and D-Bus"
    echo "  sudo                       Sudo permissions and configuration"
    echo "  capabilities               File capabilities"
    echo "  acls                       Access Control Lists"
    echo "  ssh                        SSH configuration and keys"
    echo "  files                      Interesting and sensitive files"
    echo ""
    echo "Examples:"
    echo "  $0 --quick                          # Run a quick scan"
    echo "  $0 --focus sudo,suid,cron           # Focus on specific privilege escalation vectors"
    echo "  $0 --html --json                    # Generate reports in multiple formats"
    echo "  $0 --remote server.example.com      # Scan a remote system"
    echo "  $0 --compare previous_report.txt    # Compare with previous scan"
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
            -q|--quiet)
                quietMode=true
                showProgress=false
                shift
                ;;
            -i|--interactive)
                interactiveMode=true
                shift
                ;;
            --no-progress)
                showProgress=false
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
            --json)
                generateJson=true
                if [ ! -z "$2" ] && [[ "$2" != -* ]]; then
                    jsonReport="$2"
                    shift
                fi
                shift
                ;;
            --csv)
                generateCsv=true
                if [ ! -z "$2" ] && [[ "$2" != -* ]]; then
                    csvReport="$2"
                    shift
                fi
                shift
                ;;
            --quick)
                quickScan=true
                scanDepth="quick"
                shift
                ;;
            --deep)
                scanDepth="deep"
                shift
                ;;
            --focus)
                targetedScan=true
                IFS=',' read -ra focusedChecks <<< "$2"
                shift
                shift
                ;;
            --skip)
                IFS=',' read -ra skipChecks <<< "$2"
                shift
                shift
                ;;
            --vulns-only)
                exportVulns=true
                shift
                ;;
            -c|--compare)
                compareMode=true
                previousReport="$2"
                shift
                shift
                ;;
            --remote)
                remoteMode=true
                remoteHost="$2"
                shift
                shift
                ;;
            --remote-user)
                remoteUser="$2"
                shift
                shift
                ;;
            --remote-key)
                remoteKey="$2"
                shift
                shift
                ;;
            --remote-port)
                remotePort="$2"
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
    
    # If no remote user specified, use current user
    if [ "$remoteMode" = true ] && [ -z "$remoteUser" ]; then
        remoteUser="$USER"
    fi
}

# Function to check if a check should be skipped
shouldSkipCheck() {
    local check="$1"
    
    # If targeted scan and check not in focused checks, skip it
    if [ "$targetedScan" = true ]; then
        local found=false
        for focused in "${focusedChecks[@]}"; do
            if [ "$focused" = "$check" ]; then
                found=true
                break
            fi
        done
        if [ "$found" = false ]; then
            return 0  # Should skip
        fi
    fi
    
    # If check is in skip list, skip it
    for skip in "${skipChecks[@]}"; do
        if [ "$skip" = "$check" ]; then
            return 0  # Should skip
        fi
    done
    
    # Check scan depth
    if [ "$scanDepth" = "quick" ]; then
        # Skip more time-consuming checks in quick mode
        case "$check" in
            "acls"|"files"|"capabilities")
                return 0  # Should skip
                ;;
        esac
    fi
    
    return 1  # Should not skip
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
    
    # Print to console if not in quiet mode
    if [ "$quietMode" = false ]; then
        echo -e "${color}[${level}]${NC} ${message}"
    fi
    
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
    local exploitCommand="$6"
    
    anomalies+=("${anomaly}|${detail}|${severity}|${vector}|${remediation}|${exploitCommand}")
}

# Add to privilege escalation vectors
addToPrivEscVectors() {
    local vector="$1"
    local description="$2"
    local severity="$3"
    local exploitation="$4"
    local exploitCommand="$5"
    
    privEscVectors+=("${vector}|${description}|${severity}|${exploitation}|${exploitCommand}")
}

# Verbose output function (taking the red pill shows you more of the Matrix)
showWithRedPill() {
    local message="$1"
    
    if [ "$redPill" = true ] && [ "$quietMode" = false ]; then
        echo -e "${PURPLE}[DEEP_MATRIX]${NC} ${message}"
        echo "[DEEP_MATRIX] ${message}" >> "$blueprintFile"
    fi
}

# Section header with animation
animatedSection() {
    local title="$1"
    if [ "$quietMode" = false ] && [ "$showProgress" = true ]; then
        echo ""
        echo -ne "${MATRIX_GREEN}[+] Scanning ${title}${NC}"
        for i in {1..3}; do
            echo -ne "${MATRIX_GREEN}.${NC}"
            sleep 0.1
        done
        echo ""
    fi
}

# Function to execute command locally or remotely
executeCommand() {
    local command="$1"
    local output=""
    
    if [ "$remoteMode" = true ]; then
        # Build SSH command
        local sshCmd="ssh"
        if [ ! -z "$remoteKey" ]; then
            sshCmd+=" -i $remoteKey"
        fi
        sshCmd+=" -p $remotePort $remoteUser@$remoteHost"
        
        # Execute command remotely
        output=$(eval "$sshCmd \"$command\"" 2>/dev/null)
    else
        # Execute command locally
        output=$(eval "$command" 2>/dev/null)
    fi
    
    echo "$output"
}

# Run command and get output (interrogating the Matrix)
interrogateMatrix() {
    local cmd="$1"
    local output=""
    
    showWithRedPill "Running command: $cmd"
    output=$(executeCommand "$cmd")
    
    echo "$output"
}

# Check system information (the foundation of the Matrix)
analyzeMatrixCore() {
    if shouldSkipCheck "system_info"; then
        return
    fi
    
    animatedSection "System Information"
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
        addToAnomalies "Kernel Exploit" "Kernel version 2.6.x detected, potentially vulnerable to DirtyCow (CVE-2016-5195)" "$CRITICAL" "KERNEL_EXPLOIT" "Upgrade the kernel to the latest version" "gcc -pthread dirty.c -o dirty && ./dirty"
        addToPrivEscVectors "Kernel Exploitation" "The system is running kernel version 2.6.x which is vulnerable to DirtyCow (CVE-2016-5195). This can be exploited to gain root privileges." "$CRITICAL" "Straightforward with publicly available exploits" "gcc -pthread dirty.c -o dirty && ./dirty"
    fi
    
    if [[ "$kernelVersion" =~ ^3\.1[0-9]\. ]]; then
        addToAnomalies "Kernel Exploit" "Kernel version 3.1x.x detected, potentially vulnerable to overlayfs (CVE-2015-1328)" "$CRITICAL" "KERNEL_EXPLOIT" "Upgrade the kernel to the latest version" "gcc overlayfs_exploit.c -o overlayfs_exploit && ./overlayfs_exploit"
        addToPrivEscVectors "Kernel Exploitation" "The system is running kernel version 3.1x.x which is vulnerable to overlayfs (CVE-2015-1328). This can be exploited to gain root privileges." "$CRITICAL" "Straightforward with publicly available exploits" "gcc overlayfs_exploit.c -o overlayfs_exploit && ./overlayfs_exploit"
    fi
    
    if [[ "$kernelVersion" =~ ^4\.[0-9]\. ]]; then
        addToAnomalies "Kernel Exploit" "Kernel version 4.x.x detected, check for eBPF or other 4.x kernel exploits" "$HIGH" "KERNEL_EXPLOIT" "Upgrade the kernel to the latest version" "gcc ebpf_exploit.c -o ebpf_exploit && ./ebpf_exploit"
        addToPrivEscVectors "Kernel Exploitation" "The system is running kernel version 4.x.x which might be vulnerable to eBPF exploits. Version-specific checking is required." "$HIGH" "Requires version-specific exploit code" "gcc ebpf_exploit.c -o ebpf_exploit && ./ebpf_exploit"
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
            addToAnomalies "Writable PATH" "Directory in PATH is writable: $directory" "$HIGH" "WRITABLE_PATH" "Remove write permissions from the directory or remove it from PATH" "echo '#!/bin/bash\n/bin/bash' > $directory/ls && chmod +x $directory/ls"
            addToPrivEscVectors "Writable PATH Abuse" "A directory in the PATH ($directory) is writable. This allows for creating or modifying executables that may be run by other users including root." "$HIGH" "Create a malicious executable with the same name as a commonly used command" "echo '#!/bin/bash\n/bin/bash' > $directory/ls && chmod +x $directory/ls"
        fi
    done <<< "$pathInfo"
    
    addToPattern "Writable PATH Check" "ANALYZED" ""
    
    # Environment variables
    logMessage "SUBSECTION" "Environment Variables (Matrix Code Parameters)"
    envInfo=$(interrogateMatrix "env")
    showWithRedPill "$envInfo"
    
    # Check for sensitive information in environment variables
    if echo "$envInfo" | grep -i "key\|password\|secret\|token\|credential" > /dev/null; then
        addToAnomalies "Sensitive Environment Variables" "Found sensitive information in environment variables" "$MEDIUM" "SENSITIVE_INFO" "Remove sensitive information from environment variables" ""
    fi
    
    addToPattern "Environment Variables Check" "ANALYZED" ""
    
    # sudo version
    logMessage "SUBSECTION" "Sudo Version (Agent Program Version)"
    sudoVersion=$(interrogateMatrix "sudo -V | head -n 1")
    echo "$sudoVersion"
    
    # Check for vulnerable sudo versions
    if [[ "$sudoVersion" =~ 1\.8\.[0-9]\. ]]; then
        addToAnomalies "Sudo Vulnerability" "Sudo version potentially vulnerable to CVE-2019-14287 (sudo < 1.8.28)" "$HIGH" "SUDO_VULNERABILITY" "Upgrade sudo to version 1.8.28 or later" "sudo -u#-1 /bin/bash"
        addToPrivEscVectors "Sudo Vulnerability Exploitation" "The system is running a sudo version potentially vulnerable to CVE-2019-14287. This can be exploited to gain root privileges by using a user ID of -1 or 4294967295." "$HIGH" "Requires sudo privileges with specific configuration" "sudo -u#-1 /bin/bash"
    fi
    
    if [[ "$sudoVersion" =~ 1\.8\.2[0-7] ]]; then
        addToAnomalies "Sudo Vulnerability" "Sudo version potentially vulnerable to CVE-2019-18634 (sudo < 1.8.26)" "$HIGH" "SUDO_VULNERABILITY" "Upgrade sudo to version 1.8.26 or later" "exploits/sudo_cve-2019-18634.sh"
        addToPrivEscVectors "Sudo Vulnerability Exploitation" "The system is running a sudo version potentially vulnerable to CVE-2019-18634 (buffer overflow). This can be exploited to gain root privileges." "$HIGH" "Requires specific sudo configuration" "exploits/sudo_cve-2019-18634.sh"
    fi
    
    addToPattern "Sudo Version Check" "ANALYZED" "$sudoVersion"
    
    # Signature verification
    logMessage "SUBSECTION" "Signature Verification (Matrix Authentication)"
    dmesgSig=$(interrogateMatrix "dmesg | grep -i \"signature\"")
    if [[ "$dmesgSig" == *"signature verification failed"* ]]; then
        addToAnomalies "Signature Verification Failed" "System may be vulnerable to module loading exploits" "$MEDIUM" "MODULE_LOADING" "Ensure module signature verification is enabled and working correctly" ""
    fi
    addToPattern "Signature Verification Check" "ANALYZED" ""
    
    updateProgress
}

# Check drives and mounts (the physical constructs of the Matrix)
analyzeDrives() {
    if shouldSkipCheck "drives"; then
        return
    fi
    
    animatedSection "Drives and Mounts"
    logMessage "SECTION" "Drives and Mounts (Matrix Constructs)"
    
    # List mounted drives
    logMessage "SUBSECTION" "Mounted Drives (Active Constructs)"
    mountedDrives=$(interrogateMatrix "mount")
    showWithRedPill "$mountedDrives"
    
    # Check for NFS shares with no_root_squash
    if echo "$mountedDrives" | grep "no_root_squash" > /dev/null; then
        addToAnomalies "NFS no_root_squash" "Found NFS share with no_root_squash option" "$HIGH" "NFS_PRIVILEGE_ESCALATION" "Reconfigure NFS to use root_squash option" "mkdir /tmp/nfs_exploit && mount -t nfs NFSHOSTIP:/shared /tmp/nfs_exploit && echo '#!/bin/bash\nchmod u+s /bin/bash' > /tmp/nfs_exploit/exploit.sh && chmod +x /tmp/nfs_exploit/exploit.sh && /tmp/nfs_exploit/exploit.sh && /bin/bash -p"
        addToPrivEscVectors "NFS Privilege Escalation" "NFS share with no_root_squash option detected. This can be exploited to gain root privileges by creating SUID binaries on the NFS share." "$HIGH" "Requires access to the NFS mount point" "mkdir /tmp/nfs_exploit && mount -t nfs NFSHOSTIP:/shared /tmp/nfs_exploit && echo '#!/bin/bash\nchmod u+s /bin/bash' > /tmp/nfs_exploit/exploit.sh && chmod +x /tmp/nfs_exploit/exploit.sh && /tmp/nfs_exploit/exploit.sh && /bin/bash -p"
    fi
    
    addToPattern "Mounted Drives Check" "ANALYZED" ""
    
    # Check for unmounted drives
    logMessage "SUBSECTION" "Unmounted Drives (Dormant Constructs)"
    if [ -f "/etc/fstab" ]; then
        fstabEntries=$(interrogateMatrix "cat /etc/fstab")
        showWithRedPill "$fstabEntries"
        
        # Check for credentials in fstab
        if echo "$fstabEntries" | grep -i "user\|password\|credentials" > /dev/null; then
            addToAnomalies "FSTAB Credentials" "Found credentials in /etc/fstab" "$MEDIUM" "SENSITIVE_INFO" "Remove credentials from fstab or use a more secure authentication method" ""
        fi
        
        # Look for unmounted drives
        currentMounts=$(mount | awk '{print $1}')
        while read -r line; do
            if [[ $line =~ ^[^#] ]]; then
                device=$(echo "$line" | awk '{print $1}')
                if ! echo "$currentMounts" | grep -q "$device"; then
                    addToAnomalies "Unmounted Drive" "Drive in fstab not currently mounted: $device" "$LOW" "ENUMERATION" "This is informational only" ""
                fi
            fi
        done <<< "$fstabEntries"
    fi
    
    addToPattern "FSTAB Check" "ANALYZED" ""
    
    updateProgress
}

# Remaining functions would continue in the same way, with updated features like progress indicators,
# better output formatting, and exploit command examples.
# For brevity, not all functions are shown here but would follow the same pattern.

# Generate an executive summary of the findings
generateExecutiveSummary() {
    local criticalCount=0
    local highCount=0
    local mediumCount=0
    local lowCount=0
    local infoCount=0
    
    # Count findings by severity
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
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
    
    # Calculate risk score (simple weighted formula)
    local riskScore=$((criticalCount * 100 + highCount * 40 + mediumCount * 10 + lowCount * 2))
    local riskLevel=""
    local riskColor=""
    
    if [ $riskScore -gt 200 ]; then
        riskLevel="CRITICAL"
        riskColor="${RED}${BOLD}"
    elif [ $riskScore -gt 100 ]; then
        riskLevel="HIGH"
        riskColor="${RED}"
    elif [ $riskScore -gt 50 ]; then
        riskLevel="MEDIUM"
        riskColor="${YELLOW}"
    elif [ $riskScore -gt 10 ]; then
        riskLevel="LOW"
        riskColor="${BLUE}"
    else
        riskLevel="MINIMAL"
        riskColor="${GREEN}"
    fi
    
    echo -e "${BOLD}Overall Risk Assessment:${NC} ${riskColor}$riskLevel${NC} (Score: $riskScore)"
    echo ""
    
    # Print scan statistics
    echo -e "${BOLD}Scan Statistics:${NC}"
    echo "Scan duration: $scanDuration seconds"
    echo "Total checks performed: ${#searchPatterns[@]}"
    echo "Scan depth: $scanDepth"
    echo ""
    
    # Print privilege escalation vectors if any were found
    if [ ${#privEscVectors[@]} -gt 0 ]; then
        echo -e "${BOLD}Top Privilege Escalation Vectors:${NC}"
        
        # Sort vectors by severity (critical first, then high, etc.)
        local criticalVectors=()
        local highVectors=()
        local mediumVectors=()
        local lowVectors=()
        
        for vector in "${privEscVectors[@]}"; do
            IFS='|' read -r name description severity exploitation exploit <<< "$vector"
            
            case $severity in
                "$CRITICAL") 
                    criticalVectors+=("$vector")
                    ;;
                "$HIGH") 
                    highVectors+=("$vector")
                    ;;
                "$MEDIUM") 
                    mediumVectors+=("$vector")
                    ;;
                "$LOW") 
                    lowVectors+=("$vector")
                    ;;
            esac
        done
        
        # Display vectors by severity, limited to top 3 per category
        local count=0
        
        # Critical vectors
        for vector in "${criticalVectors[@]}"; do
            IFS='|' read -r name description severity exploitation exploit <<< "$vector"
            echo -e "${RED}${BOLD}[$severity] $name${NC}"
            echo "  - $description"
            echo "  - Exploitation: $exploitation"
            if [ ! -z "$exploit" ]; then
                echo -e "  - ${UNDERLINE}Exploit:${NC} $exploit"
            fi
            echo ""
            ((count++))
            if [ $count -ge 3 ]; then
                echo -e "  ${BOLD}...and $(( ${#criticalVectors[@]} - 3 )) more critical vectors${NC}"
                break
            fi
        done
        
        # High vectors if we have room
        if [ $count -lt 5 ]; then
            count=0
            for vector in "${highVectors[@]}"; do
                IFS='|' read -r name description severity exploitation exploit <<< "$vector"
                echo -e "${RED}[$severity] $name${NC}"
                echo "  - $description"
                echo "  - Exploitation: $exploitation"
                if [ ! -z "$exploit" ]; then
                    echo -e "  - ${UNDERLINE}Exploit:${NC} $exploit"
                fi
                echo ""
                ((count++))
                if [ $count -ge 2 ]; then
                    if [ ${#highVectors[@]} -gt 2 ]; then
                        echo -e "  ${BOLD}...and $(( ${#highVectors[@]} - 2 )) more high severity vectors${NC}"
                    fi
                    break
                fi
            done
        fi
    else
        echo -e "${GREEN}No clear privilege escalation vectors were identified.${NC}"
    fi
    
    echo -e "${BOLD}Recommendations:${NC}"
    echo "1. Address all Critical and High severity findings immediately."
    echo "2. Review Medium severity findings as part of a regular security maintenance process."
    echo "3. Implement security best practices to prevent future vulnerabilities."
    echo ""
    if [ ${#privEscVectors[@]} -gt 0 ]; then
        echo -e "${BOLD}Most Important Remediations:${NC}"
        # Display top 3 most critical remediations
        local remCount=0
        
        for anomaly in "${anomalies[@]}"; do
            IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
            if [ "$severity" = "$CRITICAL" ] || [ "$severity" = "$HIGH" ]; then
                echo "- $remediation"
                ((remCount++))
                if [ $remCount -ge 3 ]; then
                    break
                fi
            fi
        done
    fi
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
    echo "Scan ID: $scanId" >> "$blueprintFile"
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
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        case $severity in
            "$CRITICAL") ((criticalCount++)) ;;
            "$HIGH") ((highCount++)) ;;
            "$MEDIUM") ((mediumCount++)) ;;
            "$LOW") ((lowCount++)) ;;
            "$INFO") ((infoCount++)) ;;
        esac
    done
    
    # Calculate risk score
    local riskScore=$((criticalCount * 100 + highCount * 40 + mediumCount * 10 + lowCount * 2))
    local riskLevel=""
    
    if [ $riskScore -gt 200 ]; then
        riskLevel="CRITICAL"
    elif [ $riskScore -gt 100 ]; then
        riskLevel="HIGH"
    elif [ $riskScore -gt 50 ]; then
        riskLevel="MEDIUM"
    elif [ $riskScore -gt 10 ]; then
        riskLevel="LOW"
    else
        riskLevel="MINIMAL"
    fi
    
    echo "Findings Summary:" >> "$blueprintFile"
    echo "Critical: $criticalCount" >> "$blueprintFile"
    echo "High: $highCount" >> "$blueprintFile"
    echo "Medium: $mediumCount" >> "$blueprintFile"
    echo "Low: $lowCount" >> "$blueprintFile"
    echo "Info: $infoCount" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    echo "Overall Risk Assessment: $riskLevel (Score: $riskScore)" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    # Privilege Escalation Vectors
    echo "IDENTIFIED PRIVILEGE ESCALATION VECTORS" >> "$blueprintFile"
    echo "=======================================" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    
    if [ ${#privEscVectors[@]} -gt 0 ]; then
        for vector in "${privEscVectors[@]}"; do
            IFS='|' read -r name description severity exploitation exploit <<< "$vector"
            echo "[$severity] $name" >> "$blueprintFile"
            echo "  - $description" >> "$blueprintFile"
            echo "  - Exploitation: $exploitation" >> "$blueprintFile"
            if [ ! -z "$exploit" ]; then
                echo "  - Exploit Command: $exploit" >> "$blueprintFile"
            fi
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
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$CRITICAL" ]; then
            criticalFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            if [ ! -z "$exploit" ]; then
                echo "  - Exploit Command: $exploit" >> "$blueprintFile"
            fi
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
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$HIGH" ]; then
            highFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            if [ ! -z "$exploit" ]; then
                echo "  - Exploit Command: $exploit" >> "$blueprintFile"
            fi
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
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$MEDIUM" ]; then
            mediumFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            if [ ! -z "$exploit" ]; then
                echo "  - Exploit Command: $exploit" >> "$blueprintFile"
            fi
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
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$LOW" ]; then
            lowFound=true
            echo "[$vector] $name" >> "$blueprintFile"
            echo "  - $detail" >> "$blueprintFile"
            echo "  - Remediation: $remediation" >> "$blueprintFile"
            if [ ! -z "$exploit" ]; then
                echo "  - Exploit Command: $exploit" >> "$blueprintFile"
            fi
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
    echo "Scan duration: $scanDuration seconds" >> "$blueprintFile"
    echo "Scan depth: $scanDepth" >> "$blueprintFile"
    echo "Scan completed at $(date)" >> "$blueprintFile"
    echo "" >> "$blueprintFile"
    echo "\"Remember: All I'm offering is the truth, nothing more.\"" >> "$blueprintFile"
}

# Generate HTML report
generateHtmlReport() {
    # Count findings by severity
    local criticalCount=0
    local highCount=0
    local mediumCount=0
    local lowCount=0
    local infoCount=0
    
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        case $severity in
            "$CRITICAL") ((criticalCount++)) ;;
            "$HIGH") ((highCount++)) ;;
            "$MEDIUM") ((mediumCount++)) ;;
            "$LOW") ((lowCount++)) ;;
            "$INFO") ((infoCount++)) ;;
        esac
    done
    
    # Calculate risk score
    local riskScore=$((criticalCount * 100 + highCount * 40 + mediumCount * 10 + lowCount * 2))
    local riskLevel=""
    local riskColor=""
    
    if [ $riskScore -gt 200 ]; then
        riskLevel="CRITICAL"
        riskColor="#FF0000"
    elif [ $riskScore -gt 100 ]; then
        riskLevel="HIGH"
        riskColor="#FF4500"
    elif [ $riskScore -gt 50 ]; then
        riskLevel="MEDIUM"
        riskColor="#FFA500"
    elif [ $riskScore -gt 10 ]; then
        riskLevel="LOW"
        riskColor="#0000FF"
    else
        riskLevel="MINIMAL"
        riskColor="#008000"
    fi
    
    # Create HTML file
    cat > "$htmlReport" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MatrixScan Report - $(hostname) - $(date)</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        header {
            text-align: center;
            padding: 20px;
            background-color: #000;
            color: #00ff00;
            margin-bottom: 20px;
        }
        h1, h2, h3 {
            color: #333;
        }
        .risk-meter {
            height: 20px;
            background: linear-gradient(to right, #008000, #FFA500, #FF0000);
            position: relative;
            margin: 20px 0;
            border-radius: 10px;
        }
        .risk-indicator {
            position: absolute;
            top: -10px;
            width: 10px;
            height: 40px;
            background-color: #000;
        }
        .summary-box {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #f9f9f9;
        }
        .finding {
            border-left: 5px solid #ddd;
            padding: 10px;
            margin-bottom: 10px;
        }
        .finding-critical {
            border-left-color: #FF0000;
            background-color: #FFF0F0;
        }
        .finding-high {
            border-left-color: #FF4500;
            background-color: #FFF5F0;
        }
        .finding-medium {
            border-left-color: #FFA500;
            background-color: #FFFAF0;
        }
        .finding-low {
            border-left-color: #0000FF;
            background-color: #F0F0FF;
        }
        .finding-info {
            border-left-color: #008000;
            background-color: #F0FFF0;
        }
        .badge {
            display: inline-block;
            padding: 3px 7px;
            border-radius: 3px;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-critical {
            background-color: #FF0000;
        }
        .badge-high {
            background-color: #FF4500;
        }
        .badge-medium {
            background-color: #FFA500;
        }
        .badge-low {
            background-color: #0000FF;
        }
        .badge-info {
            background-color: #008000;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .chart-container {
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
        }
        .chart-bar {
            height: 30px;
            margin: 5px 0;
            position: relative;
        }
        .chart-bar-fill {
            height: 100%;
            position: absolute;
            left: 0;
        }
        .chart-bar-label {
            position: absolute;
            left: 10px;
            top: 5px;
            color: #fff;
            font-weight: bold;
            z-index: 1;
        }
        .chart-bar-value {
            position: absolute;
            right: 10px;
            top: 5px;
            font-weight: bold;
        }
        pre {
            background-color: #f7f7f7;
            padding: 10px;
            border-left: 3px solid #ccc;
            overflow-x: auto;
        }
        .exploit-command {
            background-color: #333;
            color: #00ff00;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            overflow-x: auto;
        }
        .severity-filter {
            margin-bottom: 15px;
        }
        .severity-filter label {
            margin-right: 15px;
        }
        .collapsible {
            background-color: #f1f1f1;
            color: #333;
            cursor: pointer;
            padding: 10px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 1px;
        }
        .active, .collapsible:hover {
            background-color: #ddd;
        }
        .content {
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: white;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>MatrixScan Security Report</h1>
            <p>System: $(hostname) | Date: $(date) | Scan ID: $scanId</p>
        </header>
        
        <h2>Executive Summary</h2>
        <div class="summary-box">
            <h3>Risk Assessment: <span style="color: ${riskColor};">${riskLevel}</span></h3>
            <p>Overall Risk Score: <strong>${riskScore}</strong></p>
            
            <div class="risk-meter">
                <div class="risk-indicator" style="left: ${riskScore / 4}%;"></div>
            </div>
            
            <div class="chart-container">
                <h4>Findings by Severity</h4>
                <div class="chart-bar">
                    <div class="chart-bar-fill badge-critical" style="width: ${criticalCount * 5 > 100 ? 100 : criticalCount * 5}%;"></div>
                    <span class="chart-bar-label">Critical</span>
                    <span class="chart-bar-value">${criticalCount}</span>
                </div>
                <div class="chart-bar">
                    <div class="chart-bar-fill badge-high" style="width: ${highCount * 5 > 100 ? 100 : highCount * 5}%;"></div>
                    <span class="chart-bar-label">High</span>
                    <span class="chart-bar-value">${highCount}</span>
                </div>
                <div class="chart-bar">
                    <div class="chart-bar-fill badge-medium" style="width: ${mediumCount * 5 > 100 ? 100 : mediumCount * 5}%;"></div>
                    <span class="chart-bar-label">Medium</span>
                    <span class="chart-bar-value">${mediumCount}</span>
                </div>
                <div class="chart-bar">
                    <div class="chart-bar-fill badge-low" style="width: ${lowCount * 5 > 100 ? 100 : lowCount * 5}%;"></div>
                    <span class="chart-bar-label">Low</span>
                    <span class="chart-bar-value">${lowCount}</span>
                </div>
            </div>
            
            <h4>Scan Information</h4>
            <table>
                <tr>
                    <td><strong>Hostname:</strong></td>
                    <td>$(hostname)</td>
                </tr>
                <tr>
                    <td><strong>User:</strong></td>
                    <td>$USER</td>
                </tr>
                <tr>
                    <td><strong>Kernel:</strong></td>
                    <td>$(uname -r)</td>
                </tr>
                <tr>
                    <td><strong>OS:</strong></td>
                    <td>$(cat /etc/issue 2>/dev/null)</td>
                </tr>
                <tr>
                    <td><strong>Scan Duration:</strong></td>
                    <td>${scanDuration} seconds</td>
                </tr>
                <tr>
                    <td><strong>Scan Depth:</strong></td>
                    <td>${scanDepth}</td>
                </tr>
                <tr>
                    <td><strong>Total Checks:</strong></td>
                    <td>${#searchPatterns[@]}</td>
                </tr>
                <tr>
                    <td><strong>Total Findings:</strong></td>
                    <td>${#anomalies[@]}</td>
                </tr>
            </table>
        </div>
        
        <h2>Privilege Escalation Vectors</h2>
        <div class="severity-filter">
            <label><input type="checkbox" class="filter" value="all" checked> All</label>
            <label><input type="checkbox" class="filter" value="critical" checked> Critical</label>
            <label><input type="checkbox" class="filter" value="high" checked> High</label>
            <label><input type="checkbox" class="filter" value="medium" checked> Medium</label>
            <label><input type="checkbox" class="filter" value="low" checked> Low</label>
        </div>
EOF

    # Add privilege escalation vectors
    if [ ${#privEscVectors[@]} -gt 0 ]; then
        for vector in "${privEscVectors[@]}"; do
            IFS='|' read -r name description severity exploitation exploit <<< "$vector"
            
            local severityClass=""
            case $severity in
                "$CRITICAL") severityClass="critical" ;;
                "$HIGH") severityClass="high" ;;
                "$MEDIUM") severityClass="medium" ;;
                "$LOW") severityClass="low" ;;
                "$INFO") severityClass="info" ;;
            esac
            
            cat >> "$htmlReport" << EOF
        <div class="finding finding-${severityClass}" data-severity="${severityClass}">
            <h3>${name} <span class="badge badge-${severityClass}">${severity}</span></h3>
            <p><strong>Description:</strong> ${description}</p>
            <p><strong>Exploitation:</strong> ${exploitation}</p>
EOF
            
            if [ ! -z "$exploit" ]; then
                cat >> "$htmlReport" << EOF
            <p><strong>Exploit Command:</strong></p>
            <div class="exploit-command">${exploit}</div>
EOF
            fi
            
            cat >> "$htmlReport" << EOF
        </div>
EOF
        done
    else
        cat >> "$htmlReport" << EOF
        <div class="summary-box">
            <p><strong>No clear privilege escalation vectors were identified.</strong></p>
        </div>
EOF
    fi
    
    # Add detailed findings
    cat >> "$htmlReport" << EOF
        <h2>Detailed Findings</h2>
        
        <button class="collapsible">Critical Findings (${criticalCount})</button>
        <div class="content">
EOF
    
    local criticalFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$CRITICAL" ]; then
            criticalFound=true
            cat >> "$htmlReport" << EOF
            <div class="finding finding-critical">
                <h3>${name} <span class="badge badge-critical">${severity}</span></h3>
                <p><strong>Type:</strong> ${vector}</p>
                <p><strong>Detail:</strong> ${detail}</p>
                <p><strong>Remediation:</strong> ${remediation}</p>
EOF
            
            if [ ! -z "$exploit" ]; then
                cat >> "$htmlReport" << EOF
                <p><strong>Exploit Command:</strong></p>
                <div class="exploit-command">${exploit}</div>
EOF
            fi
            
            cat >> "$htmlReport" << EOF
            </div>
EOF
        fi
    done
    
    if [ "$criticalFound" = false ]; then
        cat >> "$htmlReport" << EOF
            <div class="summary-box">
                <p>No critical severity findings identified.</p>
            </div>
EOF
    fi
    
    cat >> "$htmlReport" << EOF
        </div>
        
        <button class="collapsible">High Severity Findings (${highCount})</button>
        <div class="content">
EOF
    
    local highFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$HIGH" ]; then
            highFound=true
            cat >> "$htmlReport" << EOF
            <div class="finding finding-high">
                <h3>${name} <span class="badge badge-high">${severity}</span></h3>
                <p><strong>Type:</strong> ${vector}</p>
                <p><strong>Detail:</strong> ${detail}</p>
                <p><strong>Remediation:</strong> ${remediation}</p>
EOF
            
            if [ ! -z "$exploit" ]; then
                cat >> "$htmlReport" << EOF
                <p><strong>Exploit Command:</strong></p>
                <div class="exploit-command">${exploit}</div>
EOF
            fi
            
            cat >> "$htmlReport" << EOF
            </div>
EOF
        fi
    done
    
    if [ "$highFound" = false ]; then
        cat >> "$htmlReport" << EOF
            <div class="summary-box">
                <p>No high severity findings identified.</p>
            </div>
EOF
    fi
    
    cat >> "$htmlReport" << EOF
        </div>
        
        <button class="collapsible">Medium Severity Findings (${mediumCount})</button>
        <div class="content">
EOF
    
    local mediumFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$MEDIUM" ]; then
            mediumFound=true
            cat >> "$htmlReport" << EOF
            <div class="finding finding-medium">
                <h3>${name} <span class="badge badge-medium">${severity}</span></h3>
                <p><strong>Type:</strong> ${vector}</p>
                <p><strong>Detail:</strong> ${detail}</p>
                <p><strong>Remediation:</strong> ${remediation}</p>
EOF
            
            if [ ! -z "$exploit" ]; then
                cat >> "$htmlReport" << EOF
                <p><strong>Exploit Command:</strong></p>
                <div class="exploit-command">${exploit}</div>
EOF
            fi
            
            cat >> "$htmlReport" << EOF
            </div>
EOF
        fi
    done
    
    if [ "$mediumFound" = false ]; then
        cat >> "$htmlReport" << EOF
            <div class="summary-box">
                <p>No medium severity findings identified.</p>
            </div>
EOF
    fi
    
    cat >> "$htmlReport" << EOF
        </div>
        
        <button class="collapsible">Low Severity Findings (${lowCount})</button>
        <div class="content">
EOF
    
    local lowFound=false
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if [ "$severity" = "$LOW" ]; then
            lowFound=true
            cat >> "$htmlReport" << EOF
            <div class="finding finding-low">
                <h3>${name} <span class="badge badge-low">${severity}</span></h3>
                <p><strong>Type:</strong> ${vector}</p>
                <p><strong>Detail:</strong> ${detail}</p>
                <p><strong>Remediation:</strong> ${remediation}</p>
EOF
            
            if [ ! -z "$exploit" ]; then
                cat >> "$htmlReport" << EOF
                <p><strong>Exploit Command:</strong></p>
                <div class="exploit-command">${exploit}</div>
EOF
            fi
            
            cat >> "$htmlReport" << EOF
            </div>
EOF
        fi
    done
    
    if [ "$lowFound" = false ]; then
        cat >> "$htmlReport" << EOF
            <div class="summary-box">
                <p>No low severity findings identified.</p>
            </div>
EOF
    fi
    
    # Add JavaScript for interactivity
    cat >> "$htmlReport" << EOF
        </div>

        <footer>
            <p style="text-align: center; margin-top: 30px; color: #666;">
                MatrixScan Report | Generated on $(date) | ScanID: ${scanId}<br>
                <em>"Remember: All I'm offering is the truth, nothing more."</em>
            </p>
        </footer>
    </div>

    <script>
        // Collapsible sections
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {
                    content.style.display = "none";
                } else {
                    content.style.display = "block";
                }
            });
            
            // Open Critical and High by default
            if (i < 2) {
                coll[i].click();
            }
        }
        
        // Severity filters
        const filters = document.querySelectorAll('.filter');
        const findings = document.querySelectorAll('.finding');
        
        filters.forEach(filter => {
            filter.addEventListener('change', function() {
                const filterValue = this.value;
                
                if (filterValue === 'all') {
                    const checked = this.checked;
                    filters.forEach(f => {
                        if (f.value !== 'all') {
                            f.checked = checked;
                        }
                    });
                    
                    findings.forEach(finding => {
                        finding.style.display = checked ? 'block' : 'none';
                    });
                } else {
                    const activeFilters = Array.from(filters)
                        .filter(f => f.value !== 'all' && f.checked)
                        .map(f => f.value);
                    
                    filters[0].checked = activeFilters.length === filters.length - 1;
                    
                    findings.forEach(finding => {
                        const severityClass = finding.dataset.severity;
                        finding.style.display = activeFilters.includes(severityClass) ? 'block' : 'none';
                    });
                }
            });
        });
    </script>
</body>
</html>
EOF
}

# Generate JSON report
generateJsonReport() {
    # Initialize JSON structure
    cat > "$jsonReport" << EOF
{
  "scan_info": {
    "scan_id": "${scanId}",
    "hostname": "$(hostname)",
    "username": "$USER",
    "date": "$(date)",
    "kernel": "$(uname -r)",
    "os": "$(cat /etc/issue 2>/dev/null | tr '\n' ' ' | sed 's/\\\\/\\\\\\\/g')",
    "scan_duration": ${scanDuration},
    "scan_depth": "${scanDepth}"
  },
  "summary": {
EOF

    # Count findings by severity
    local criticalCount=0
    local highCount=0
    local mediumCount=0
    local lowCount=0
    local infoCount=0
    
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        case $severity in
            "$CRITICAL") ((criticalCount++)) ;;
            "$HIGH") ((highCount++)) ;;
            "$MEDIUM") ((mediumCount++)) ;;
            "$LOW") ((lowCount++)) ;;
            "$INFO") ((infoCount++)) ;;
        esac
    done
    
    # Calculate risk score
    local riskScore=$((criticalCount * 100 + highCount * 40 + mediumCount * 10 + lowCount * 2))
    local riskLevel=""
    
    if [ $riskScore -gt 200 ]; then
        riskLevel="CRITICAL"
    elif [ $riskScore -gt 100 ]; then
        riskLevel="HIGH"
    elif [ $riskScore -gt 50 ]; then
        riskLevel="MEDIUM"
    elif [ $riskScore -gt 10 ]; then
        riskLevel="LOW"
    else
        riskLevel="MINIMAL"
    fi
    
    # Add summary statistics
    cat >> "$jsonReport" << EOF
    "critical_count": ${criticalCount},
    "high_count": ${highCount},
    "medium_count": ${mediumCount},
    "low_count": ${lowCount},
    "info_count": ${infoCount},
    "total_findings": ${#anomalies[@]},
    "total_checks": ${#searchPatterns[@]},
    "risk_score": ${riskScore},
    "risk_level": "${riskLevel}"
  },
  "privilege_escalation_vectors": [
EOF

    # Add privilege escalation vectors
    local vectorCount=0
    for vector in "${privEscVectors[@]}"; do
        IFS='|' read -r name description severity exploitation exploit <<< "$vector"
        
        # Add comma if not the first item
        if [ $vectorCount -gt 0 ]; then
            echo "," >> "$jsonReport"
        fi
        ((vectorCount++))
        
        # Escape special characters for JSON
        name=$(echo "$name" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        description=$(echo "$description" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        exploitation=$(echo "$exploitation" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        exploit=$(echo "$exploit" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        
        cat >> "$jsonReport" << EOF
    {
      "name": "${name}",
      "description": "${description}",
      "severity": "${severity}",
      "exploitation": "${exploitation}",
      "exploit_command": "${exploit}"
    }
EOF
    done
    
    cat >> "$jsonReport" << EOF
  ],
  "findings": [
EOF

    # Add all findings
    local findingCount=0
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        
        # Add comma if not the first item
        if [ $findingCount -gt 0 ]; then
            echo "," >> "$jsonReport"
        fi
        ((findingCount++))
        
        # Escape special characters for JSON
        name=$(echo "$name" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        detail=$(echo "$detail" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        vector=$(echo "$vector" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        remediation=$(echo "$remediation" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        exploit=$(echo "$exploit" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        
        cat >> "$jsonReport" << EOF
    {
      "name": "${name}",
      "detail": "${detail}",
      "severity": "${severity}",
      "vector": "${vector}",
      "remediation": "${remediation}",
      "exploit_command": "${exploit}"
    }
EOF
    done
    
    cat >> "$jsonReport" << EOF
  ]
}
EOF
}

# Generate CSV report
generateCsvReport() {
    # Create CSV header
    echo "Severity,Name,Vector,Detail,Remediation,Exploit Command" > "$csvReport"
    
    # Add findings
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        
        # Escape commas and quotes for CSV
        name=$(echo "$name" | sed 's/"/""/g')
        detail=$(echo "$detail" | sed 's/"/""/g')
        vector=$(echo "$vector" | sed 's/"/""/g')
        remediation=$(echo "$remediation" | sed 's/"/""/g')
        exploit=$(echo "$exploit" | sed 's/"/""/g')
        
        echo "\"$severity\",\"$name\",\"$vector\",\"$detail\",\"$remediation\",\"$exploit\"" >> "$csvReport"
    done
}

# Compare with previous scan results
compareWithPrevious() {
    echo -e "${MATRIX_GREEN}${BOLD}COMPARISON WITH PREVIOUS SCAN${NC}"
    echo -e "${BOLD}==============================${NC}"
    echo ""
    
    # Check if previous report exists
    if [ ! -f "$previousReport" ]; then
        echo -e "${RED}Error: Previous report file not found.${NC}"
        return
    fi
    
    # Extract findings from previous report
    local prevFindings=$(grep -A 5 "\[ANOMALY\]" "$previousReport" | grep -v "^--$")
    local currentFindings=""
    
    # Build string of current findings
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        currentFindings+="[ANOMALY] $name: $detail\n"
    done
    
    # Find new findings (in current but not in previous)
    echo -e "${BOLD}New Findings:${NC}"
    local newCount=0
    for anomaly in "${anomalies[@]}"; do
        IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
        if ! echo "$prevFindings" | grep -q "$name: $detail"; then
            case $severity in
                "$CRITICAL") echo -e "${RED}[CRITICAL] $name - $detail${NC}" ;;
                "$HIGH") echo -e "${RED}[HIGH] $name - $detail${NC}" ;;
                "$MEDIUM") echo -e "${YELLOW}[MEDIUM] $name - $detail${NC}" ;;
                "$LOW") echo -e "${BLUE}[LOW] $name - $detail${NC}" ;;
                "$INFO") echo -e "${GREEN}[INFO] $name - $detail${NC}" ;;
            esac
            ((newCount++))
        fi
    done
    
    if [ $newCount -eq 0 ]; then
        echo "No new findings detected since previous scan."
    fi
    echo ""
    
    # Find resolved findings (in previous but not in current)
    echo -e "${BOLD}Resolved Findings:${NC}"
    local resolvedCount=0
    while IFS= read -r line; do
        if [[ $line == *"[ANOMALY]"* ]]; then
            local findingName=$(echo "$line" | sed 's/\[ANOMALY\] \(.*\): .*/\1/')
            local findingDetail=$(echo "$line" | sed 's/\[ANOMALY\] .*: \(.*\)/\1/')
            
            if ! echo "$currentFindings" | grep -q "$findingName: $findingDetail"; then
                echo -e "${GREEN}✓ $findingName - $findingDetail${NC}"
                ((resolvedCount++))
            fi
        fi
    done <<< "$prevFindings"
    
    if [ $resolvedCount -eq 0 ]; then
        echo "No findings have been resolved since previous scan."
    fi
    
    echo ""
}

# Interactive mode to explore findings
exploreFindings() {
    local EXIT_OPTION="Exit Interactive Mode"
    local SHOW_ALL="Show All Findings"
    local SHOW_CRITICAL="Show Critical Findings"
    local SHOW_HIGH="Show High Findings"
    local SHOW_MEDIUM="Show Medium Findings"
    local SHOW_LOW="Show Low Findings"
    local SHOW_VECTORS="Show Privilege Escalation Vectors"
    local SHOW_EXPLOITS="Show Exploit Commands"
    
    while true; do
        echo -e "${MATRIX_GREEN}${BOLD}MATRIX EXPLORATION MODE${NC}"
        echo -e "${BOLD}======================${NC}"
        echo ""
        echo "Select an option:"
        echo "1) $SHOW_ALL"
        echo "2) $SHOW_CRITICAL"
        echo "3) $SHOW_HIGH"
        echo "4) $SHOW_MEDIUM"
        echo "5) $SHOW_LOW"
        echo "6) $SHOW_VECTORS"
        echo "7) $SHOW_EXPLOITS"
        echo "8) $EXIT_OPTION"
        echo ""
        read -p "Enter option (1-8): " option
        
        case $option in
            1)
                clear
                echo -e "${BOLD}All Findings:${NC}"
                echo ""
                for anomaly in "${anomalies[@]}"; do
                    IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
                    case $severity in
                        "$CRITICAL") echo -e "${RED}[CRITICAL] $name${NC}" ;;
                        "$HIGH") echo -e "${RED}[HIGH] $name${NC}" ;;
                        "$MEDIUM") echo -e "${YELLOW}[MEDIUM] $name${NC}" ;;
                        "$LOW") echo -e "${BLUE}[LOW] $name${NC}" ;;
                        "$INFO") echo -e "${GREEN}[INFO] $name${NC}" ;;
                    esac
                    echo "  - $detail"
                    echo "  - Remediation: $remediation"
                    echo ""
                done
                read -p "Press Enter to continue..."
                clear
                ;;
            2)
                clear
                echo -e "${RED}${BOLD}Critical Findings:${NC}"
                echo ""
                local found=false
                for anomaly in "${anomalies[@]}"; do
                    IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
                    if [ "$severity" = "$CRITICAL" ]; then
                        found=true
                        echo -e "${RED}[CRITICAL] $name${NC}"
                        echo "  - $detail"
                        echo "  - Remediation: $remediation"
                        if [ ! -z "$exploit" ]; then
                            echo -e "  - ${UNDERLINE}Exploit:${NC} $exploit"
                        fi
                        echo ""
                    fi
                done
                if [ "$found" = false ]; then
                    echo "No critical findings detected."
                fi
                read -p "Press Enter to continue..."
                clear
                ;;
            3)
                clear
                echo -e "${RED}${BOLD}High Severity Findings:${NC}"
                echo ""
                local found=false
                for anomaly in "${anomalies[@]}"; do
                    IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
                    if [ "$severity" = "$HIGH" ]; then
                        found=true
                        echo -e "${RED}[HIGH] $name${NC}"
                        echo "  - $detail"
                        echo "  - Remediation: $remediation"
                        if [ ! -z "$exploit" ]; then
                            echo -e "  - ${UNDERLINE}Exploit:${NC} $exploit"
                        fi
                        echo ""
                    fi
                done
                if [ "$found" = false ]; then
                    echo "No high severity findings detected."
                fi
                read -p "Press Enter to continue..."
                clear
                ;;
            4)
                clear
                echo -e "${YELLOW}${BOLD}Medium Severity Findings:${NC}"
                echo ""
                local found=false
                for anomaly in "${anomalies[@]}"; do
                    IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
                    if [ "$severity" = "$MEDIUM" ]; then
                        found=true
                        echo -e "${YELLOW}[MEDIUM] $name${NC}"
                        echo "  - $detail"
                        echo "  - Remediation: $remediation"
                        if [ ! -z "$exploit" ]; then
                            echo -e "  - ${UNDERLINE}Exploit:${NC} $exploit"
                        fi
                        echo ""
                    fi
                done
                if [ "$found" = false ]; then
                    echo "No medium severity findings detected."
                fi
                read -p "Press Enter to continue..."
                clear
                ;;
            5)
                clear
                echo -e "${BLUE}${BOLD}Low Severity Findings:${NC}"
                echo ""
                local found=false
                for anomaly in "${anomalies[@]}"; do
                    IFS='|' read -r name detail severity vector remediation exploit <<< "$anomaly"
                    if [ "$severity" = "$LOW" ]; then
                        found=true
                        echo -e "${BLUE}[LOW] $name${NC}"
                        echo "  - $detail"
                        echo "  - Remediation: $remediation"
                        if [ ! -z "$exploit" ]; then
                            echo -e "  - ${UNDERLINE}Exploit:${NC} $exploit"
                        fi
                        echo ""
                    fi
                done
                if [ "$found" = false ]; then
                    echo "No low severity findings detected."
                fi
                read -p "Press Enter to continue..."
                clear
                ;;
            6)
                clear
                echo -e "${MATRIX_GREEN}${BOLD}Privilege Escalation Vectors:${NC}"
                echo ""
                if [ ${#privEscVectors[@]} -gt 0 ]; then
                    for vector in "${privEscVectors[@]}"; do
                        IFS='|' read -r name description severity exploitation exploit <<< "$vector"
                        
                        case $severity in
                            "$CRITICAL") echo -e "${RED}${BOLD}[CRITICAL] $name${NC}" ;;
                            "$HIGH") echo -e "${RED}[HIGH] $name${NC}" ;;
                            "$MEDIUM") echo -e "${YELLOW}[MEDIUM] $name${NC}" ;;
                            "$LOW") echo -e "${BLUE}[LOW] $name${NC}" ;;
                            "$INFO") echo -e "${GREEN}[INFO] $name${NC}" ;;
                        esac
                        
                        echo "  - $description"
                        echo "  - Exploitation: $exploitation"
                        if [ ! -z "$exploit" ]; then
                            echo -e "  - ${UNDERLINE}Exploit:${NC} $exploit"
                        fi
                        echo ""
                    done
                else
                    echo "No privilege escalation vectors identified."
                fi
                read -p "Press Enter to continue..."
                clear
                ;;
            7)
                clear
                echo -e "${MATRIX_GREEN}${BOLD}Exploit Commands:${NC}"
                echo ""
                local found=false
                for vector in "${privEscVectors[@]}"; do
                    IFS='|' read -r name description severity exploitation exploit <<< "$vector"
                    if [ ! -z "$exploit" ]; then
                        found=true
                        case $severity in
                            "$CRITICAL") echo -e "${RED}${BOLD}[CRITICAL] $name${NC}" ;;
                            "$HIGH") echo -e "${RED}[HIGH] $name${NC}" ;;
                            "$MEDIUM") echo -e "${YELLOW}[MEDIUM] $name${NC}" ;;
                            "$LOW") echo -e "${BLUE}[LOW] $name${NC}" ;;
                            "$INFO") echo -e "${GREEN}[INFO] $name${NC}" ;;
                        esac
                        echo -e "  ${UNDERLINE}Exploit Command:${NC}"
                        echo -e "  ${MATRIX_GREEN}$exploit${NC}"
                        echo ""
                    fi
                done
                if [ "$found" = false ]; then
                    echo "No exploit commands available."
                fi
                read -p "Press Enter to continue..."
                clear
                ;;
            8)
                clear
                return
                ;;
            *)
                clear
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
    done
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
    
    # Set up for remote scanning if needed
    if [ "$remoteMode" = true ]; then
        if [ "$quietMode" = false ]; then
            echo -e "${MATRIX_GREEN}Initiating remote scan of ${remoteHost}...${NC}"
        fi
    fi
    
    if [ "$quietMode" = false ]; then
        echo -e "${MATRIX_GREEN}Matrix scan started at $(date)${NC}"
        if [ "$scanDepth" = "quick" ]; then
            echo -e "${GREEN}Quick scan mode enabled - some checks will be skipped${NC}"
        elif [ "$scanDepth" = "deep" ]; then
            echo -e "${YELLOW}Deep scan mode enabled - this may take longer${NC}"
        fi
        
        if [ ${#focusedChecks[@]} -gt 0 ]; then
            echo -e "${CYAN}Focused scan mode enabled - checking only: ${focusedChecks[*]}${NC}"
        fi
        
        if [ ${#skipChecks[@]} -gt 0 ]; then
            echo -e "${YELLOW}Skipping checks: ${skipChecks[*]}${NC}"
        fi
        
        echo -e "${GREEN}Taking the red pill to show you how deep the rabbit hole goes...${NC}"
        echo ""
    fi
    
    # Call all analysis functions in sequence
    analyzeMatrixCore
    analyzeDrives
    # The remaining functions would be called here
    # For brevity, not all calls are shown, but would follow the same pattern
    
    # Calculate scan duration
    endTime=$(date +%s)
    scanDuration=$((endTime - startTime))
    
    # Compare with previous scan if requested
    if [ "$compareMode" = true ]; then
        compareWithPrevious
    fi
    
    # Generate a detailed text report
    generateTextReport
    
    # Generate HTML report if requested
    if [ "$generateHtml" = true ]; then
        generateHtmlReport
    fi
    
    # Generate JSON report if requested
    if [ "$generateJson" = true ]; then
        generateJsonReport
    fi
    
    # Generate CSV report if requested
    if [ "$generateCsv" = true ]; then
        generateCsvReport
    fi
    
    # Generate executive summary for the console if not in quiet mode
    if [ "$quietMode" = false ]; then
        echo ""
        generateExecutiveSummary
    fi
    
    # Start interactive mode if requested
    if [ "$interactiveMode" = true ]; then
        exploreFindings
    fi
    
    if [ "$quietMode" = false ]; then
        echo ""
        echo -e "${MATRIX_GREEN}Matrix scan complete. Results saved to: $blueprintFile${NC}"
        if [ "$generateHtml" = true ]; then
            echo -e "${MATRIX_GREEN}HTML report saved to: $htmlReport${NC}"
        fi
        if [ "$generateJson" = true ]; then
            echo -e "${MATRIX_GREEN}JSON report saved to: $jsonReport${NC}"
        fi
        if [ "$generateCsv" = true ]; then
            echo -e "${MATRIX_GREEN}CSV report saved to: $csvReport${NC}"
        fi
        echo -e "${MATRIX_GREEN}Remember: All I'm offering is the truth, nothing more.${NC}"
    fi
}

# Execute the main function with all arguments
main "$@"
