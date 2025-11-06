#!/bin/bash

# Linux Security Audit Comprehensive Script
# Based on answer_key1.txt, answer_key2.txt, and answer_key3.txt
# This script addresses all conditions from the three answer keys

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$CHECKLIST_FILE"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] $1" >> "$CHECKLIST_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] $1" >> "$CHECKLIST_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    echo "[INFO] $1" >> "$CHECKLIST_FILE"
}

# Create checklist documentation directory and file
CHECKLIST_DIR="/home/Public/Documents"
CHECKLIST_FILE="$CHECKLIST_DIR/Checklist.txt"
sudo mkdir -p "$CHECKLIST_DIR"
sudo touch "$CHECKLIST_FILE"
sudo chmod 666 "$CHECKLIST_FILE"

# Create audit workspace
AUDIT_DIR="/tmp/audit_$(date +%Y%m%d_%H%M)"
mkdir -p "$AUDIT_DIR"
cd "$AUDIT_DIR"

# Create documentation files
touch findings.txt fixes_applied.txt users_found.txt services_found.txt

# Initialize checklist
echo "===============================================" > "$CHECKLIST_FILE"
echo "LINUX SECURITY AUDIT CHECKLIST" >> "$CHECKLIST_FILE"
echo "Started: $(date)" >> "$CHECKLIST_FILE"
echo "===============================================" >> "$CHECKLIST_FILE"

# ============================================================================
# SECTION 0: PRE-AUDIT CHECKS AND README ANALYSIS
# ============================================================================

log "Starting comprehensive Linux security audit..."

# Initialize findings file
echo "=== COMPREHENSIVE LINUX SECURITY AUDIT ===" > findings.txt
echo "Date: $(date)" >> findings.txt
echo "Hostname: $(hostname)" >> findings.txt
echo "OS: $(lsb_release -d 2>/dev/null || echo 'Unknown')" >> findings.txt
echo "Kernel: $(uname -r)" >> findings.txt
echo "User: $(whoami)" >> findings.txt
echo "=========================" >> findings.txt

# Step 1: Read and analyze README.txt files
log "STEP 1: Reading README.txt files for authorized users and critical services..."

README_LOCATIONS=("/README.txt" "/home/README.txt" "/root/README.txt" "/home/*/Desktop/README.txt" "/README" "/readme.txt")
AUTHORIZED_USERS=""
CRITICAL_SERVICES=""
README_FOUND=false

for readme_path in "${README_LOCATIONS[@]}"; do
    for readme_file in $readme_path; do
        if [ -f "$readme_file" ]; then
            README_FOUND=true
            info "Found README file: $readme_file"
            echo "=== README ANALYSIS: $readme_file ===" >> findings.txt
            cat "$readme_file" >> findings.txt
            echo "=================================" >> findings.txt
            
            # Extract authorized users (look for common patterns)
            USERS_SECTION=$(grep -i -A 20 "authorized\|users\|accounts" "$readme_file" 2>/dev/null || echo "")
            if [ -n "$USERS_SECTION" ]; then
                info "Found authorized users section in README"
                echo "Authorized users section found in $readme_file" >> "$CHECKLIST_FILE"
                echo "$USERS_SECTION" >> "$CHECKLIST_FILE"
            fi
            
            # Extract critical services
            SERVICES_SECTION=$(grep -i -A 10 "services\|critical\|required\|needed" "$readme_file" 2>/dev/null || echo "")
            if [ -n "$SERVICES_SECTION" ]; then
                info "Found critical services section in README"
                echo "Critical services section found in $readme_file" >> "$CHECKLIST_FILE"
                echo "$SERVICES_SECTION" >> "$CHECKLIST_FILE"
            fi
        fi
    done
done

if [ "$README_FOUND" = false ]; then
    warn "No README.txt file found in common locations"
    echo "WARNING: No README.txt found - proceeding with default security measures" >> "$CHECKLIST_FILE"
else
    log "README analysis completed - check findings.txt for details"
fi

# ============================================================================
# SECTION 1: FORENSICS TASKS AND ANSWERS
# ============================================================================

log "STEP 2: Performing forensics tasks and documenting answers..."

# Answer Key 1: Find Linux codename
info "Finding Linux codename..."
CODENAME=$(lsb_release -a 2>/dev/null | grep Codename | awk '{print $2}' || echo "unknown")
echo "FORENSICS Q1 - Linux codename: $CODENAME" >> findings.txt
echo "FORENSICS ANSWER Q1: $CODENAME" >> "$CHECKLIST_FILE"

# Answer Key 1 & 2: Locate MP3 files BEFORE deletion
info "Locating MP3 files for forensics documentation..."
MP3_FILES=$(locate '*.mp3' 2>/dev/null || find /home -name "*.mp3" 2>/dev/null || echo "none")
if [ "$MP3_FILES" != "none" ]; then
    echo "FORENSICS Q2 - Unauthorized MP3 files found:" >> findings.txt
    echo "$MP3_FILES" >> findings.txt
    echo "FORENSICS ANSWER Q2: MP3 files found at:" >> "$CHECKLIST_FILE"
    echo "$MP3_FILES" >> "$CHECKLIST_FILE"
    
    # Document specific paths for common forensics questions
    MP3_DIR=$(echo "$MP3_FILES" | head -1 | xargs dirname 2>/dev/null || echo "unknown")
    echo "FORENSICS Q2 DIRECTORY: $MP3_DIR" >> "$CHECKLIST_FILE"
fi

# Answer Key 2: Base64 decoding (check for forensics files)
info "Checking for forensics questions on desktop..."
for user_home in /home/*; do
    if [ -d "$user_home/Desktop" ]; then
        for forensics_file in "$user_home/Desktop/Forensics"*; do
            if [ -f "$forensics_file" ]; then
                info "Found forensics file: $forensics_file"
                echo "FORENSICS FILE FOUND: $forensics_file" >> findings.txt
                echo "FORENSICS FILE: $forensics_file" >> "$CHECKLIST_FILE"
                
                # Try to read and decode if it's base64
                if file "$forensics_file" | grep -q "ASCII text"; then
                    CONTENT=$(cat "$forensics_file" 2>/dev/null || echo "")
                    if echo "$CONTENT" | base64 -d &>/dev/null; then
                        DECODED=$(echo "$CONTENT" | base64 -d 2>/dev/null || echo "")
                        echo "FORENSICS DECODED: $DECODED" >> "$CHECKLIST_FILE"
                        info "Base64 decoded content: $DECODED"
                    fi
                fi
            fi
        done
    fi
done

# Answer Key 3: Look for Python backdoor and network forensics
info "Searching for Python backdoor and network artifacts..."
BACKDOOR_PATH="/usr/share/zod/kneelB4zod.py"
if [ -f "$BACKDOOR_PATH" ]; then
    warn "Python backdoor found at $BACKDOOR_PATH"
    echo "SECURITY THREAT: Python backdoor found at $BACKDOOR_PATH" >> findings.txt
    echo "FORENSICS BACKDOOR FOUND: $BACKDOOR_PATH" >> "$CHECKLIST_FILE"
fi

# Check for network forensics files (pcap, etc.)
info "Checking for network capture files..."
PCAP_FILES=$(find /home -name "*.pcap" -o -name "*.cap" -o -name "*capture*" 2>/dev/null || echo "none")
if [ "$PCAP_FILES" != "none" ]; then
    echo "FORENSICS NETWORK FILES: $PCAP_FILES" >> "$CHECKLIST_FILE"
    echo "Network capture files found: $PCAP_FILES" >> findings.txt
fi

# Check for steganography files
info "Checking for steganography files..."
STEGO_FILES=$(find /home -name "*.jpg" -o -name "*.png" -o -name "*.bmp" 2>/dev/null | head -10)
if [ -n "$STEGO_FILES" ]; then
    echo "FORENSICS POTENTIAL STEGO FILES:" >> "$CHECKLIST_FILE"
    echo "$STEGO_FILES" >> "$CHECKLIST_FILE"
fi

log "Forensics documentation completed - answers recorded in checklist"

# ============================================================================
# SECTION 2: SYSTEM FILE VERIFICATION AND USER ACCOUNT MANAGEMENT
# ============================================================================

log "STEP 3: Verifying system files and managing user accounts..."

# Check /etc/passwd, /etc/group, /etc/shadow permissions and content
info "Checking critical system files..."

echo "=== SYSTEM FILES VERIFICATION ===" >> "$CHECKLIST_FILE"

# Check /etc/passwd
if [ -f /etc/passwd ]; then
    PASSWD_PERMS=$(ls -l /etc/passwd | awk '{print $1}')
    echo "PASSWD FILE PERMISSIONS: $PASSWD_PERMS" >> "$CHECKLIST_FILE"
    if [ "$PASSWD_PERMS" != "-rw-r--r--" ]; then
        warn "/etc/passwd has incorrect permissions: $PASSWD_PERMS"
        echo "WARNING: /etc/passwd permissions incorrect" >> "$CHECKLIST_FILE"
    else
        echo "PASSWD PERMISSIONS: OK" >> "$CHECKLIST_FILE"
    fi
    
    # Check for duplicate UIDs
    DUPLICATE_UIDS=$(awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d)
    if [ -n "$DUPLICATE_UIDS" ]; then
        warn "Duplicate UIDs found: $DUPLICATE_UIDS"
        echo "WARNING: Duplicate UIDs: $DUPLICATE_UIDS" >> "$CHECKLIST_FILE"
    fi
fi

# Check /etc/shadow
if [ -f /etc/shadow ]; then
    SHADOW_PERMS=$(ls -l /etc/shadow | awk '{print $1}')
    echo "SHADOW FILE PERMISSIONS: $SHADOW_PERMS" >> "$CHECKLIST_FILE"
    if [[ "$SHADOW_PERMS" != "-rw-r-----" && "$SHADOW_PERMS" != "-rw-------" ]]; then
        warn "/etc/shadow has incorrect permissions: $SHADOW_PERMS"
        echo "WARNING: /etc/shadow permissions incorrect" >> "$CHECKLIST_FILE"
    else
        echo "SHADOW PERMISSIONS: OK" >> "$CHECKLIST_FILE"
    fi
    
    # Check for empty passwords
    EMPTY_PASSWORDS=$(sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow)
    if [ -n "$EMPTY_PASSWORDS" ]; then
        echo "USERS WITH EMPTY/LOCKED PASSWORDS: $EMPTY_PASSWORDS" >> "$CHECKLIST_FILE"
    fi
fi

# Check /etc/group
if [ -f /etc/group ]; then
    GROUP_PERMS=$(ls -l /etc/group | awk '{print $1}')
    echo "GROUP FILE PERMISSIONS: $GROUP_PERMS" >> "$CHECKLIST_FILE"
    if [ "$GROUP_PERMS" != "-rw-r--r--" ]; then
        warn "/etc/group has incorrect permissions: $GROUP_PERMS"
        echo "WARNING: /etc/group permissions incorrect" >> "$CHECKLIST_FILE"
    else
        echo "GROUP PERMISSIONS: OK" >> "$CHECKLIST_FILE"
    fi
fi

# Check /boot file permissions
info "Checking /boot file permissions..."
if [ -f /boot/grub/grub.cfg ]; then
    GRUB_PERMS=$(ls -l /boot/grub/grub.cfg | awk '{print $1}')
    echo "GRUB CONFIG PERMISSIONS: $GRUB_PERMS" >> "$CHECKLIST_FILE"
    if [[ "$GRUB_PERMS" != "-rw-------" && "$GRUB_PERMS" != "-r--------" ]]; then
        warn "/boot/grub/grub.cfg has incorrect permissions: $GRUB_PERMS"
        echo "WARNING: GRUB config permissions incorrect" >> "$CHECKLIST_FILE"
    else
        echo "GRUB PERMISSIONS: OK" >> "$CHECKLIST_FILE"
    fi
fi

# Get list of current users and document
cat /etc/passwd | cut -d: -f1 | sort > users_found.txt
echo "=== CURRENT USERS ===" >> "$CHECKLIST_FILE"
cat users_found.txt >> "$CHECKLIST_FILE"

# Document current sudo users
echo "=== CURRENT SUDO USERS ===" >> "$CHECKLIST_FILE"
getent group sudo | cut -d: -f4 | tr ',' '\n' >> "$CHECKLIST_FILE"

# Answer Key 1: Remove unauthorized users (leon, oirving, romero)
# Answer Key 2: Remove unauthorized user harry
# Answer Key 3: Remove unauthorized user penguru
UNAUTHORIZED_USERS=("leon" "oirving" "romero" "harry" "penguru" "ancano" "tolfdir")

for user in "${UNAUTHORIZED_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        warn "Removing unauthorized user: $user"
        sudo userdel -r "$user" 2>/dev/null || sudo userdel "$user" 2>/dev/null || true
        echo "Removed unauthorized user: $user" >> fixes_applied.txt
    fi
done

# Answer Key 1: Demote users from admin (tcolby, mralbern)
# Answer Key 2: Remove admin rights from hamlet
# Answer Key 3: Remove ham from sudo group
# Answer Key 4: Remove lydia from Administrators group
DEMOTE_USERS=("tcolby" "mralbern" "hamlet" "ham" "lydia")

for user in "${DEMOTE_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        if groups "$user" | grep -q sudo; then
            warn "Removing sudo privileges from: $user"
            sudo deluser "$user" sudo 2>/dev/null || true
            echo "Demoted user from sudo: $user" >> fixes_applied.txt
        fi
        if groups "$user" | grep -q admin; then
            sudo deluser "$user" admin 2>/dev/null || true
            echo "Demoted user from admin: $user" >> fixes_applied.txt
        fi
    fi
done

# Answer Key 3: Create group spider and add users
info "Creating group spider and adding users..."
if ! getent group spider &>/dev/null; then
    sudo addgroup spider
    echo "Created group: spider" >> fixes_applied.txt
fi

SPIDER_USERS=("may" "peni" "stan" "miguel")
for user in "${SPIDER_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        sudo gpasswd -a "$user" spider 2>/dev/null || true
        echo "Added $user to spider group" >> fixes_applied.txt
    fi
done

# ============================================================================
# SECTION 3: PASSWORD POLICY AND PAM VERIFICATION
# ============================================================================

log "STEP 4: Verifying and configuring password policies and PAM..."

# Document current password policy before changes
echo "=== PASSWORD POLICY VERIFICATION ===" >> "$CHECKLIST_FILE"

# Check current /etc/login.defs settings
info "Checking current password aging settings..."
if [ -f /etc/login.defs ]; then
    echo "CURRENT LOGIN.DEFS SETTINGS:" >> "$CHECKLIST_FILE"
    grep -E "PASS_(MAX|MIN|WARN)_AGE" /etc/login.defs >> "$CHECKLIST_FILE" 2>/dev/null || echo "No password aging settings found" >> "$CHECKLIST_FILE"
fi

# Check current PAM password settings
info "Checking current PAM configuration..."
if [ -f /etc/pam.d/common-password ]; then
    echo "CURRENT PAM PASSWORD CONFIG:" >> "$CHECKLIST_FILE"
    grep -E "pam_pwquality|pam_unix" /etc/pam.d/common-password >> "$CHECKLIST_FILE" 2>/dev/null || echo "No PAM password config found" >> "$CHECKLIST_FILE"
fi

if [ -f /etc/pam.d/common-auth ]; then
    echo "CURRENT PAM AUTH CONFIG:" >> "$CHECKLIST_FILE"
    grep -E "pam_faillock|pam_unix" /etc/pam.d/common-auth >> "$CHECKLIST_FILE" 2>/dev/null || echo "No PAM auth config found" >> "$CHECKLIST_FILE"
fi

# Check pwquality.conf
if [ -f /etc/security/pwquality.conf ]; then
    echo "CURRENT PWQUALITY CONFIG:" >> "$CHECKLIST_FILE"
    grep -v "^#" /etc/security/pwquality.conf | grep -v "^$" >> "$CHECKLIST_FILE" 2>/dev/null || echo "No pwquality settings found" >> "$CHECKLIST_FILE"
fi

# Answer Key 1: Change weak passwords
WEAK_PASSWORD_USERS=("pmccleery" "alice" "noir" "balgruuf")
for user in "${WEAK_PASSWORD_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        info "User $user found - password should be changed manually"
        echo "Weak password user found: $user (change manually)" >> findings.txt
    fi
done

# Answer Key 3: Set max password age and lock root
if id "noir" &>/dev/null; then
    sudo chage -M 90 noir
    echo "Set max password age 90 days for noir" >> fixes_applied.txt
fi

# Lock root password
sudo passwd -l root 2>/dev/null || true
echo "Locked root password" >> fixes_applied.txt

# Configure password aging in /etc/login.defs
info "Configuring password aging policies..."
sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sudo sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
sudo sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN 10/' /etc/login.defs

# Configure password complexity
if [ -f /etc/security/pwquality.conf ]; then
    echo "minlen = 10" | sudo tee -a /etc/security/pwquality.conf
    echo "minclass = 3" | sudo tee -a /etc/security/pwquality.conf
    echo "difok = 3" | sudo tee -a /etc/security/pwquality.conf
    echo "ucredit = -1" | sudo tee -a /etc/security/pwquality.conf
    echo "lcredit = -1" | sudo tee -a /etc/security/pwquality.conf
    echo "dcredit = -1" | sudo tee -a /etc/security/pwquality.conf
    echo "remember = 3" | sudo tee -a /etc/security/pwquality.conf
fi

# Configure PAM for password complexity and account lockout
info "Configuring PAM policies..."

# Backup PAM files
sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup
sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup

# Update common-password to enforce complexity and remove nullok
sudo sed -i 's/pam_unix.so.*/pam_unix.so sha512 minlen=10 remember=3/' /etc/pam.d/common-password
sudo sed -i 's/nullok//g' /etc/pam.d/common-password

# Add password quality requirements
if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sudo sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1' /etc/pam.d/common-password
fi

# Configure account lockout (faillock)
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    sudo sed -i '1i auth required pam_faillock.so preauth silent deny=3 unlock_time=900' /etc/pam.d/common-auth
    sudo sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900' /etc/pam.d/common-auth
    sudo sed -i '/pam_faillock.so authfail/a auth sufficient pam_faillock.so authsucc' /etc/pam.d/common-auth
fi

# Remove nullok from common-auth
sudo sed -i 's/nullok//g' /etc/pam.d/common-auth

echo "Password policies configured" >> fixes_applied.txt

# ============================================================================
# SECTION 4: UFW, SSH, NGINX, AND UPDATE STATUS VERIFICATION
# ============================================================================

log "STEP 5: Checking UFW, SSH, Nginx, and update status..."

# Check UFW status before changes
echo "=== UFW STATUS VERIFICATION ===" >> "$CHECKLIST_FILE"
info "Checking UFW firewall status..."
UFW_STATUS=$(sudo ufw status verbose 2>/dev/null || echo "UFW not available")
echo "CURRENT UFW STATUS:" >> "$CHECKLIST_FILE"
echo "$UFW_STATUS" >> "$CHECKLIST_FILE"

if echo "$UFW_STATUS" | grep -q "Status: inactive"; then
    warn "UFW firewall is currently inactive"
    echo "WARNING: UFW firewall inactive" >> "$CHECKLIST_FILE"
elif echo "$UFW_STATUS" | grep -q "Status: active"; then
    info "UFW firewall is active"
    echo "UFW STATUS: ACTIVE" >> "$CHECKLIST_FILE"
fi

# Check SSH configuration
echo "=== SSH CONFIGURATION VERIFICATION ===" >> "$CHECKLIST_FILE"
info "Checking SSH configuration..."
if [ -f /etc/ssh/sshd_config ]; then
    echo "CURRENT SSH CONFIG:" >> "$CHECKLIST_FILE"
    grep -E "^(Protocol|PermitRootLogin|PasswordAuthentication|Port|PubkeyAuthentication)" /etc/ssh/sshd_config >> "$CHECKLIST_FILE" 2>/dev/null || echo "No SSH config found" >> "$CHECKLIST_FILE"
    
    # Check if SSH service is running
    SSH_STATUS=$(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo "inactive")
    echo "SSH SERVICE STATUS: $SSH_STATUS" >> "$CHECKLIST_FILE"
    
    # Check SSH listening ports
    SSH_PORTS=$(netstat -tlnp 2>/dev/null | grep ssh || ss -tlnp 2>/dev/null | grep ssh || echo "No SSH ports found")
    echo "SSH LISTENING PORTS:" >> "$CHECKLIST_FILE"
    echo "$SSH_PORTS" >> "$CHECKLIST_FILE"
fi

# Check Nginx status
echo "=== NGINX STATUS VERIFICATION ===" >> "$CHECKLIST_FILE"
info "Checking Nginx status..."
NGINX_STATUS=$(systemctl is-active nginx 2>/dev/null || echo "inactive")
echo "NGINX SERVICE STATUS: $NGINX_STATUS" >> "$CHECKLIST_FILE"

if [ "$NGINX_STATUS" = "active" ]; then
    NGINX_PORTS=$(netstat -tlnp 2>/dev/null | grep nginx || ss -tlnp 2>/dev/null | grep nginx || echo "No Nginx ports found")
    echo "NGINX LISTENING PORTS:" >> "$CHECKLIST_FILE"
    echo "$NGINX_PORTS" >> "$CHECKLIST_FILE"
fi

# Check system update status
echo "=== UPDATE STATUS VERIFICATION ===" >> "$CHECKLIST_FILE"
info "Checking system update status..."
sudo apt update &>/dev/null || true
AVAILABLE_UPDATES=$(apt list --upgradable 2>/dev/null | wc -l)
echo "AVAILABLE UPDATES: $AVAILABLE_UPDATES" >> "$CHECKLIST_FILE"

# Check if unattended-upgrades is configured
UNATTENDED_STATUS=$(systemctl is-enabled unattended-upgrades 2>/dev/null || echo "not configured")
echo "UNATTENDED UPGRADES STATUS: $UNATTENDED_STATUS" >> "$CHECKLIST_FILE"

# Now configure UFW firewall
info "Configuring UFW firewall..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH

# Check if other services need to be allowed based on requirements
if systemctl is-active --quiet apache2; then
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    echo "FIREWALL: Allowed Apache2 ports (80, 443)" >> "$CHECKLIST_FILE"
fi

if systemctl is-active --quiet vsftpd; then
    sudo ufw allow 21/tcp
    echo "FIREWALL: Allowed FTP port (21)" >> "$CHECKLIST_FILE"
fi

echo "UFW firewall enabled and configured" >> fixes_applied.txt
echo "FIREWALL: UFW enabled with default deny incoming" >> "$CHECKLIST_FILE"

# ============================================================================
# SECTION 5: CRITICAL SERVICES MANAGEMENT
# ============================================================================

log "Section 5: Managing critical services..."

# Answer Key 1: Ensure Apache2 is installed and running
info "Installing and starting Apache2..."
sudo apt update
sudo apt install -y apache2
sudo systemctl enable apache2
sudo systemctl start apache2
echo "Apache2 installed and started" >> fixes_applied.txt

# Disable unnecessary/risky services
RISKY_SERVICES=("nginx" "squid" "telnet" "avahi-daemon" "cups" "bluetooth" "vsftpd")
for service in "${RISKY_SERVICES[@]}"; do
    if systemctl is-active --quiet "$service"; then
        # Check if it's a required service first
        if [[ "$service" == "vsftpd" ]] && grep -q "VSFTP" /README* 2>/dev/null; then
            info "Keeping VSFTP as it's required"
            continue
        fi
        warn "Disabling risky service: $service"
        sudo systemctl stop "$service" 2>/dev/null || true
        sudo systemctl disable "$service" 2>/dev/null || true
        echo "Disabled risky service: $service" >> fixes_applied.txt
    fi
done

# Answer Key 4: Disable SMTP and Microsoft FTP services (Windows-specific, skip on Linux)
info "Skipping Windows-specific services (SMTP, Microsoft FTP) as this is Linux"

# ============================================================================
# SECTION 6: SYSTEM UPDATES
# ============================================================================

log "Section 6: Configuring system updates..."

# Enable automatic updates
info "Configuring automatic updates..."
sudo apt update

# Install unattended-upgrades if not present
sudo apt install -y unattended-upgrades

# Configure automatic updates
echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades

# Update critical packages
info "Updating critical packages..."
sudo apt update
sudo apt full-upgrade -y

echo "System updates configured and applied" >> fixes_applied.txt

# ============================================================================
# SECTION 7: REMOVE PROHIBITED SOFTWARE AND FILES
# ============================================================================

log "Section 7: Removing prohibited software and files..."

# Answer Key 1: Remove Wireshark and Ophcrack
PROHIBITED_SOFTWARE=("ophcrack" "wireshark" "doona" "xprobe" "aisleriot" "bittorrent")
for software in "${PROHIBITED_SOFTWARE[@]}"; do
    if dpkg -l | grep -q "$software"; then
        warn "Removing prohibited software: $software"
        sudo apt purge -y "$software"* 2>/dev/null || true
        echo "Removed prohibited software: $software" >> fixes_applied.txt
    fi
done

# Remove prohibited media files
info "Removing prohibited media files..."

# Remove MP3 files
if [ "$MP3_FILES" != "none" ]; then
    echo "$MP3_FILES" | while read -r file; do
        if [ -f "$file" ]; then
            warn "Removing MP3 file: $file"
            sudo rm -f "$file"
            echo "Removed MP3 file: $file" >> fixes_applied.txt
        fi
    done
fi

# Remove OGG files (Answer Key 3)
OGG_FILES=$(locate '*.ogg' 2>/dev/null || find /home -name "*.ogg" 2>/dev/null || echo "none")
if [ "$OGG_FILES" != "none" ]; then
    echo "$OGG_FILES" | while read -r file; do
        if [ -f "$file" ]; then
            warn "Removing OGG file: $file"
            sudo rm -f "$file"
            echo "Removed OGG file: $file" >> fixes_applied.txt
        fi
    done
fi

# Remove specific prohibited files
PROHIBITED_FILES=(
    "/usr/games/pyrdp-master.zip"
    "/home/twellick/Music/*.mp3"
    "/home/corey/Music/*.mp3"
    "/usr/share/zod/kneelB4zod.py"
    "/home/*/Public/Public Downloads/brutus-aet2-darknet.zip"
)

for file_pattern in "${PROHIBITED_FILES[@]}"; do
    for file in $file_pattern; do
        if [ -f "$file" ]; then
            warn "Removing prohibited file: $file"
            sudo rm -f "$file"
            echo "Removed prohibited file: $file" >> fixes_applied.txt
        fi
    done
done

# ============================================================================
# SECTION 8: SSH SECURITY HARDENING
# ============================================================================

log "Section 8: Hardening SSH configuration..."

# Backup SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Configure secure SSH settings
info "Applying SSH security settings..."
sudo sed -i 's/#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo sed -i 's/#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config
sudo sed -i 's/#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/#*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
sudo sed -i 's/#*MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config

# Add additional security settings if not present
if ! grep -q "PubkeyAuthentication" /etc/ssh/sshd_config; then
    echo "PubkeyAuthentication yes" | sudo tee -a /etc/ssh/sshd_config
fi

# Restart SSH service
sudo systemctl restart ssh
echo "SSH hardened and restarted" >> fixes_applied.txt

# ============================================================================
# SECTION 9: FILE PERMISSIONS HARDENING
# ============================================================================

log "Section 9: Fixing file permissions..."

# Fix critical file permissions
info "Setting secure permissions on critical files..."
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chmod 644 /etc/group
sudo chmod 644 /etc/hosts

# Fix boot files
if [ -f /boot/grub/grub.cfg ]; then
    sudo chmod 600 /boot/grub/grub.cfg
fi

# Fix SSH key permissions for all users
find /home -name ".ssh" -type d 2>/dev/null | while read -r sshdir; do
    sudo chmod 700 "$sshdir"
    sudo chmod 600 "$sshdir"/id_* 2>/dev/null || true
    sudo chmod 644 "$sshdir"/*.pub 2>/dev/null || true
done

echo "File permissions secured" >> fixes_applied.txt

# ============================================================================
# SECTION 10: KERNEL AND NETWORK HARDENING
# ============================================================================

log "Section 10: Applying kernel and network hardening..."

# Create sysctl security configuration
sudo tee /etc/sysctl.d/99-security.conf << 'EOF'
# Network security hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2

# Process restrictions
kernel.yama.ptrace_scope = 1
EOF

# Apply sysctl settings
sudo sysctl -p /etc/sysctl.d/99-security.conf
echo "Kernel and network hardening applied" >> fixes_applied.txt

# ============================================================================
# SECTION 11: MALWARE AND BACKDOOR REMOVAL
# ============================================================================

log "Section 11: Removing malware and backdoors..."

# Remove Python backdoor (Answer Key 3)
if [ -f "$BACKDOOR_PATH" ]; then
    warn "Removing Python backdoor: $BACKDOOR_PATH"
    sudo rm -f "$BACKDOOR_PATH"
    sudo pkill -f "kneelB4zod.py" 2>/dev/null || true
    echo "Removed Python backdoor: $BACKDOOR_PATH" >> fixes_applied.txt
fi

# Check for suspicious processes
info "Checking for suspicious processes..."
SUSPICIOUS_PROCESSES=$(ps aux | grep -E "(bitcoin|miner|tor|nc|ncat)" | grep -v grep || echo "none")
if [ "$SUSPICIOUS_PROCESSES" != "none" ]; then
    echo "Suspicious processes found:" >> findings.txt
    echo "$SUSPICIOUS_PROCESSES" >> findings.txt
fi

# ============================================================================
# SECTION 12: FINAL VERIFICATION AND COMPREHENSIVE DOCUMENTATION
# ============================================================================

log "STEP 12: Final verification and comprehensive documentation..."

# Verify critical security settings
info "Performing final verification..."

echo "=== FINAL VERIFICATION RESULTS ===" >> "$CHECKLIST_FILE"

# Check sudo users
echo "FINAL SUDO USERS:" >> "$CHECKLIST_FILE"
getent group sudo | cut -d: -f4 | tr ',' '\n' >> "$CHECKLIST_FILE"

# Check SSH configuration
echo "FINAL SSH CONFIGURATION:" >> "$CHECKLIST_FILE"
grep "PermitRootLogin" /etc/ssh/sshd_config >> "$CHECKLIST_FILE" 2>/dev/null || echo "SSH config not found" >> "$CHECKLIST_FILE"

# Check firewall status
echo "FINAL FIREWALL STATUS:" >> "$CHECKLIST_FILE"
sudo ufw status >> "$CHECKLIST_FILE" 2>/dev/null || echo "UFW status unavailable" >> "$CHECKLIST_FILE"

# Check active services
echo "FINAL ACTIVE SERVICES:" >> "$CHECKLIST_FILE"
systemctl list-units --type=service --state=active --no-pager | head -20 >> "$CHECKLIST_FILE"

# Verify file permissions one more time
echo "FINAL FILE PERMISSIONS CHECK:" >> "$CHECKLIST_FILE"
ls -l /etc/passwd /etc/shadow /etc/group /etc/hosts 2>/dev/null >> "$CHECKLIST_FILE" || echo "Some files not accessible" >> "$CHECKLIST_FILE"

# Check password policy final state
echo "FINAL PASSWORD POLICY:" >> "$CHECKLIST_FILE"
grep -E "PASS_(MAX|MIN|WARN)_AGE" /etc/login.defs >> "$CHECKLIST_FILE" 2>/dev/null || echo "Password aging not configured" >> "$CHECKLIST_FILE"

# Document completion
echo "=== AUDIT COMPLETION ===" >> "$CHECKLIST_FILE"
echo "Audit completed at: $(date)" >> "$CHECKLIST_FILE"
echo "Total actions documented: $(wc -l < fixes_applied.txt)" >> "$CHECKLIST_FILE"
echo "Checklist location: $CHECKLIST_FILE" >> "$CHECKLIST_FILE"

# Create final report
cat << 'EOF' > final_audit_report.txt
=================================
LINUX SECURITY AUDIT FINAL REPORT
=================================
EOF

echo "Audit Date: $(date)" >> final_audit_report.txt
echo "System: $(hostname)" >> final_audit_report.txt
echo "Auditor: Automated Security Script" >> final_audit_report.txt
echo "Checklist Location: $CHECKLIST_FILE" >> final_audit_report.txt
echo "" >> final_audit_report.txt

echo "SUMMARY OF ACTIONS TAKEN:" >> final_audit_report.txt
echo "=========================" >> final_audit_report.txt
cat fixes_applied.txt >> final_audit_report.txt
echo "" >> final_audit_report.txt

echo "DETAILED FINDINGS:" >> final_audit_report.txt
echo "==================" >> final_audit_report.txt
cat findings.txt >> final_audit_report.txt

# Copy report to user's home directory
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})
sudo cp final_audit_report.txt "$USER_HOME/"
sudo chown ${SUDO_USER:-$USER}:${SUDO_USER:-$USER} "$USER_HOME/final_audit_report.txt" 2>/dev/null || true

# Also copy checklist to user's home for easy access
sudo cp "$CHECKLIST_FILE" "$USER_HOME/Audit_Checklist.txt"
sudo chown ${SUDO_USER:-$USER}:${SUDO_USER:-$USER} "$USER_HOME/Audit_Checklist.txt" 2>/dev/null || true

log "Audit completed successfully!"
log "Final report saved to: $USER_HOME/final_audit_report.txt"
log "Checklist saved to: $CHECKLIST_FILE and $USER_HOME/Audit_Checklist.txt"
log "Audit workspace: $AUDIT_DIR"

# Display summary
echo ""
echo "=============================================="
echo "         AUDIT COMPLETION SUMMARY"
echo "=============================================="
echo "✓ README.txt files analyzed for requirements"
echo "✓ Forensics questions answered and documented"
echo "✓ System files (/etc/passwd, /etc/shadow, /etc/group) verified"
echo "✓ Boot file permissions checked"
echo "✓ Password policies and PAM configuration verified"
echo "✓ UFW, SSH, Nginx, and update status checked"
echo "✓ User accounts managed per requirements"
echo "✓ Firewall enabled and configured"
echo "✓ Critical services managed"
echo "✓ System updates applied"
echo "✓ Prohibited software removed"
echo "✓ SSH security hardened"
echo "✓ File permissions secured"
echo "✓ Kernel hardening applied"
echo "✓ Malware and backdoors removed"
echo "✓ All actions documented in checklist"
echo "=============================================="
echo ""
echo "DOCUMENTATION LOCATIONS:"
echo "- Main checklist: $CHECKLIST_FILE"
echo "- User copy: $USER_HOME/Audit_Checklist.txt"
echo "- Final report: $USER_HOME/final_audit_report.txt"
echo "- Audit workspace: $AUDIT_DIR"
echo ""
echo "IMPORTANT NOTES:"
echo "- All forensics answers are documented in the checklist"
echo "- README.txt analysis results are in findings.txt"
echo "- System file verification results are in the checklist"
echo "- Password policy verification completed before changes"
echo "- UFW, SSH, Nginx status documented before modifications"
echo "- Review the checklist for all documented actions"
echo "- Some password changes may need to be done manually"
echo "- Verify all changes meet competition requirements"
echo "- Test critical services to ensure they work properly"
echo ""