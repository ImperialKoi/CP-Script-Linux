# Linux Security Audit Manual Cheat Sheet

## Competition Image Manual Audit Workflow (Ubuntu/Mint)

**Purpose:** Manual step-by-step security audit for students who cannot run automation  
**Target:** Ubuntu/Mint competition images  
**Time:** 2-3 hours for complete audit  
**Team:** 2-4 students recommended  

---

## Workflow Overview

```
System Preparation → User/Group Audit → Password Policy → File Permissions 
      ↓                    ↓                  ↓              ↓
   SSH Security  ←  Firewall Audit  ←  Services Audit  ←  System Updates
      ↓                    ↓                  ↓              ↓
Kernel Security  →  Malware Detection  →  Final Documentation & Report
```

---

## Phase 1: System Preparation (5 minutes)

### Initial Setup Commands

```bash
# Open terminal and gain root access
sudo -i

# Create audit workspace
mkdir -p /tmp/audit_$(date +%Y%m%d_%H%M)
cd /tmp/audit_$(date +%Y%m%d_%H%M)

# Create documentation files
touch findings.txt fixes_applied.txt users_found.txt services_found.txt

# Record system information
echo "=== SYSTEM AUDIT START ===" > findings.txt
echo "Date: $(date)" >> findings.txt
echo "Hostname: $(hostname)" >> findings.txt
echo "OS: $(lsb_release -d)" >> findings.txt
echo "Kernel: $(uname -r)" >> findings.txt
echo "=========================" >> findings.txt
```

---

## Phase 2: Users & Groups Audit (20 minutes)

### Step 1: List All Users (5 minutes)

```bash
# Show all user accounts
cat /etc/passwd | cut -d: -f1 | sort

# Show human users (UID >= 1000)
awk -F: '$3 >= 1000 {print $1 " (UID:" $3 ")"}' /etc/passwd

# Check for users with empty passwords  
awk -F: '($2 == "") {print $1}' /etc/shadow

# Record users found
cat /etc/passwd | cut -d: -f1 > users_found.txt
```

### Step 2: Check Administrative Users (5 minutes)

```bash
# List sudo group members
getent group sudo | cut -d: -f4 | tr ',' '\n'

# List admin group members
getent group admin | cut -d: -f4 | tr ',' '\n' 2>/dev/null

# Find users with UID 0 (root privileges)  
awk -F: '$3 == 0 {print $1}' /etc/passwd

# ACTION REQUIRED: Compare with competition requirements
# Remove unauthorized sudo users with: sudo deluser USERNAME sudo
```

### Step 3: Validate User Accounts (5 minutes)

```bash
# Check for duplicate UIDs
awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d

# Check for duplicate usernames
cut -d: -f1 /etc/passwd | sort | uniq -d

# Find users with no home directory
while read user home; do 
    if [ ! -d "$home" ]; then 
        echo "Missing home: $user ($home)"
    fi
done < <(awk -F: '{print $1 " " $6}' /etc/passwd)

# Document findings
echo "=== USER AUDIT RESULTS ===" >> findings.txt
echo "Total users: $(wc -l < /etc/passwd)" >> findings.txt
```

### Step 4: Remove Unauthorized Users (5 minutes)

```bash
# DANGER: Only remove users NOT in competition requirements
# Remove user completely: sudo userdel -r USERNAME
# Remove from sudo group: sudo deluser USERNAME sudo  
# Lock user account: sudo passwd -l USERNAME

# Document changes
echo "Removed users: [list here]" >> fixes_applied.txt
```

---

## Phase 3: Password Policy Audit (15 minutes)

### Key Files to Check
- /etc/pam.d/common-password
- /etc/login.defs
- /etc/security/pwquality.conf

### Step 1: Check Current Password Policies (5 minutes)

```bash
# Check password aging settings
grep -E "PASS_(MAX|MIN|WARN)_AGE" /etc/login.defs

# Check password complexity rules
grep -v "^#" /etc/security/pwquality.conf | grep -v "^$"

# Check PAM password settings  
grep -E "pam_pwquality|pam_unix" /etc/pam.d/common-password
```

### Step 2: Fix Password Policies (10 minutes)

```bash
# Set password aging in /etc/login.defs
sudo sed -i 's/PASS_MAX_AGE.*/PASS_MAX_AGE 90/' /etc/login.defs
sudo sed -i 's/PASS_MIN_AGE.*/PASS_MIN_AGE 1/' /etc/login.defs
sudo sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

# Enable password complexity
echo "minlen = 12" | sudo tee -a /etc/security/pwquality.conf
echo "minclass = 3" | sudo tee -a /etc/security/pwquality.conf

# Document changes
echo "Password policies updated: $(date)" >> fixes_applied.txt
```

---

## Phase 4: File Permissions Audit (25 minutes)

### Critical Files Checklist
```
□ /etc/passwd (644)        □ /etc/shadow (640)
□ /etc/group (644)         □ /etc/hosts (644)  
□ /boot/grub/grub.cfg (600)   □ SSH keys (~/.ssh/*)
```

### Step 1: Check Critical System Files (10 minutes)

```bash
# Check permissions of critical files
ls -l /etc/passwd /etc/shadow /etc/group /etc/hosts

# Find world-writable files (SECURITY RISK)
find /etc /bin /sbin /usr -type f -perm -002 2>/dev/null

# Find SUID files (potential risk)
find / -type f -perm -4000 2>/dev/null | head -20

# Document findings
echo "=== FILE PERMISSIONS AUDIT ===" >> findings.txt
```

### Step 2: Check SSH Key Permissions (5 minutes)

```bash
# Find all SSH directories
find /home -name ".ssh" -type d 2>/dev/null

# Check SSH key permissions
for sshdir in $(find /home -name ".ssh" -type d 2>/dev/null); do
    echo "=== $sshdir ==="
    ls -la "$sshdir/"
done

# Fix SSH permissions if needed:
# chmod 700 /home/user/.ssh
# chmod 600 /home/user/.ssh/id_*
# chmod 644 /home/user/.ssh/*.pub
```

### Step 3: Fix File Permissions (10 minutes)

```bash
# Fix critical file permissions
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chmod 644 /etc/group  
sudo chmod 644 /etc/hosts

# Fix boot files
sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null

# Document changes
echo "File permissions fixed: $(date)" >> fixes_applied.txt
```

---

## Phase 5: SSH Security Audit (15 minutes)

### SSH Configuration Checklist
```
□ SSH Protocol 2 only       □ Root login disabled
□ Password authentication   □ Port configuration
□ Strong ciphers only      □ Login banner
```

### Step 1: Check SSH Service (3 minutes)

```bash
# Check if SSH is running
systemctl status ssh

# Check SSH is listening
netstat -tlnp | grep :22
```

### Step 2: Audit SSH Configuration (7 minutes)

```bash
# Backup SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Check critical SSH settings
grep -E "^(Protocol|PermitRootLogin|PasswordAuthentication|Port)" /etc/ssh/sshd_config

# Document current settings
echo "=== SSH CONFIGURATION ===" >> findings.txt
grep -E "^[^#]" /etc/ssh/sshd_config >> findings.txt
```

### Step 3: Harden SSH Configuration (5 minutes)

```bash
# Set secure SSH options (verify competition requirements first!)
sudo sed -i 's/#Protocol.*/Protocol 2/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Restart SSH service
sudo systemctl restart ssh

# Document changes
echo "SSH hardened: $(date)" >> fixes_applied.txt
```

---

## Phase 6: Firewall Audit (10 minutes)

### Step 1: Check Firewall Status (3 minutes)

```bash
# Check UFW status
sudo ufw status verbose

# Check iptables rules
sudo iptables -L -n

# Check listening ports
netstat -tlnp
```

### Step 2: Configure Basic Firewall (7 minutes)

```bash
# Enable UFW
sudo ufw --force enable

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (adjust port if needed)
sudo ufw allow 22/tcp

# Check final status
sudo ufw status numbered

# Document configuration
echo "Firewall configured: $(date)" >> fixes_applied.txt
```

---

## Phase 7: Services Audit (20 minutes)

### Step 1: List All Services (10 minutes)

```bash
# List all active services
systemctl list-units --type=service --state=active

# List enabled services
systemctl list-unit-files --type=service --state=enabled

# Check for suspicious services
systemctl list-units --type=service | grep -E "(bitcoin|tor|p2p|mining)"

# Document all services
systemctl list-units --type=service --state=active > services_found.txt
```

### Step 2: Check Network Services (5 minutes)

```bash
# Check what's listening on network
ss -tlnp

# Check for unauthorized servers
netstat -tlnp | grep -E ":(21|23|25|53|80|110|143|443|993|995)"

# Document network services
echo "=== NETWORK SERVICES AUDIT ===" >> findings.txt
netstat -tlnp >> findings.txt
```

### Step 3: Disable Risky Services (5 minutes)

```bash
# Check common risky services
services_to_check="telnet vsftpd apache2 nginx avahi-daemon cups bluetooth"

for service in $services_to_check; do
    if systemctl is-active --quiet $service; then
        echo "Found active service: $service"
        # Uncomment next lines to disable:
        # sudo systemctl stop $service
        # sudo systemctl disable $service
    fi
done

# Document changes
echo "Services disabled: [list here]" >> fixes_applied.txt
```

---

## Phase 8: System Updates Audit (10 minutes)

### Step 1: Check Update Status (5 minutes)

```bash
# Update package list
sudo apt update

# Check available updates
apt list --upgradable

# Document update status
echo "=== SYSTEM UPDATES ===" >> findings.txt
echo "Available updates: $(apt list --upgradable 2>/dev/null | wc -l)" >> findings.txt
```

### Step 2: Apply Updates (5 minutes)

```bash
# COMPETITION RULE: Check if updates are allowed first!

# Install security updates only
sudo unattended-upgrade

# Install all updates (if competition allows):
# sudo apt upgrade -y

# Document updates
echo "Updates applied: $(date)" >> fixes_applied.txt
```

---

## Phase 9: Kernel Security (15 minutes)

### Step 1: Check Kernel Parameters (5 minutes)

```bash
# Check current security parameters
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.all.send_redirects
sysctl kernel.dmesg_restrict

# Check custom settings
cat /etc/sysctl.conf | grep -v "^#" | grep -v "^$"
```

### Step 2: Harden Kernel Settings (10 minutes)

```bash
# Create security configuration
sudo tee -a /etc/sysctl.d/99-security.conf << 'EOF'
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1

# Memory protection  
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
EOF

# Apply settings
sudo sysctl -p /etc/sysctl.d/99-security.conf

# Document changes
echo "Kernel hardened: $(date)" >> fixes_applied.txt
```

---

## Phase 10: Basic Malware Detection (15 minutes)

### Step 1: Check Processes (5 minutes)

```bash
# List all processes
ps aux

# Check for high resource usage
top -b -n1 | head -20

# Look for suspicious processes
ps aux | grep -E "(bitcoin|miner|tor|nc|ncat)"
```

### Step 2: Check Files (5 minutes)

```bash
# Find recently modified files
find / -type f -mtime -1 2>/dev/null | grep -v "/proc\|/sys\|/run" | head -20

# Find executables in temp directories
find /tmp /var/tmp -type f -executable 2>/dev/null

# Check for hidden files
find /home -name ".*" -type f 2>/dev/null | grep -v ".bash\|.profile\|.cache"
```

### Step 3: Check Network (5 minutes)

```bash
# Check active connections
netstat -antup

# Look for suspicious outbound connections
ss -tupln | grep ESTAB

# Document findings
echo "=== MALWARE SCAN RESULTS ===" >> findings.txt
echo "Suspicious items: [none found or list here]" >> findings.txt
```

---

## Phase 11: Final Documentation (10 minutes)

### Create Final Report

```bash
# Compile audit report
cat << 'EOF' > final_audit_report.txt
=================================
LINUX SECURITY AUDIT FINAL REPORT
=================================

Audit Date: $(date)
System: $(hostname)  
Auditor: [Your Name]

SUMMARY:
========
EOF

# Add summary statistics
echo "Users audited: $(wc -l < users_found.txt)" >> final_audit_report.txt
echo "Services checked: $(wc -l < services_found.txt)" >> final_audit_report.txt
echo "" >> final_audit_report.txt

# Append detailed findings
cat findings.txt >> final_audit_report.txt
echo "" >> final_audit_report.txt
echo "FIXES APPLIED:" >> final_audit_report.txt
cat fixes_applied.txt >> final_audit_report.txt

# Save to home directory
sudo cp final_audit_report.txt /home/$(logname)/
sudo chown $(logname):$(logname) /home/$(logname)/final_audit_report.txt

echo "AUDIT COMPLETE! Report saved to /home/$(logname)/final_audit_report.txt"
```

---

## Quick Reference: Emergency Commands

### Critical Security Actions

```bash
# Lock user account immediately
sudo passwd -l USERNAME

# Kill suspicious process  
sudo kill -9 PID

# Block IP address
sudo ufw deny from IP_ADDRESS

# Disable service immediately
sudo systemctl stop SERVICE_NAME
sudo systemctl disable SERVICE_NAME

# Emergency firewall lockdown
sudo ufw --force reset
sudo ufw default deny incoming  
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw --force enable
```

---

## Time Management & Team Roles

### Phase Time Limits
- System Setup: 5 minutes
- Users/Groups: 20 minutes  
- Passwords: 15 minutes
- File Permissions: 25 minutes
- SSH: 15 minutes
- Firewall: 10 minutes
- Services: 20 minutes
- Updates: 10 minutes  
- Kernel: 15 minutes
- Malware: 15 minutes
- Documentation: 10 minutes
- **Total: 160 minutes (2h 40m)**

### Suggested Team Roles
- **Student A:** Users, Groups, Passwords (35 min)
- **Student B:** File Permissions, SSH (40 min)  
- **Student C:** Services, Firewall (30 min)
- **Student D:** Updates, Kernel, Malware, Docs (50 min)

---

## Important Reminders

1. **Check competition requirements** before making ANY changes
2. **Document everything** for scoring points
3. **Test services** after configuration changes
4. **Keep backups** of all configuration files  
5. **Work systematically** through each phase
6. **Verify fixes** before moving to next phase

**Success Goal:** Complete systematic audit in under 3 hours with comprehensive documentation!