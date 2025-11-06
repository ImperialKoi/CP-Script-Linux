# Linux Security Audit Quick Reference Card

## Competition Commands Cheat Sheet (Ubuntu/Mint)

**PRINT THIS PAGE** for quick reference during competition!

---

### 🚨 EMERGENCY COMMANDS (Use Immediately)

```bash
# Lock suspicious user
sudo passwd -l USERNAME

# Kill bad process  
sudo kill -9 PID

# Emergency firewall
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw allow 22/tcp

# Disable risky service
sudo systemctl stop SERVICE
sudo systemctl disable SERVICE
```

---

### 👥 USER AUDIT (20 minutes)

```bash
# List all users
cut -d: -f1 /etc/passwd | sort

# Check sudo users
getent group sudo | cut -d: -f4 | tr ',' '\n'

# Find root users (UID 0)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Remove from sudo
sudo deluser USERNAME sudo

# Lock account
sudo passwd -l USERNAME
```

---

### 🔐 PASSWORD POLICY (15 minutes)

```bash
# Check password settings
grep PASS_ /etc/login.defs
grep -v "^#" /etc/security/pwquality.conf

# Fix password aging
sudo sed -i 's/PASS_MAX_AGE.*/PASS_MAX_AGE 90/' /etc/login.defs
sudo sed -i 's/PASS_MIN_AGE.*/PASS_MIN_AGE 1/' /etc/login.defs

# Add complexity
echo "minlen = 12" | sudo tee -a /etc/security/pwquality.conf
echo "minclass = 3" | sudo tee -a /etc/security/pwquality.conf
```

---

### 📂 FILE PERMISSIONS (25 minutes)

```bash
# Check critical files
ls -l /etc/passwd /etc/shadow /etc/group /etc/hosts

# Find world-writable (DANGER!)
find /etc /bin /sbin /usr -type f -perm -002 2>/dev/null

# Find SUID files
find / -type f -perm -4000 2>/dev/null | head -20

# Fix critical permissions
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chmod 644 /etc/group
sudo chmod 600 /boot/grub/grub.cfg

# Fix SSH keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/*.pub
```

---

### 🔒 SSH SECURITY (15 minutes)

```bash
# Backup config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Check current settings
grep -E "^(Protocol|PermitRootLogin|PasswordAuthentication)" /etc/ssh/sshd_config

# Secure SSH (check competition rules first!)
sudo sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart ssh
```

---

### 🔥 FIREWALL (10 minutes)

```bash
# Check status
sudo ufw status verbose

# Basic setup
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp

# Check what's listening
netstat -tlnp
ss -tlnp
```

---

### ⚙️ SERVICES AUDIT (20 minutes)

```bash
# List active services
systemctl list-units --type=service --state=active

# Check network services
netstat -tlnp | grep LISTEN

# Find suspicious services
systemctl list-units | grep -E "(bitcoin|tor|mining|p2p)"

# Disable service
sudo systemctl stop SERVICE_NAME
sudo systemctl disable SERVICE_NAME

# Common risky services to check:
# telnet, vsftpd, apache2, nginx, avahi-daemon, cups, bluetooth
```

---

### 🔄 SYSTEM UPDATES (10 minutes)

```bash
# Check for updates (VERIFY COMPETITION RULES FIRST!)
sudo apt update
apt list --upgradable

# Security updates only
sudo unattended-upgrade

# All updates (if allowed)
sudo apt upgrade -y
```

---

### 🛡️ KERNEL HARDENING (15 minutes)

```bash
# Check current settings
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects

# Apply hardening
sudo tee -a /etc/sysctl.d/99-security.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
kernel.dmesg_restrict = 1
EOF

# Apply immediately
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

---

### 🦠 MALWARE DETECTION (15 minutes)

```bash
# Check processes
ps aux | grep -E "(bitcoin|miner|tor|nc)"

# Check network connections
netstat -antup
ss -tupln | grep ESTAB

# Find recent files
find / -type f -mtime -1 2>/dev/null | head -20

# Check temp directories
find /tmp /var/tmp -type f -executable 2>/dev/null

# Check for hidden files
find /home -name ".*" -type f | grep -v ".bash\|.profile"
```

---

### 📋 DOCUMENTATION COMMANDS

```bash
# Create audit workspace
mkdir /tmp/audit_$(date +%Y%m%d_%H%M)
cd /tmp/audit_$(date +%Y%m%d_%H%M)
touch findings.txt fixes_applied.txt

# Document findings
echo "Found issue: [description]" >> findings.txt
echo "Fixed: [what was fixed]" >> fixes_applied.txt

# System info
echo "System: $(hostname)" > final_report.txt
echo "Date: $(date)" >> final_report.txt
echo "Auditor: [Your Name]" >> final_report.txt
```

---

### ⏱️ TIME MANAGEMENT

**Phase 1:** Users & Groups (20 min)  
**Phase 2:** Passwords (15 min)  
**Phase 3:** File Permissions (25 min)  
**Phase 4:** SSH (15 min)  
**Phase 5:** Firewall (10 min)  
**Phase 6:** Services (20 min)  
**Phase 7:** Updates (10 min)  
**Phase 8:** Kernel (15 min)  
**Phase 9:** Malware (15 min)  
**Phase 10:** Documentation (10 min)  

**TOTAL: 160 minutes (2h 40m)**

---

### 🎯 CRITICAL SUCCESS FACTORS

1. **Read competition requirements FIRST**
2. **Document every change made**  
3. **Test services after modifications**
4. **Keep backups of config files**
5. **Work systematically through phases**
6. **Don't skip documentation**

---

### 📞 TEAM COORDINATION

**Student A:** Users, Groups, Passwords  
**Student B:** File Permissions, SSH  
**Student C:** Services, Firewall  
**Student D:** Updates, Kernel, Malware, Docs  

**Communication:** Call out when phase is complete!

---

### 🔍 VERIFICATION CHECKLIST

```bash
# Final verification commands
getent group sudo              # Check sudo users
sudo ufw status               # Check firewall
systemctl list-units --failed # Check for failed services
grep PermitRootLogin /etc/ssh/sshd_config  # Check SSH
ls -l /etc/passwd /etc/shadow  # Check permissions
```

**Print this page and keep it handy during competition!**