# Linux Security Audit Comprehensive Script

This script addresses all security requirements from the three answer keys (answer_key1.txt, answer_key2.txt, and answer_key3.txt) and implements the manual audit procedures from the documentation files.

## What This Script Does

### 📋 Pre-Audit Requirements (NEW)
- **Reads README.txt files** from multiple locations to identify authorized users and critical services
- **Documents forensics answers BEFORE deletion** - answers all forensics questions first
- **Verifies system files** (/etc/passwd, /etc/group, /etc/shadow, /boot permissions)
- **Checks password policies and PAM** configuration before making changes
- **Verifies UFW, SSH, Nginx, and update status** before modifications
- **Documents ALL actions** in `/home/Public/Documents/Checklist.txt`

### 🔍 Forensics Tasks
- Finds Linux codename using `lsb_release` and documents answer
- Locates unauthorized MP3 and OGG files and documents paths BEFORE removal
- Searches for Python backdoors and malicious files
- Checks for Base64 encoded forensics files and decodes them
- Documents all forensics answers in the checklist before any file deletion

### 👥 User Account Management
- Removes unauthorized users: leon, oirving, romero, harry, penguru, ancano, tolfdir
- Demotes users from admin privileges: tcolby, mralbern, hamlet, ham, lydia
- Creates required groups (spider) and adds users
- Locks root password for security

### 🔐 Password Security
- Configures password aging policies (90-day max, 1-day min, 7-day warning)
- Implements password complexity requirements (10+ chars, mixed case, numbers)
- Sets up PAM for password quality enforcement
- Configures account lockout after failed attempts
- Removes null password authentication

### 🔥 Firewall Configuration
- Enables UFW (Uncomplicated Firewall)
- Sets default deny incoming, allow outgoing
- Opens necessary ports (SSH, HTTP/HTTPS if Apache running)
- Configures service-specific firewall rules

### ⚙️ Service Management
- Installs and enables Apache2 (required service)
- Disables risky services: nginx, squid, telnet, avahi-daemon, cups, bluetooth
- Maintains required services like VSFTP if specified in requirements
- Documents all service changes

### 🔄 System Updates
- Configures automatic security updates
- Updates all system packages
- Installs unattended-upgrades for ongoing security

### 🗑️ Malware and Prohibited Content Removal
- Removes prohibited software: ophcrack, wireshark, doona, xprobe, aisleriot, bittorrent
- Deletes unauthorized media files (MP3, OGG)
- Removes specific malicious files and backdoors
- Cleans up prohibited downloads and tools

### 🔒 SSH Security Hardening
- Disables root SSH login
- Prevents empty password authentication
- Sets connection limits and timeouts
- Configures secure SSH protocols and ciphers

### 📂 File Permissions Security
- Secures critical system files (/etc/passwd, /etc/shadow, etc.)
- Fixes SSH key permissions
- Sets proper permissions on boot files
- Identifies and reports world-writable files

### 🛡️ Kernel and Network Hardening
- Disables IP forwarding
- Prevents ICMP redirects and source routing
- Enables SYN flood protection
- Configures memory protection (ASLR, KASLR)
- Hardens kernel parameters for security

### 📋 Documentation and Verification
- Creates comprehensive audit logs
- Documents all changes made
- Performs final verification of security settings
- Generates detailed final report

## Usage

### Prerequisites
- Ubuntu/Linux Mint system
- Root/sudo access
- Internet connection for package updates

### Running the Script

1. **Make the script executable:**
   ```bash
   chmod +x linux_audit_comprehensive_script.sh
   ```

2. **Run the script with sudo:**
   ```bash
   sudo ./linux_audit_comprehensive_script.sh
   ```

3. **Monitor the output:**
   - Green messages: Successful operations
   - Yellow messages: Warnings about changes
   - Red messages: Errors (script will continue)
   - Blue messages: Informational updates

### What to Expect

The script will:
- Take 10-30 minutes to complete (depending on system size and updates)
- Create an audit workspace in `/tmp/audit_YYYYMMDD_HHMM/`
- Generate a final report in your home directory
- Show a completion summary with all actions taken
- Require no user interaction (fully automated)

### Output Files

After completion, you'll find:
- **`/home/Public/Documents/Checklist.txt`** - **MAIN DOCUMENTATION** with all actions, forensics answers, and verification results
- `~/Audit_Checklist.txt` - Copy of the main checklist in user's home directory
- `~/final_audit_report.txt` - Complete audit report
- `/tmp/audit_*/findings.txt` - Detailed findings log including README analysis
- `/tmp/audit_*/fixes_applied.txt` - List of all changes made
- `/tmp/audit_*/users_found.txt` - User account inventory
- `/tmp/audit_*/services_found.txt` - Service inventory

## Important Notes

### ⚠️ Before Running
1. **Place README.txt file** in root directory, /home, or user desktop with authorized users and critical services
2. **Ensure forensics files exist** if you need to answer forensics questions
3. **Backup critical data** - The script makes significant system changes
4. **Test in a safe environment** first if possible
5. **Verify required services** - Some services may be required for your specific scenario

### ✅ After Running
1. **Review the main checklist** at `/home/Public/Documents/Checklist.txt` for all documented actions
2. **Check forensics answers** in the checklist - all answers are documented before any file deletion
3. **Verify system file permissions** were properly checked and documented
4. **Review password policy verification** results in the checklist
5. **Check UFW, SSH, Nginx status** verification results
6. **Test critical services** to ensure they still function
7. **Change weak passwords manually** for flagged user accounts
8. **Verify firewall rules** don't block required services

### 🔧 Manual Actions Still Needed
- Change passwords for users with weak passwords (pmccleery, alice, noir, balgruuf)
- Verify forensics questions on desktop and provide answers
- Test that all required services are working properly
- Review and adjust firewall rules if needed for specific requirements

## Troubleshooting

### Common Issues
- **Permission denied**: Ensure you're running with `sudo`
- **Package conflicts**: The script handles most conflicts automatically
- **Service failures**: Check the final report for any failed service operations
- **Network issues**: Ensure internet connectivity for package updates

### Recovery
If something goes wrong:
- Configuration backups are created (e.g., `/etc/ssh/sshd_config.backup`)
- Check the audit workspace for detailed logs
- Review `/var/log/auth.log` for authentication issues
- Use `systemctl status <service>` to check service problems

## Competition Compliance

This script addresses requirements from multiple competition scenarios:
- **CyberPatriot-style** Linux security competitions
- **CCDC** (Collegiate Cyber Defense Competition) requirements
- **General security hardening** best practices
- **Forensics challenges** commonly found in competitions

The script is designed to be comprehensive while avoiding actions that typically result in point deductions, such as:
- Removing required services (OpenSSH, Apache, etc.)
- Disabling critical system functions
- Breaking required functionality

## Support

If you encounter issues:
1. Check the final audit report for error details
2. Review the script output for specific error messages
3. Ensure your system meets the prerequisites
4. Verify you have proper sudo/root access

Remember: This script automates the manual procedures documented in the audit cheat sheets, providing a comprehensive security audit solution for Linux competition environments.