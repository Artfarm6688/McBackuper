# Security Policy 🛡️

At **McBackuper**, the security of your Minecraft server and its data is our top priority. This document outlines our supported versions, reporting processes, and security best practices for using this utility.

> [!IMPORTANT]
> Using RCON is not recommended, as the protocol itself lacks reliable security. 
> Use it at your own risk, with proper firewall protection.

---

## Supported Versions

We actively provide security updates.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a potential security flaw in McBackuper (e.g., credential leaks or path traversal), please follow these steps:

1. **Private Disclosure:** Send a detailed report to the author (**Art_Farm**) via [GitHub Private Vulnerability Reporting](https://github.com/Artfarm6688/McBackuper/security/advisories/new) or contact the author directly.
2. **Details to Include:**
   - A description of the vulnerability.
   - Steps to reproduce the issue.
   - Potential impact on the user's system.
3. **Response Time:** We aim to acknowledge all security reports within **48 hours** and provide a fix or mitigation strategy as soon as possible.

## Security Best Practices for Users

To keep your server safe while using McBackuper, we strongly recommend:

### 1. Protect your `config.toml`
- Ensure the file is owned by the user running the script.
- Set strict permissions: `chmod 600 config.toml` (this prevents other users on the Linux system from reading your config.toml).

### 2. Use a Dedicated User
Never run `backuper.py` as **root**. Create a dedicated `minecraft` user with access only to the necessary directories.

### 3. Firewall Rules
If your RCON is enabled, ensure your firewall (ufw/iptables) only allows connections from `127.0.0.1`

### 4. Keep Python Updated
Since McBackuper relies on Python 3.11+, ensure your Python environment is patched against known CVEs.

---
*Thank you for helping us keep McBackuper secure for everyone!*