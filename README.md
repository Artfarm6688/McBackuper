# McBackuper 🛡️

![McBackuper Banner](https://github.com/Artfarm6688/McBackuper/blob/main/McBackuper-Banner.png)

**McBackuper** is a lightweight Python 3.11 utility designed for high-performance, reliable Minecraft server backups. Unlike generic scripts, it is built specifically for **Unix/Linux** environments to ensure maximum stability and data integrity.

> [!IMPORTANT]
> This tool is strictly for Linux/Unix systems.

---

## Why McBackuper?

* **Zero Downtime:** Backup your world while the server is running.
* **Smart Rotation:** Don't just delete old files—keep a logical history (Hourly, Daily, Weekly, Monthly).
* **RCON Integration:** A self-written RCON client that allows you to execute commands before and after backup directly on the server. (WARNING: Using RCON may be dangerous).
* **Fast & Atomic:** Uses a staging `tmp/` directory to ensure your backup isn't corrupted if the process is interrupted.
* **No Bloat:** Written in Python 3.11 with minimal dependencies.
* **External Utillity:** This is an external utility: no unnecessary plug-ins on the server.

## Key Features

- **Single Instance Lock:** Prevents multiple backup processes from running at once and eating your I/O.
- **Advanced Exclusions:** Easily skip `logs/`, `dynmap/`, or `.tmp` files using glob patterns.
- **Health Checks:** Automatically verifies ZIP integrity after creation.
- **Permission Management:** Sets strict `0o600` permissions on sensitive files.

## Quick Start

### 1. Requirements
* Python 3.11 or higher
* Linux/Unix OS (Ubuntu, Debian, CentOS, etc.)

### 2. Installation
```bash
git clone https://github.com/Artfarm6688/McBackuper.git
cd McBackuper
chmod +x backuper.py
