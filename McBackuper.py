#!/usr/bin/env python3
"""
===============================================================
McBackuper Utility v1.0.0
by Art_Farm

⚠️ ATTENTION: Do not edit anything if you do not know what you are doing. ⚠️
===============================================================
"""

import argparse
import copy
import datetime
import fcntl
import fnmatch
import logging
import os
import re
import shutil
import signal
import socket
import struct
import sys
import tempfile
import time
import tomllib
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Event
from typing import Any

if os.name == 'nt':
    sys.exit("Critical Error: This utility is strictly designed for Unix-like systems.")

if sys.version_info < (3, 11):
    sys.exit("Critical Error: Python 3.11+ required.")

VERSION = "1.0.0"
UPDATE_URL = "https://api.mine-farm.ru/public/mcbackuper/version.txt"

GLOBAL_DEFAULTS: dict[str, Any] = {
    "backup_interval_minutes": 60,
    "max_parallel_backups": 1,
    "check_updates": True,
}

SERVER_DEFAULTS: dict[str, Any] = {
    "rotation_mode": "smart",
    "max_backups": 10,
    "smart_keep_hourly": 24,
    "smart_keep_daily": 7,
    "smart_keep_weekly": 4,
    "smart_keep_monthly": 6,
    "health_check_enabled": True,
    "compression_level": 6,
    "auto_delete_old_backups": True,
    "exclude_hidden": False,
    "exclude_patterns": ["*.lock", "logs/*", "cache/*", "*.tmp", "*.log"],
    "rcon_enabled": False,
    "rcon_host": "127.0.0.1",
    "rcon_port": 25575,
    "rcon_password": "",
    "rcon_pre_commands": ["save-off", "save-all flush"],
    "rcon_post_commands": ["save-on"],
}


def _sanitize_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', name)


def check_for_updates(logger: logging.Logger) -> None:
    try:
        req = urllib.request.Request(UPDATE_URL, headers={'User-Agent': f'McBackuper/{VERSION}'})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            raw_version = response.read(1024).decode('utf-8', errors='replace').strip()
            latest = re.sub(r'[^\w.-]', '', raw_version)[:20]

        def parse(v: str) -> tuple[int, ...]:
            return tuple(map(int, re.sub(r'[^0-9.]', '', v).split('.'))) if v else (0, 0, 0)

        if parse(latest) > parse(VERSION):
            logger.info(f"Update available: v{latest} (Current: v{VERSION}).")
            logger.info(f"Download: https://github.com/artfarm6688/mcbackuper")

    except Exception as e:
        logger.debug(f"Update check failed: {e}")


class RCONClient:
    PACKET_AUTH = 3
    PACKET_CMD = 2

    def __init__(self, host: str, port: int, password: str, timeout: float = 5.0):
        self.addr = (host, port)
        self.password = password
        self.timeout = timeout
        self.socket: socket.socket | None = None

    def __enter__(self) -> 'RCONClient':
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.disconnect()

    def connect(self) -> bool:
        for _ in range(3):
            try:
                self.socket = socket.create_connection(self.addr, timeout=self.timeout)
                if self._authenticate():
                    return True
            except OSError:
                pass
            self.disconnect()
            time.sleep(1.0)
        return False

    def disconnect(self) -> None:
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self.socket.close()
                self.socket = None

    def command(self, cmd: str) -> str | None:
        if not self.socket:
            return None
        
        req_id = int.from_bytes(os.urandom(4), 'little', signed=True)
        try:
            self.socket.sendall(self._build_packet(req_id, self.PACKET_CMD, cmd))
            resp = self._receive_packet()
            if resp and resp.get('id') == req_id:
                return resp.get('body')
        except OSError:
            self.disconnect()
        return None

    def _authenticate(self) -> bool:
        req_id = 1
        try:
            self.socket.sendall(self._build_packet(req_id, self.PACKET_AUTH, self.password))
            resp = self._receive_packet()
            return resp is not None and resp.get('id') == req_id
        except OSError:
            return False

    def _build_packet(self, req_id: int, ptype: int, body: str) -> bytes:
        body_bytes = body.encode('utf-8')
        length = 10 + len(body_bytes)
        return struct.pack('<i', length) + struct.pack('<ii', req_id, ptype) + body_bytes + b'\x00\x00'

    def _receive_exactly(self, n: int) -> bytes | None:
        if not self.socket:
            return None
        data = bytearray()
        while len(data) < n:
            try:
                chunk = self.socket.recv(n - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            except OSError:
                return None
        return bytes(data)

    def _receive_packet(self) -> dict[str, Any] | None:
        len_bytes = self._receive_exactly(4)
        if not len_bytes:
            return None
        
        length = struct.unpack('<i', len_bytes)[0]
        if not (10 <= length <= 4096):
            return None
        
        data = self._receive_exactly(length)
        if not data or len(data) < length:
            return None
            
        req_id, ptype = struct.unpack('<ii', data[:8])
        body = data[8:-2].decode('utf-8', errors='replace')
        
        return {
            'id': req_id,
            'type': ptype,
            'body': body
        }


class SingleInstanceLock:
    def __init__(self, lock_file: Path):
        self.lock_file = lock_file
        self.fp = None

    def __enter__(self) -> 'SingleInstanceLock':
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.fp = open(self.lock_file, 'w')
        try:
            fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except BlockingIOError:
            self.fp.close()
            raise RuntimeError("Lock failed. Another instance is already running.")

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.fp:
            try:
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                self.fp.close()
                self.lock_file.unlink(missing_ok=True)


class BackupJob:
    def __init__(self, name: str, server_path: Path, cfg: dict[str, Any], temp_base: Path, backups_dir: Path):
        self.safe_name = _sanitize_filename(name)
        self.server_path = server_path.resolve()
        self.cfg = cfg
        self.temp_base = temp_base
        self.backups_dir = backups_dir / self.safe_name
        self.logger = logging.getLogger(f"Job.{self.safe_name}")

    def _get_backup_files(self) -> list[tuple[int, Path]]:
        if not self.backups_dir.exists():
            return []
        
        pattern = re.compile(rf"^{re.escape(self.safe_name)}-(\d+)\.zip$")
        backups = []
        for f in self.backups_dir.iterdir():
            if f.is_file():
                match = pattern.match(f.name)
                if match:
                    backups.append((int(match.group(1)), f))
        return sorted(backups, key=lambda x: x[0])

    def _execute_rcon(self, commands: list[str]) -> None:
        if not commands or not self.cfg.get('rcon_enabled'):
            return

        try:
            with RCONClient(self.cfg['rcon_host'], self.cfg['rcon_port'], self.cfg['rcon_password']) as rcon:
                if not rcon.socket:
                    self.logger.warning("RCON connection failed. Skipped commands.")
                    return
                for cmd in commands:
                    rcon.command(cmd)
        except Exception as e:
            self.logger.error(f"RCON error: {e}")

    def _copy_server_to_temp(self, temp_dir: Path) -> bool:
        exclude_hidden = self.cfg.get('exclude_hidden', False)
        patterns = self.cfg.get('exclude_patterns', [])

        def ignore_func(src: str, names: list[str]) -> list[str]:
            ignored = []
            src_path = Path(src)
            for name in names:
                if exclude_hidden and name.startswith('.'):
                    ignored.append(name)
                    continue
                
                rel_path = str((src_path / name).relative_to(self.server_path))
                if any(fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p) for p in patterns):
                    ignored.append(name)
            return ignored

        try:
            shutil.copytree(self.server_path, temp_dir, ignore=ignore_func, symlinks=False, dirs_exist_ok=True)
            return True
        except shutil.Error as e:
            self.logger.warning(f"Ignored file changes during active copy: {e}")
            return True
        except Exception as e:
            self.logger.error(f"Staging copy failed: {e}")
            return False

    def _create_zip(self, source_dir: Path, target_zip: Path) -> bool:
        tmp_zip = target_zip.with_suffix('.zip.tmp')
        try:
            with zipfile.ZipFile(tmp_zip, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=self.cfg['compression_level']) as zf:
                for root, dirs, files in os.walk(source_dir):
                    root_path = Path(root)
                    if not dirs and not files and root_path != source_dir:
                        zf.write(root_path, root_path.relative_to(source_dir))
                    for file in files:
                        file_path = root_path / file
                        zf.write(file_path, file_path.relative_to(source_dir))
            
            tmp_zip.replace(target_zip)
            target_zip.chmod(0o600)
            return True
        except Exception as e:
            self.logger.error(f"ZIP creation failed: {e}")
            tmp_zip.unlink(missing_ok=True)
            return False

    def _rotate_backups(self) -> None:
        if not self.cfg.get('auto_delete_old_backups'):
            return
            
        backups = self._get_backup_files()
        if not backups:
            return

        if self.cfg.get('rotation_mode') == 'smart':
            now = datetime.datetime.now()
            limits = {
                'hourly': datetime.timedelta(hours=self.cfg['smart_keep_hourly']),
                'daily': datetime.timedelta(days=self.cfg['smart_keep_daily']),
                'weekly': datetime.timedelta(weeks=self.cfg['smart_keep_weekly']),
                'monthly': datetime.timedelta(days=self.cfg['smart_keep_monthly'] * 30)
            }
            buckets = {k: set() for k in limits}
            newest_backup = backups[-1][1]

            for _, path in sorted(backups, key=lambda x: x[1].stat().st_mtime, reverse=True):
                if path == newest_backup:
                    continue

                dt = datetime.datetime.fromtimestamp(path.stat().st_mtime)
                age = now - dt
                keep = False

                keys = {
                    'hourly': dt.strftime("%Y-%m-%d_%H"),
                    'daily': dt.strftime("%Y-%m-%d"),
                    'weekly': dt.strftime("%Y-%W"),
                    'monthly': dt.strftime("%Y-%m")
                }

                for period, limit in limits.items():
                    if age <= limit:
                        key = keys[period]
                        if key not in buckets[period]:
                            buckets[period].add(key)
                            keep = True
                        break

                if not keep:
                    path.unlink(missing_ok=True)
                    self.logger.info(f"Rotated: {path.name}")
        else:
            max_b = max(1, self.cfg['max_backups'])
            while len(backups) > max_b:
                _, path = backups.pop(0)
                path.unlink(missing_ok=True)
                self.logger.info(f"Rotated: {path.name}")

    def run(self) -> bool:
        self.logger.info(f"Processing backup for '{self.safe_name}'")
        backups = self._get_backup_files()
        next_id = backups[-1][0] + 1 if backups else 1

        self.backups_dir.mkdir(parents=True, exist_ok=True)
        temp_dir_obj = None

        try:
            self._execute_rcon(self.cfg.get('rcon_pre_commands', []))
            temp_dir_obj = tempfile.TemporaryDirectory(prefix=f"bak_{self.safe_name}_", dir=self.temp_base)
            temp_path = Path(temp_dir_obj.name)
            
            if not self._copy_server_to_temp(temp_path):
                return False

            zip_path = self.backups_dir / f"{self.safe_name}-{next_id:04d}.zip"
            if not self._create_zip(temp_path, zip_path):
                return False

            if self.cfg.get('health_check_enabled'):
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        if bad := zf.testzip():
                            self.logger.error(f"Archive corrupted at {bad}")
                            zip_path.unlink(missing_ok=True)
                            return False
                except Exception as e:
                    self.logger.error(f"Health check failed: {e}")
                    zip_path.unlink(missing_ok=True)
                    return False

            self.logger.info(f"Success: {zip_path.name}")
            self._rotate_backups()
            return True
            
        finally:
            self._execute_rcon(self.cfg.get('rcon_post_commands', []))
            if temp_dir_obj:
                try:
                    temp_dir_obj.cleanup()
                except OSError as e:
                    self.logger.warning(f"Temp cleanup warning: {e}")


class BackupManager:
    def __init__(self, base_dir: Path, config_path: Path):
        self.base_dir = base_dir
        self.config_path = config_path
        self.backups_dir = self.base_dir / "backups"
        self.temp_dir = self.base_dir / "tmp"
        self.logger = logging.getLogger("Manager")
        self.config: dict[str, Any] = {}
        self.stop_event = Event()

    def load_config(self) -> bool:
        if not self.config_path.exists():
            self._write_default_config()
            self.logger.info(f"Config generated at {self.config_path}. Configure it and restart.")
            return False

        try:
            with open(self.config_path, "rb") as f:
                self.config = tomllib.load(f)
        except Exception as e:
            self.logger.error(f"Config parse error: {e}")
            return False

        for k, v in GLOBAL_DEFAULTS.items():
            self.config.setdefault(k, v)

        valid_servers = []
        for idx, srv in enumerate(self.config.get("servers", [])):
            name, path = srv.get("name"), srv.get("path")
            if not isinstance(name, str) or not name.strip() or not isinstance(path, str):
                self.logger.error(f"Server index {idx} has invalid name/path.")
                continue

            if not Path(path).expanduser().resolve().is_dir():
                self.logger.error(f"Target '{path}' not found. Skipping '{name}'.")
                continue

            valid_servers.append(srv)

        self.config["servers"] = valid_servers
        return bool(valid_servers)

    def _write_default_config(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        default_toml = f"""# McBackuper Configuration File v{VERSION}
# This file defines global settings and individual backup jobs for Minecraft servers.

# ==========================================
# GLOBAL SETTINGS
# ==========================================

# Default backup interval if not specified in the server section (in minutes).
backup_interval_minutes = 60

# Maximum number of backup jobs running at the same time. 
# Recommended: 1 for HDD, 2-4 for high-speed NVMe SSDs to prevent I/O lag.
max_parallel_backups = 1

# Automatically check for new versions of McBackuper on startup.
check_updates = true

# ==========================================
# SERVER INSTANCES
# ==========================================
# You can add multiple [[servers]] blocks for different worlds or instances.

[[servers]]
# Unique name for the job. Used for folder and filename generation.
name = "survival"

# Absolute path to the Minecraft server directory.
path = "/home/minecraft/survival"

# Override global interval for this specific server (in minutes).
backup_interval_minutes = 120

# --- Backup Rotation (Cleanup) ---

# Toggle automatic deletion of old backups.
auto_delete_old_backups = true

# Rotation mode: "smart" (retains specific intervals) or "simple" (retains fixed count).
rotation_mode = "smart"

# Simple mode parameter: How many latest backups to keep.
max_backups = 10

# Smart mode parameters:
# Retain one backup for every hour for the last X hours.
smart_keep_hourly = 24
# Retain one backup for every day for the last X days.
smart_keep_daily = 7
# Retain one backup for every week for the last X weeks.
smart_keep_weekly = 4
# Retain one backup for every month for the last X months.
smart_keep_monthly = 6

# --- Archiving & Security ---

# ZIP compression level (1 = fastest/largest, 9 = slowest/smallest). 6 is recommended.
compression_level = 6

# Perform integrity check (testzip) after creating the archive.
health_check_enabled = true

# Skip all hidden files and folders (starting with a dot, e.g., .git, .bashrc).
exclude_hidden = false

# List of glob patterns to exclude from the backup.
# Supports wildcards like * and directory-specific exclusions.
exclude_patterns = ["*.lock", "logs/*", "cache/*", "*.tmp", "*.log"]

# --- RCON Integration ---

rcon_enabled = false
rcon_host = "127.0.0.1"
rcon_port = 25575
rcon_password = "Super_Mega_Giga_Pass"

# Commands sent to the server BEFORE file copying begins.
rcon_pre_commands = ["save-off", "save-all flush"]

# Commands sent to the server AFTER file copying is finished.
rcon_post_commands = ["save-on"]
"""
        self.config_path.write_text(default_toml, encoding="utf-8")
        self.config_path.chmod(0o600)

    def _run_servers(self, servers_to_run: list[dict[str, Any]]) -> bool:
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

        max_workers = self.config.get("max_parallel_backups", 1)
        futures = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for srv in servers_to_run:
                cfg = copy.deepcopy(SERVER_DEFAULTS)
                cfg.update(srv)
                job = BackupJob(
                    name=srv["name"],
                    server_path=Path(srv["path"]).expanduser(),
                    cfg=cfg,
                    temp_base=self.temp_dir,
                    backups_dir=self.backups_dir
                )
                futures.append(executor.submit(job.run))

        return all(f.result() for f in as_completed(futures))

    def run_once(self) -> bool:
        servers = self.config.get("servers", [])
        return self._run_servers(servers) if servers else False

    def run_forever(self) -> None:
        self.logger.info("Scheduler running in background.")
        servers = self.config.get("servers", [])
        last_run = {s["name"]: time.monotonic() - (s.get("backup_interval_minutes", self.config["backup_interval_minutes"]) * 60) for s in servers}

        while not self.stop_event.is_set():
            now = time.monotonic()
            to_run = []

            for srv in servers:
                name = srv["name"]
                interval = srv.get("backup_interval_minutes", self.config["backup_interval_minutes"]) * 60
                if now - last_run.get(name, 0) >= interval:
                    to_run.append(srv)
                    last_run[name] = now

            if to_run:
                self._run_servers(to_run)

            self.stop_event.wait(timeout=30.0)


def setup_logging(debug: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG if debug else logging.INFO,
        handlers=[logging.StreamHandler(sys.stdout)]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=f"McBackuper v{VERSION}")
    parser.add_argument("-c", "--config", type=Path, help="Custom path to config.toml")
    parser.add_argument("--once", action="store_true", help="Execute single backup pass and exit")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()
    
    setup_logging(args.debug)
    logger = logging.getLogger("System")

    if args.config:
        config_path = args.config.resolve()
        base_dir = config_path.parent
    else:
        base_dir = Path(__file__).resolve().parent / "backuper"
        config_path = base_dir / "config.toml"

    manager = BackupManager(base_dir=base_dir, config_path=config_path)

    def shutdown_handler(signum: int, frame: Any) -> None:
        logger.info("Graceful shutdown initiated. Awaiting task completion...")
        manager.stop_event.set()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        with SingleInstanceLock(base_dir / "backuper.lock"):
            if not manager.load_config():
                sys.exit(1)

            if manager.config.get("check_updates"):
                check_for_updates(logger)

            if args.once:
                sys.exit(0 if manager.run_once() else 1)
            else:
                manager.run_forever()
    except RuntimeError as e:
        logger.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Process interrupted manually.")
        manager.stop_event.set()


if __name__ == "__main__":
    main()