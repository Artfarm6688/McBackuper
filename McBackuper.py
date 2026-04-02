#!/usr/bin/env python3
"""
===============================================================
McBackuper Utility v1.1.0
Developed by Art_Farm (https://github.com/Artfarm6688)

⚠️ CRITICAL WARNING:
Do not modify the source code unless you fully understand its logic.
Strictly designed for Unix-like systems.
===============================================================
"""

import argparse
import concurrent.futures
import copy
import datetime
import fcntl
import fnmatch
import itertools
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from typing import Any

if os.name == 'nt':
    sys.exit("Critical Error: This utility is strictly designed for Unix-like systems.")

if sys.version_info < (3, 11):
    sys.exit("Critical Error: Python 3.11+ required.")

VERSION = "1.1.0"
UPDATE_URL = "https://api.mine-farm.ru/public/mcbackuper/version.txt"

GLOBAL_DEFAULTS: dict[str, Any] = {
    "backup_interval_minutes": 60,
    "max_parallel_backups": 1,
    "check_updates": True,
    "global_backup_dir": "./backups",
    "global_temp_dir": "./tmp",
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
            logger.info("Download: https://github.com/artfarm6688/mcbackuper")
    except Exception as e:
        logger.debug(f"Update check failed: {e}")


class RCONClient:
    PACKET_AUTH = 3
    PACKET_CMD = 2

    def __init__(self, host: str, port: int, password: str, logger: logging.Logger, timeout: float = 5.0):
        self.addr = (host, port)
        self.password = password
        self.timeout = timeout
        self.logger = logger
        self.socket: socket.socket | None = None
        self._req_id_gen = itertools.count(1)

    def __enter__(self) -> 'RCONClient':
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.disconnect()

    def connect(self) -> bool:
        for attempt in range(1, 4):
            try:
                self.socket = socket.create_connection(self.addr, timeout=self.timeout)
                if self._authenticate():
                    return True
            except OSError as e:
                self.logger.debug(f"RCON connection attempt {attempt} failed: {e}")
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
        if not self.socket and not self.connect():
            self.logger.error("Cannot send RCON command: Not connected.")
            return None
        
        req_id = next(self._req_id_gen)
        try:
            packet = self._build_packet(req_id, self.PACKET_CMD, cmd)
            self.socket.sendall(packet)
            resp = self._receive_packet()
            
            if resp is None:
                self.disconnect()
                return None
                
            if resp.get('id') == req_id:
                return resp.get('body')
            self.logger.warning("RCON response ID mismatch.")
        except OSError as e:
            self.logger.error(f"RCON command '{cmd}' failed: {e}")
            self.disconnect()
        return None

    def _authenticate(self) -> bool:
        req_id = next(self._req_id_gen)
        try:
            self.socket.sendall(self._build_packet(req_id, self.PACKET_AUTH, self.password))
            resp = self._receive_packet()
            if resp is None or resp.get('id') != req_id:
                self.logger.debug("RCON authentication rejected by server.")
                return False
            return True
        except OSError as e:
            self.logger.debug(f"RCON authentication socket error: {e}")
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
            self.logger.warning(f"RCON packet length anomalous: {length}")
            return None
        
        data = self._receive_exactly(length)
        if not data or len(data) < length:
            self.logger.warning("RCON packet truncated.")
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
        self.fp: Any | None = None

    def __enter__(self) -> 'SingleInstanceLock':
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.fp = open(self.lock_file, 'w')
        try:
            # fcntl lock is released automatically by the OS when the process exits or is killed (e.g. kill -9).
            # The lingering file on disk is safe to overwrite next time.
            fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fp.write(str(os.getpid()))
            self.fp.flush()
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
                try:
                    self.lock_file.unlink(missing_ok=True)
                except OSError:
                    pass


class BackupJob:
    def __init__(self, name: str, server_path: Path, cfg: dict[str, Any], temp_base: Path, backups_dir: Path, stop_event: Event):
        self.safe_name = _sanitize_filename(name)
        self.server_path = server_path.resolve()
        self.cfg = cfg
        self.temp_base = temp_base
        self.backups_dir = backups_dir / self.safe_name
        self.stop_event = stop_event
        self.logger = logging.getLogger(f"Job.{self.safe_name}")

    def _get_backup_files(self) -> list[tuple[datetime.datetime, Path]]:
        if not self.backups_dir.exists():
            return []
        
        # Note: sorting relies on local time encoded in filenames
        pattern = re.compile(rf"^{re.escape(self.safe_name)}-(\d{{8}}_\d{{6}})\.zip$")
        backups = []
        for f in self.backups_dir.iterdir():
            if f.is_file():
                match = pattern.match(f.name)
                if match:
                    try:
                        dt = datetime.datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
                        backups.append((dt, f))
                    except ValueError:
                        continue
        return sorted(backups, key=lambda x: x[0])

    def _execute_rcon(self, commands: list[str]) -> None:
        if not commands or not self.cfg.get('rcon_enabled'):
            return

        try:
            with RCONClient(self.cfg['rcon_host'], self.cfg['rcon_port'], self.cfg['rcon_password'], self.logger) as rcon:
                if not rcon.socket:
                    self.logger.warning("RCON connection failed. Skipped commands.")
                    return
                for cmd in commands:
                    if self.stop_event.is_set():
                        break
                    rcon.command(cmd)
        except Exception as e:
            self.logger.error(f"RCON error: {e}")

    def _is_ignored(self, name: str, rel_path: Path, exclude_hidden: bool, patterns: list[str]) -> bool:
        if exclude_hidden and name.startswith('.'):
            return True
        rel_str = str(rel_path)
        return any(fnmatch.fnmatch(rel_str, p) or fnmatch.fnmatch(name, p) for p in patterns)

    def _copy_server_to_temp(self, temp_dir: Path) -> bool:
        exclude_hidden = bool(self.cfg.get('exclude_hidden', False))
        patterns = self.cfg.get('exclude_patterns', [])

        def walk_err_handler(err: OSError) -> None:
            self.logger.warning(f"Skipping inaccessible directory {err.filename}: {err.strerror}")

        try:
            for root, dirs, files in os.walk(self.server_path, onerror=walk_err_handler):
                if self.stop_event.is_set():
                    self.logger.warning("Copy interrupted by shutdown event.")
                    return False

                root_path = Path(root)
                rel_root = root_path.relative_to(self.server_path)

                dirs[:] = [d for d in dirs if not self._is_ignored(d, rel_root / d, exclude_hidden, patterns)]

                target_dir = temp_dir / rel_root
                target_dir.mkdir(parents=True, exist_ok=True)

                for file in files:
                    if self.stop_event.is_set():
                        return False
                    
                    if self._is_ignored(file, rel_root / file, exclude_hidden, patterns):
                        continue

                    src_file = root_path / file
                    dst_file = target_dir / file
                    
                    try:
                        if src_file.is_symlink():
                            os.symlink(os.readlink(src_file), dst_file)
                        else:
                            shutil.copy2(src_file, dst_file)
                    except FileNotFoundError:
                        self.logger.warning(f"File disappeared during copy, skipping: {src_file}")
                    except OSError as e:
                        self.logger.error(f"Failed to copy file {src_file}: {e}")
                        return False
            return True
        except Exception as e:
            self.logger.error(f"Staging copy critically failed: {e}")
            return False

    def _create_zip(self, source_dir: Path, target_zip: Path) -> bool:
        tmp_zip = target_zip.with_suffix('.zip.tmp')
        added_dirs: set[Path] = set()
        
        try:
            with zipfile.ZipFile(tmp_zip, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=int(self.cfg.get('compression_level', 6))) as zf:
                for root, dirs, files in os.walk(source_dir):
                    if self.stop_event.is_set():
                        self.logger.warning("ZIP creation interrupted by shutdown event.")
                        return False

                    root_path = Path(root)
                    
                    for d in dirs:
                        dir_path = root_path / d
                        rel_dir = dir_path.relative_to(source_dir)
                        if rel_dir not in added_dirs:
                            zf.write(dir_path, rel_dir)
                            added_dirs.add(rel_dir)

                    for file in files:
                        if self.stop_event.is_set():
                            return False
                        file_path = root_path / file
                        zf.write(file_path, file_path.relative_to(source_dir))
            
            tmp_zip.replace(target_zip)
            target_zip.chmod(0o600)
            return True
        except Exception as e:
            self.logger.error(f"ZIP creation failed: {e}")
            return False
        finally:
            tmp_zip.unlink(missing_ok=True)

    def _rotate_backups(self) -> None:
        if not self.cfg.get('auto_delete_old_backups'):
            return
            
        backups = self._get_backup_files()
        if not backups:
            return

        if self.cfg.get('rotation_mode') == 'smart':
            now = datetime.datetime.now()
            
            def get_int(key: str, default: int) -> int:
                val = self.cfg.get(key, default)
                return int(val) if str(val).isdigit() else default

            limits = {
                'hourly': datetime.timedelta(hours=get_int('smart_keep_hourly', 24)),
                'daily': datetime.timedelta(days=get_int('smart_keep_daily', 7)),
                'weekly': datetime.timedelta(weeks=get_int('smart_keep_weekly', 4)),
                'monthly': datetime.timedelta(days=get_int('smart_keep_monthly', 6) * 30)
            }
            buckets = {k: set() for k in limits}
            newest_backup = backups[-1][1]

            for dt, path in sorted(backups, key=lambda x: x[0], reverse=True):
                if path == newest_backup:
                    continue

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
                    try:
                        path.unlink(missing_ok=True)
                        self.logger.info(f"Rotated: {path.name}")
                    except OSError as e:
                        self.logger.warning(f"Failed to delete old backup {path.name}: {e}")
        else:
            max_b = max(1, int(self.cfg.get('max_backups', 10)))
            if len(backups) > max_b:
                for _, path in backups[:-max_b]:
                    try:
                        path.unlink(missing_ok=True)
                        self.logger.info(f"Rotated: {path.name}")
                    except OSError as e:
                        self.logger.warning(f"Failed to delete old backup {path.name}: {e}")

    def run(self) -> bool:
        try:
            self.logger.info(f"Processing backup for '{self.safe_name}'")
            
            try:
                self.backups_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                self.logger.error(f"Cannot create backup directory {self.backups_dir}: {e}")
                return False

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            self._execute_rcon(self.cfg.get('rcon_pre_commands', []))
            
            try:
                with tempfile.TemporaryDirectory(prefix=f"bak_{self.safe_name}_", dir=self.temp_base) as temp_dir_name:
                    temp_path = Path(temp_dir_name)
                    
                    if not self._copy_server_to_temp(temp_path):
                        return False

                    zip_path = self.backups_dir / f"{self.safe_name}-{timestamp}.zip"
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

                    self._rotate_backups()
                    self.logger.info(f"Success: {zip_path.name}")
                    return True
            finally:
                self._execute_rcon(self.cfg.get('rcon_post_commands', []))
        except Exception as e:
            self.logger.critical(f"Unhandled exception in backup job '{self.safe_name}': {e}")
            return False


class BackupManager:
    def __init__(self, base_dir: Path, config_path: Path):
        self.base_dir = base_dir
        self.config_path = config_path
        self.logger = logging.getLogger("Manager")
        self.config: dict[str, Any] = {}
        self.stop_event = Event()
        self.backups_dir: Path = self.base_dir / "backups"
        self.temp_dir: Path = self.base_dir / "tmp"

    def _resolve_path(self, path_str: str) -> Path:
        p = Path(path_str).expanduser()
        if p.is_absolute():
            return p.resolve()
        return (self.base_dir / p).resolve()

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

        self.backups_dir = self._resolve_path(self.config["global_backup_dir"])
        self.temp_dir = self._resolve_path(self.config["global_temp_dir"])

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

# ==========================================
# GLOBAL SETTINGS
# ==========================================
backup_interval_minutes = 60
max_parallel_backups = 1
check_updates = true

# Resolved relative to this config file's directory
global_backup_dir = "./backups"
global_temp_dir = "./tmp"

# ==========================================
# SERVER INSTANCES
# ==========================================
[[servers]]
name = "survival"
path = "/home/minecraft/survival"
backup_interval_minutes = 120

auto_delete_old_backups = true
rotation_mode = "smart"
max_backups = 10
smart_keep_hourly = 24
smart_keep_daily = 7
smart_keep_weekly = 4
smart_keep_monthly = 6

compression_level = 6
health_check_enabled = true
exclude_hidden = false
exclude_patterns = ["*.lock", "logs/*", "cache/*", "*.tmp", "*.log"]

rcon_enabled = false
rcon_host = "127.0.0.1"
rcon_port = 25575
# Ensure this file has 600 permissions to protect the password below!
rcon_password = "Super_Mega_Giga_Pass"
rcon_pre_commands = ["save-off", "save-all flush"]
rcon_post_commands = ["save-on"]
"""
        self.config_path.write_text(default_toml, encoding="utf-8")
        self.config_path.chmod(0o600)

    def _run_servers(self, servers_to_run: list[dict[str, Any]]) -> bool:
        try:
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            self.backups_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.logger.error(f"Critical IO Error ensuring base directories: {e}")
            return False

        max_workers = int(self.config.get("max_parallel_backups", 1))
        executor = ThreadPoolExecutor(max_workers=max_workers)
        
        futures = []
        for srv in servers_to_run:
            cfg = copy.deepcopy(SERVER_DEFAULTS)
            cfg.update(srv)
            job = BackupJob(
                name=srv["name"],
                server_path=Path(srv["path"]).expanduser(),
                cfg=cfg,
                temp_base=self.temp_dir,
                backups_dir=self.backups_dir,
                stop_event=self.stop_event
            )
            futures.append(executor.submit(job.run))

        results = []
        pending = set(futures)
        
        # Manually wait for futures to support immediate stop_event cancellation
        while pending and not self.stop_event.is_set():
            done, pending = concurrent.futures.wait(
                pending, 
                timeout=1.0, 
                return_when=concurrent.futures.FIRST_COMPLETED
            )
            for f in done:
                try:
                    results.append(f.result())
                except Exception as e:
                    self.logger.error(f"Executor caught unhandled task exception: {e}")
                    results.append(False)

        if self.stop_event.is_set() and pending:
            self.logger.warning("Shutdown event active. Detaching pending tasks...")
            # Python 3.9+ cancel_futures safely drops pending work
            executor.shutdown(wait=False, cancel_futures=True)
            return False

        executor.shutdown(wait=True)
        return all(results)

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

            self.stop_event.wait(timeout=10.0)


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
        base_dir = Path.cwd()
        config_path = base_dir / "config.toml"

    manager = BackupManager(base_dir=base_dir, config_path=config_path)

    def shutdown_handler(_signum: int, _frame: Any | None) -> None:
        logger.info("Graceful shutdown initiated. Interrupting active tasks...")
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