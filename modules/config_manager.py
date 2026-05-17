"""
config_manager.py - Configuration loading, merging, and access
"""

import json
import logging
import os
import socket
import subprocess
from pathlib import Path
from typing import Any, Optional

import yaml
from rich.console import Console

console = Console()
log = logging.getLogger("autopwn.config")

# ─── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    # Wordlists
    "wordlist_dir": "/usr/share/wordlists",
    "dir_wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "pass_wordlist": "/usr/share/wordlists/rockyou.txt",
    "user_wordlist": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    # Nmap
    "nmap_timing": "T4",
    "nmap_scripts": "vulners,smb-os-discovery,http-enum,ftp-anon,ssh-auth-methods",
    # Timeouts (seconds)
    "timeout": 300,
    "nmap_timeout": 600,
    "gobuster_timeout": 180,
    "nikto_timeout": 300,
    # Threading
    "threads": 10,
    "gobuster_threads": 30,
    # Shell
    "lhost": None,
    "lport": 4444,
    "shell_types": ["bash", "python", "php", "powershell", "msfvenom"],
    # Flags
    "flag_filenames": ["user.txt", "root.txt", "proof.txt", "flag.txt", "local.txt"],
    # Output
    "save_screenshots": True,
    "verbose": False,
    "dry_run": False,
    # Metasploit
    "no_metasploit": False,
    "msf_workspace": "autopwn",
    # Rate limiting
    "rate_limit_delay": 0.1,
}

# Common OSCP machine exploit mappings (service → module hints)
EXPLOIT_HINTS = {
    "ms17-010": {
        "msf": "exploit/windows/smb/ms17_010_eternalblue",
        "standalone": "exploits/ms17_010.py",
        "ports": [445],
        "name": "EternalBlue",
    },
    "ms08-067": {
        "msf": "exploit/windows/smb/ms08_067_netapi",
        "ports": [445],
        "name": "MS08-067 NetAPI",
    },
    "ms14-068": {
        "msf": "exploit/windows/local/ms14_068_kerberos_checksum",
        "ports": [88],
        "name": "Kerberos Checksum",
    },
    "shellshock": {
        "msf": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "ports": [80, 443],
        "name": "Shellshock",
    },
    "heartbleed": {
        "msf": "auxiliary/scanner/ssl/openssl_heartbleed",
        "ports": [443],
        "name": "Heartbleed",
    },
    "drupal": {
        "msf": "exploit/unix/webapp/drupal_drupalgeddon2",
        "ports": [80, 443],
        "name": "Drupalgeddon2",
    },
    "struts": {
        "msf": "exploit/multi/http/struts2_content_type_ognl",
        "ports": [80, 8080, 443],
        "name": "Apache Struts RCE",
    },
    "phpmyadmin": {
        "msf": "exploit/unix/webapp/phpmyadmin_lfi_rce",
        "ports": [80, 443],
        "name": "phpMyAdmin LFI/RCE",
    },
}

# Common privilege escalation techniques
PRIVESC_TECHNIQUES = {
    "linux": [
        "sudo_misconfig",
        "suid_binaries",
        "writable_passwd",
        "cron_jobs",
        "kernel_exploit",
        "path_hijack",
        "docker_escape",
        "lxd_escape",
        "nfs_root_squash",
        "ssh_keys",
        "password_reuse",
        "capabilities",
        "writable_service",
    ],
    "windows": [
        "seimpersonate",
        "unquoted_service_path",
        "always_install_elevated",
        "weak_service_perms",
        "registry_autoruns",
        "dll_hijacking",
        "token_impersonation",
        "juicypotato",
        "printspoofer",
        "roguewinrm",
        "kernel_exploit",
        "stored_creds",
        "pass_the_hash",
    ],
}


class ConfigManager:
    """Manages framework configuration with file + runtime overrides."""

    def __init__(self, config_file: Optional[Path] = None):
        self._config = dict(DEFAULT_CONFIG)

        if config_file and Path(config_file).exists():
            self._load_file(config_file)

        # Auto-detect wordlists
        self._resolve_wordlists()

    def _load_file(self, path: Path):
        """Load YAML or JSON config file."""
        try:
            with open(path) as f:
                if str(path).endswith(".json"):
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
            if isinstance(data, dict):
                self._config.update(data)
                log.info(f"Loaded config from {path}")
        except Exception as e:
            log.warning(f"Could not load config {path}: {e}")

    def _resolve_wordlists(self):
        """Find wordlists in common locations."""
        # Directory wordlist
        dir_candidates = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for c in dir_candidates:
            if Path(c).exists():
                self._config["dir_wordlist"] = c
                break

        # Password wordlist
        pass_candidates = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/seclists/Passwords/rockyou.txt",
        ]
        for c in pass_candidates:
            if Path(c).exists():
                self._config["pass_wordlist"] = c
                break

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        self._config[key] = value

    def get_lhost(self, vpn_iface: Optional[str] = None) -> str:
        """Auto-detect local IP, preferring VPN interface."""
        if vpn_iface:
            try:
                import netifaces
                addrs = netifaces.ifaddresses(vpn_iface)
                return addrs[netifaces.AF_INET][0]["addr"]
            except Exception:
                pass

        # Try common VPN interfaces
        for iface in ["tun0", "tun1", "tap0", "eth0"]:
            try:
                import netifaces
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]["addr"]
            except Exception:
                pass

        # Fallback: hostname resolution
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

    @property
    def exploit_hints(self):
        return EXPLOIT_HINTS

    @property
    def privesc_techniques(self):
        return PRIVESC_TECHNIQUES

    def is_dry_run(self) -> bool:
        return self._config.get("dry_run", False)

    def dump(self) -> dict:
        return dict(self._config)
