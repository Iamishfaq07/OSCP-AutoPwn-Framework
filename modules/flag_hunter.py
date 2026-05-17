"""
flag_hunter.py - Phase 5: Flag Hunting & Credential Collection

- Searches for OSCP-style flags: user.txt, root.txt, proof.txt, local.txt, flag.txt
- Generates commands to run on victim (can't run remotely without shell)
- Hash identification and cracking suggestions
- Formats flags for display and saving
"""

import asyncio
import hashlib
import logging
import re
from pathlib import Path
from typing import List, Optional, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.utils import run_command, save_output, has_tool

console = Console()

# Regex patterns for common hash types
HASH_PATTERNS = {
    "MD5": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
    "SHA1": re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE),
    "SHA256": re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
    "SHA512": re.compile(r"^[a-f0-9]{128}$", re.IGNORECASE),
    "NTLM": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
    "bcrypt": re.compile(r"^\$2[aby]\$\d{2}\$.{53}$"),
    "sha512crypt": re.compile(r"^\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}$"),
    "sha256crypt": re.compile(r"^\$5\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{43}$"),
    "MD5crypt": re.compile(r"^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$"),
    "MSSQL_2000": re.compile(r"^0x0100[a-f0-9]{88}$", re.IGNORECASE),
    "MySQL": re.compile(r"^\*[A-F0-9]{40}$"),
    "LM": re.compile(r"^[a-f0-9]{32}:[a-f0-9]{32}$", re.IGNORECASE),
    "NTHash": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
}

OSCP_FLAG_NAMES = [
    "user.txt", "root.txt", "proof.txt", "local.txt",
    "flag.txt", "flag1.txt", "flag2.txt", "FLAG.TXT",
]

LINUX_FLAG_PATHS = [
    "/root/root.txt",
    "/root/proof.txt",
    "/home/*/user.txt",
    "/home/*/local.txt",
    "/home/*/flag.txt",
    "/tmp/flag.txt",
    "/var/flag.txt",
]

WINDOWS_FLAG_PATHS = [
    "C:\\Users\\Administrator\\Desktop\\root.txt",
    "C:\\Users\\Administrator\\Desktop\\proof.txt",
    "C:\\Users\\*\\Desktop\\user.txt",
    "C:\\Users\\*\\Desktop\\local.txt",
    "C:\\Users\\*\\Desktop\\flag.txt",
    "C:\\Documents and Settings\\Administrator\\Desktop\\root.txt",
]


class FlagHunter:
    def __init__(self, target: str, target_dir: Path, cfg, log, all_results: dict):
        self.target = target
        self.target_dir = target_dir
        self.cfg = cfg
        self.log = log
        self.all_results = all_results
        self.dry_run = cfg.is_dry_run()
        self.os_type = all_results.get("recon", {}).get("os", "Unknown")

        self.results = {
            "flags_found": [],
            "flag_commands": {},
            "hashes_found": [],
            "cracking_commands": [],
        }

        (target_dir / "flags").mkdir(parents=True, exist_ok=True)

    async def run(self) -> dict:
        """Generate flag hunting commands and search for flags."""
        console.print(f"[green][*] Starting flag hunt on {self.target}[/green]")

        await asyncio.gather(
            self._generate_flag_commands(),
            self._check_recon_for_flags(),
            self._generate_hash_cracking_guide(),
        )

        self._print_flag_summary()
        return self.results

    async def _generate_flag_commands(self):
        """Generate OS-appropriate flag hunting commands."""
        out_file = self.target_dir / "flags" / "flag_hunt_commands.txt"
        lines = [f"# Flag Hunt Commands for {self.target}", ""]

        if self.os_type in ("Linux", "Unknown"):
            linux_cmds = self._linux_flag_commands()
            self.results["flag_commands"]["linux"] = linux_cmds
            lines.append("# === LINUX ===")
            lines.extend(linux_cmds)
            lines.append("")

        if self.os_type in ("Windows", "Unknown"):
            win_cmds = self._windows_flag_commands()
            self.results["flag_commands"]["windows"] = win_cmds
            lines.append("# === WINDOWS ===")
            lines.extend(win_cmds)

        save_output(out_file, "\n".join(lines))
        console.print(f"[green][+] Flag hunt commands: {out_file}[/green]")
        self._print_flag_commands()

    def _linux_flag_commands(self) -> List[str]:
        """Linux flag search commands."""
        cmds = [
            "# Quick hits:",
            "cat /root/root.txt 2>/dev/null || cat /root/proof.txt 2>/dev/null",
            "find /home -name 'user.txt' -exec cat {} \\; 2>/dev/null",
            "find /home -name 'local.txt' -exec cat {} \\; 2>/dev/null",
            "",
            "# Comprehensive recursive search from root:",
            "find / -name 'user.txt' -o -name 'root.txt' -o -name 'proof.txt' "
            "-o -name 'flag.txt' -o -name 'local.txt' 2>/dev/null",
            "",
            "# Search with content display:",
            "for f in $(find / -name 'user.txt' -o -name 'root.txt' "
            "-o -name 'proof.txt' -o -name 'local.txt' -o -name 'flag.txt' 2>/dev/null); "
            "do echo \"=== $f ===\"; cat \"$f\"; done",
            "",
            "# If you suspect flag is hidden/encoded:",
            "find / -name '*.txt' -readable 2>/dev/null | xargs grep -l -E '[a-f0-9]{32}' 2>/dev/null",
            "",
            "# User home directories:",
            "ls -la /home/",
            "find /home -type f -readable 2>/dev/null | head -50",
        ]
        return cmds

    def _windows_flag_commands(self) -> List[str]:
        """Windows flag search commands (CMD and PowerShell)."""
        cmds = [
            "REM Quick hits:",
            "type C:\\Users\\Administrator\\Desktop\\root.txt 2>nul",
            "type C:\\Users\\Administrator\\Desktop\\proof.txt 2>nul",
            'dir C:\\Users\\*\\Desktop\\ /s | findstr /i "txt"',
            "",
            "REM Recursive search:",
            'dir /s /b C:\\Users\\*.txt 2>nul | findstr /i "user root proof flag local"',
            'dir /s /b C:\\*.txt 2>nul | findstr /i "user root proof flag local"',
            "",
            "# PowerShell recursive:",
            "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue "
            "-Filter '*.txt' | Where-Object {$_.Name -match 'user|root|proof|flag|local'} "
            "| Select-Object FullName | ForEach-Object {$_.FullName; Get-Content $_.FullName}",
            "",
            "REM Check common locations:",
            "dir C:\\Documents and Settings\\Administrator\\Desktop\\ 2>nul",
            "dir C:\\Shares\\ 2>nul",
        ]
        return cmds

    async def _check_recon_for_flags(self):
        """Scan already-collected recon output for flag patterns."""
        flag_re = re.compile(r"[a-f0-9]{32}", re.IGNORECASE)
        oscp_flag_re = re.compile(
            r"(?:user|root|proof|flag|local)\.txt[:\s]+([a-f0-9]{32})", re.IGNORECASE
        )

        raw_outputs = self.all_results.get("recon", {}).get("raw", {})
        for source, content in raw_outputs.items():
            if not isinstance(content, str):
                continue
            for m in oscp_flag_re.finditer(content):
                flag = {"value": m.group(1), "source": source}
                if flag not in self.results["flags_found"]:
                    self.results["flags_found"].append(flag)
                    console.print(f"[bold red][!!!] FLAG FOUND in {source}: {m.group(1)}[/bold red]")

            # Collect hashes
            for m in flag_re.finditer(content):
                h = m.group(0)
                if len(h) == 32 and h not in [x.get("hash") for x in self.results["hashes_found"]]:
                    hash_type = self._identify_hash(h)
                    self.results["hashes_found"].append({"hash": h, "type": hash_type, "source": source})

    def _identify_hash(self, h: str) -> str:
        """Identify hash type from its format."""
        for name, pattern in HASH_PATTERNS.items():
            if pattern.match(h):
                return name
        return "Unknown"

    async def _generate_hash_cracking_guide(self):
        """Generate hashcat / john commands for discovered hashes."""
        out_file = self.target_dir / "flags" / "cracking_guide.txt"
        passlist = self.cfg.get("pass_wordlist", "/usr/share/wordlists/rockyou.txt")

        lines = [
            "# Hash Cracking Guide",
            f"# Wordlist: {passlist}",
            "",
            "# ── Hashcat Modes ──",
            "# MD5:         -m 0",
            "# NTLM:        -m 1000",
            "# NTLMv2:      -m 5600",
            "# SHA1:        -m 100",
            "# bcrypt:      -m 3200",
            "# sha512crypt: -m 1800",
            "# sha256crypt: -m 7400",
            "# WPA:         -m 2500",
            "",
            "# ── Examples ──",
            f"hashcat -m 0 hash.txt {passlist}",
            f"hashcat -m 1000 hash.txt {passlist}  # NTLM",
            f"hashcat -m 5600 hash.txt {passlist}  # NTLMv2",
            f"john --wordlist={passlist} hash.txt",
            "",
            "# ── Online Resources ──",
            "# https://crackstation.net/",
            "# https://hashes.com/",
            "# https://md5decrypt.net/",
            "",
            "# ── Identify Hash Type ──",
            "hashid hash.txt",
            "hash-identifier",
            "python3 -c \"import hashid; h=hashid.HashID(); print(h.identifyHash('HASHHERE'))\"",
        ]

        if self.results["hashes_found"]:
            lines.append("\n# ── Discovered Hashes ──")
            for entry in self.results["hashes_found"]:
                lines.append(f"# [{entry['type']}] {entry['hash']} (from: {entry['source']})")
                lines.append(f"hashcat -m 0 '{entry['hash']}' {passlist}")
                lines.append("")

        save_output(out_file, "\n".join(lines))
        self.results["cracking_commands"] = lines

    def _print_flag_commands(self):
        """Display flag commands in a panel."""
        linux_cmds = self.results["flag_commands"].get("linux", [])
        win_cmds = self.results["flag_commands"].get("windows", [])

        key_linux = [c for c in linux_cmds if not c.startswith("#") and c.strip()][:4]
        key_win = [c for c in win_cmds if not c.startswith(("REM", "#")) and c.strip()][:3]

        content = "[bold]Linux:[/bold]\n"
        for c in key_linux:
            content += f"  [cyan]{c}[/cyan]\n"

        content += "\n[bold]Windows:[/bold]\n"
        for c in key_win:
            content += f"  [cyan]{c}[/cyan]\n"

        console.print(Panel(content, title="[bold green]🚩 FLAG HUNT COMMANDS[/bold green]", border_style="green"))

    def _print_flag_summary(self):
        """Display discovered flags."""
        if self.results["flags_found"]:
            console.print("\n[bold red]" + "=" * 60 + "[/bold red]")
            console.print("[bold red]  🚩🚩🚩  FLAGS DISCOVERED!  🚩🚩🚩[/bold red]")
            console.print("[bold red]" + "=" * 60 + "[/bold red]")

            for flag in self.results["flags_found"]:
                console.print(f"  [bold green]FLAG: {flag['value']}[/bold green]")
                console.print(f"  [dim]Source: {flag['source']}[/dim]")

            # Save flags to file
            flag_file = self.target_dir / "flags" / "FOUND_FLAGS.txt"
            content = "\n".join(
                f"FLAG: {f['value']} (from: {f['source']})"
                for f in self.results["flags_found"]
            )
            save_output(flag_file, content)
            console.print(f"\n[green]Flags saved to: {flag_file}[/green]")
        else:
            console.print("\n[yellow][!] No flags auto-discovered. Run commands manually on victim.[/yellow]")

        if self.results["hashes_found"]:
            console.print(f"\n[yellow][!] {len(self.results['hashes_found'])} hash(es) found - see cracking guide[/yellow]")
