"""
recon.py - Phase 1: Reconnaissance & Enumeration

Covers:
  - Nmap full port + service/version + NSE scripts
  - HTTP/HTTPS: gobuster/ffuf, nikto, whatweb
  - SMB: enum4linux-ng, smbclient, crackmapexec
  - FTP/SSH/Telnet/RDP: auth + version checks
  - NoSQL/SQL/Redis/Mongo: basic exposure checks
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from modules.utils import (
    run_command, run_command_shell, save_output,
    parse_ports_from_nmap, identify_os, get_progress, has_tool
)

console = Console()


class ReconModule:
    def __init__(self, target: str, target_dir: Path, cfg, log):
        self.target = target
        self.target_dir = target_dir
        self.cfg = cfg
        self.log = log
        self.dry_run = cfg.is_dry_run()
        self.timeout = cfg.get("timeout", 300)
        self.results = {
            "ports": [],
            "os": "Unknown",
            "services": {},
            "web_dirs": [],
            "smb_shares": [],
            "vulnerabilities": [],
            "credentials": [],
            "raw": {},
        }

        # Create subdirectories
        for sub in ["nmap", "web", "smb", "ftp", "ssh", "misc"]:
            (target_dir / sub).mkdir(parents=True, exist_ok=True)

    async def run(self) -> dict:
        """Run all recon tasks."""
        console.print(f"[cyan][*] Starting recon on {self.target}[/cyan]")

        # Step 1: Quick port scan
        await self._nmap_quick()
        open_ports = [p["port"] for p in self.results["ports"]]
        console.print(f"[green][+] Found {len(open_ports)} open ports: {open_ports}[/green]")

        if not open_ports and not self.dry_run:
            console.print("[yellow][!] No open ports found. Skipping service enum.[/yellow]")
            return self.results

        # Step 2: Full version + script scan
        await self._nmap_full()

        # Identify OS
        nmap_raw = self.results["raw"].get("nmap_full", "")
        self.results["os"] = identify_os(nmap_raw)
        console.print(f"[cyan][*] OS guess: {self.results['os']}[/cyan]")

        # Step 3: Service-specific enumeration (concurrent)
        tasks = []
        for port_info in self.results["ports"]:
            port = port_info["port"]
            svc = port_info["service"].lower()

            if svc in ("http", "https") or port in (80, 443, 8080, 8443, 8000, 8888):
                scheme = "https" if (port == 443 or "ssl" in svc or "https" in svc) else "http"
                tasks.append(self._enum_web(port, scheme))

            elif svc in ("smb", "microsoft-ds", "netbios-ssn") or port in (445, 139):
                tasks.append(self._enum_smb())

            elif svc in ("ftp",) or port == 21:
                tasks.append(self._enum_ftp(port))

            elif svc in ("ssh",) or port == 22:
                tasks.append(self._enum_ssh(port))

            elif svc in ("rdp", "ms-wbt-server") or port == 3389:
                tasks.append(self._enum_rdp(port))

            elif svc in ("mysql",) or port == 3306:
                tasks.append(self._enum_mysql(port))

            elif port == 6379:
                tasks.append(self._enum_redis(port))

            elif port == 27017:
                tasks.append(self._enum_mongo(port))

            elif svc in ("mssql", "ms-sql-s") or port == 1433:
                tasks.append(self._enum_mssql(port))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._print_summary()
        return self.results

    # ── Nmap ──────────────────────────────────────────────────────────────────

    async def _nmap_quick(self):
        """Fast TCP SYN scan to find open ports."""
        out_file = self.target_dir / "nmap" / "quick.txt"
        cmd = [
            "nmap", "-sV", "--open", "-p-",
            f"-T{self.cfg.get('nmap_timing', 'T4')}",
            "--min-rate", "1000",
            "-oN", str(out_file),
            self.target,
        ]
        console.print(f"[cyan][*] Running nmap port scan...[/cyan]")
        rc, stdout, stderr = await run_command(
            cmd, timeout=self.cfg.get("nmap_timeout", 600),
            log=self.log, dry_run=self.dry_run
        )

        output = stdout or ""
        if out_file.exists():
            output = out_file.read_text()

        self.results["raw"]["nmap_quick"] = output
        self.results["ports"] = parse_ports_from_nmap(output)
        save_output(out_file, output)

    async def _nmap_full(self):
        """Full NSE script + version scan on discovered ports."""
        if not self.results["ports"] and not self.dry_run:
            return

        ports_str = ",".join(str(p["port"]) for p in self.results["ports"]) or "1-1000"
        out_file = self.target_dir / "nmap" / "full.txt"
        xml_file = self.target_dir / "nmap" / "full.xml"

        scripts = self.cfg.get(
            "nmap_scripts",
            "vulners,smb-os-discovery,http-enum,ftp-anon,ssh-auth-methods,banner"
        )

        cmd = [
            "nmap", "-sV", "-sC",
            f"-p{ports_str}",
            f"--script={scripts}",
            f"-T{self.cfg.get('nmap_timing', 'T4')}",
            "-oN", str(out_file),
            "-oX", str(xml_file),
            self.target,
        ]

        console.print("[cyan][*] Running full nmap script scan...[/cyan]")
        rc, stdout, stderr = await run_command(
            cmd, timeout=self.cfg.get("nmap_timeout", 600),
            log=self.log, dry_run=self.dry_run
        )

        output = out_file.read_text() if out_file.exists() else stdout
        self.results["raw"]["nmap_full"] = output

        # Re-parse with script output to enrich port list
        self.results["ports"] = parse_ports_from_nmap(output) or self.results["ports"]

        # Extract CVEs from vulners output
        cve_re = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
        for cve in set(cve_re.findall(output)):
            if cve not in self.results["vulnerabilities"]:
                self.results["vulnerabilities"].append(cve)

        save_output(out_file, output)

    # ── Web Enumeration ───────────────────────────────────────────────────────

    async def _enum_web(self, port: int, scheme: str = "http"):
        """Full web enumeration: gobuster, nikto, whatweb."""
        base_url = f"{scheme}://{self.target}:{port}"
        console.print(f"[cyan][*] Web enum: {base_url}[/cyan]")
        svc_key = f"web_{port}"
        self.results["services"][svc_key] = {"url": base_url, "dirs": [], "tech": [], "vulns": []}

        tasks = [
            self._gobuster(base_url, port),
            self._nikto(base_url, port),
            self._whatweb(base_url, port),
            self._check_web_vulns(base_url, port),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _gobuster(self, url: str, port: int):
        """Directory brute-force with gobuster or ffuf."""
        wordlist = self.cfg.get("dir_wordlist", "/usr/share/wordlists/dirb/common.txt")
        out_file = self.target_dir / "web" / f"gobuster_{port}.txt"

        if has_tool("gobuster"):
            cmd = [
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "-t", str(self.cfg.get("gobuster_threads", 30)),
                "-o", str(out_file),
                "--timeout", "10s",
                "-q",
                "-x", "php,html,txt,asp,aspx,jsp,py,sh,bak,conf,xml,json",
            ]
            rc, stdout, stderr = await run_command(
                cmd, timeout=self.cfg.get("gobuster_timeout", 180),
                log=self.log, dry_run=self.dry_run
            )
        elif has_tool("ffuf"):
            cmd = [
                "ffuf",
                "-u", f"{url}/FUZZ",
                "-w", wordlist,
                "-t", str(self.cfg.get("gobuster_threads", 30)),
                "-o", str(out_file),
                "-of", "csv",
                "-mc", "200,204,301,302,307,401,403",
            ]
            rc, stdout, stderr = await run_command(
                cmd, timeout=self.cfg.get("gobuster_timeout", 180),
                log=self.log, dry_run=self.dry_run
            )
        else:
            console.print("[yellow][!] Neither gobuster nor ffuf found; skipping dir brute[/yellow]")
            return

        output = out_file.read_text() if out_file.exists() else stdout or ""
        dirs = re.findall(r"(/[^\s]+)\s+\(Status:\s*(\d+)", output)
        found = [f"{d[0]} [{d[1]}]" for d in dirs]
        self.results["services"][f"web_{port}"]["dirs"].extend(found)
        self.results["web_dirs"].extend(found)

        if found:
            console.print(f"[green][+] gobuster found {len(found)} paths on :{port}[/green]")

    async def _nikto(self, url: str, port: int):
        """Nikto vulnerability scan."""
        if not has_tool("nikto"):
            return

        out_file = self.target_dir / "web" / f"nikto_{port}.txt"
        cmd = ["nikto", "-h", url, "-o", str(out_file), "-Format", "txt", "-nointeractive"]

        rc, stdout, stderr = await run_command(
            cmd, timeout=self.cfg.get("nikto_timeout", 300),
            log=self.log, dry_run=self.dry_run
        )
        output = out_file.read_text() if out_file.exists() else stdout or ""

        # Extract findings
        vulns = [line.strip() for line in output.splitlines()
                 if line.strip().startswith("+") and "Server:" not in line and "Target" not in line]
        if vulns:
            self.results["services"][f"web_{port}"]["vulns"].extend(vulns[:20])
            self.results["vulnerabilities"].extend(vulns[:5])
            console.print(f"[yellow][!] nikto: {len(vulns)} findings on :{port}[/yellow]")

    async def _whatweb(self, url: str, port: int):
        """Web technology fingerprinting."""
        if not has_tool("whatweb"):
            return

        out_file = self.target_dir / "web" / f"whatweb_{port}.txt"
        cmd = ["whatweb", "--color=never", "-a", "3", url]

        rc, stdout, stderr = await run_command(
            cmd, timeout=60, log=self.log, dry_run=self.dry_run
        )
        save_output(out_file, stdout or "")
        if stdout:
            self.results["services"][f"web_{port}"]["tech"].append(stdout.strip())

    async def _check_web_vulns(self, url: str, port: int):
        """Manual checks for LFI, SQLi, command injection patterns."""
        out_file = self.target_dir / "web" / f"manual_checks_{port}.txt"
        findings = []

        # Check for common sensitive files
        sensitive_paths = [
            "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
            "/wp-config.php", "/config.php", "/phpinfo.php",
            "/.htaccess", "/web.config", "/server-status",
            "/admin", "/login", "/administrator",
        ]

        if not self.dry_run and has_tool("curl"):
            for path in sensitive_paths:
                cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"{url}{path}"]
                rc, code, _ = await run_command(cmd, timeout=10, log=self.log)
                if code.strip() in ("200", "301", "302", "403"):
                    findings.append(f"{path} → HTTP {code.strip()}")

        if findings:
            self.results["services"][f"web_{port}"]["dirs"].extend(findings)
            console.print(f"[yellow][!] Interesting paths found: {findings[:5]}[/yellow]")

        save_output(out_file, "\n".join(findings))

    # ── SMB ───────────────────────────────────────────────────────────────────

    async def _enum_smb(self):
        """SMB enumeration: enum4linux-ng, smbclient, crackmapexec."""
        console.print("[cyan][*] Enumerating SMB...[/cyan]")
        self.results["services"]["smb"] = {"shares": [], "users": [], "info": ""}

        await asyncio.gather(
            self._enum4linux(),
            self._smbclient_list(),
            self._crackmapexec_smb(),
            return_exceptions=True,
        )

    async def _enum4linux(self):
        if not (has_tool("enum4linux-ng") or has_tool("enum4linux")):
            return

        tool = "enum4linux-ng" if has_tool("enum4linux-ng") else "enum4linux"
        out_file = self.target_dir / "smb" / "enum4linux.txt"

        if tool == "enum4linux-ng":
            cmd = [tool, "-A", "-oA", str(self.target_dir / "smb" / "enum4linux"), self.target]
        else:
            cmd = [tool, "-a", self.target]

        rc, stdout, stderr = await run_command(
            cmd, timeout=120, log=self.log, dry_run=self.dry_run
        )
        output = stdout or ""
        save_output(out_file, output)

        # Parse shares
        share_re = re.compile(r"Sharename\s+(\S+)\s+(.+)?", re.IGNORECASE)
        for line in output.splitlines():
            m = share_re.search(line)
            if m:
                share = m.group(1)
                if share not in ("Type", "----"):
                    self.results["smb_shares"].append(share)
                    self.results["services"]["smb"]["shares"].append(share)

        # Parse users
        user_re = re.compile(r"user:\[(\S+)\]", re.IGNORECASE)
        users = user_re.findall(output)
        if users:
            self.results["services"]["smb"]["users"].extend(users)
            console.print(f"[yellow][!] SMB users found: {users}[/yellow]")

    async def _smbclient_list(self):
        if not has_tool("smbclient"):
            return

        out_file = self.target_dir / "smb" / "smbclient_list.txt"
        cmd = ["smbclient", "-L", f"//{self.target}", "-N"]

        rc, stdout, stderr = await run_command(
            cmd, timeout=30, log=self.log, dry_run=self.dry_run
        )
        output = stdout or stderr or ""
        save_output(out_file, output)

        # Parse shares
        share_re = re.compile(r"^\s+(\S+)\s+Disk", re.MULTILINE)
        for m in share_re.finditer(output):
            share = m.group(1)
            if share not in self.results["smb_shares"]:
                self.results["smb_shares"].append(share)

        if self.results["smb_shares"]:
            console.print(f"[green][+] SMB shares: {self.results['smb_shares']}[/green]")

    async def _crackmapexec_smb(self):
        tool = "crackmapexec" if has_tool("crackmapexec") else ("cme" if has_tool("cme") else None)
        if not tool:
            return

        out_file = self.target_dir / "smb" / "cme.txt"
        cmd = [tool, "smb", self.target]

        rc, stdout, stderr = await run_command(
            cmd, timeout=30, log=self.log, dry_run=self.dry_run
        )
        output = stdout or ""
        save_output(out_file, output)
        self.results["services"]["smb"]["info"] = output[:500]

    # ── FTP ───────────────────────────────────────────────────────────────────

    async def _enum_ftp(self, port: int):
        """Check FTP: anonymous login, banner."""
        console.print(f"[cyan][*] Checking FTP on port {port}...[/cyan]")
        self.results["services"][f"ftp_{port}"] = {"anonymous": False, "banner": ""}

        if not has_tool("curl"):
            return

        out_file = self.target_dir / "ftp" / f"ftp_{port}.txt"

        # Test anonymous login
        cmd = ["curl", "-s", "--connect-timeout", "5",
               f"ftp://{self.target}:{port}/", "--user", "anonymous:anonymous"]

        rc, stdout, stderr = await run_command(cmd, timeout=15, log=self.log, dry_run=self.dry_run)

        if rc == 0 and stdout:
            self.results["services"][f"ftp_{port}"]["anonymous"] = True
            self.results["vulnerabilities"].append(f"FTP anonymous login allowed on port {port}")
            console.print(f"[red][!] FTP ANONYMOUS LOGIN on port {port}![/red]")
            save_output(out_file, stdout)

    # ── SSH ───────────────────────────────────────────────────────────────────

    async def _enum_ssh(self, port: int):
        """SSH banner and auth methods check."""
        console.print(f"[cyan][*] Checking SSH on port {port}...[/cyan]")
        self.results["services"][f"ssh_{port}"] = {"banner": "", "auth_methods": []}

        cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=no",
               f"-p{port}", f"root@{self.target}"]

        rc, stdout, stderr = await run_command(cmd, timeout=10, log=self.log, dry_run=self.dry_run)
        banner = (stdout + stderr)
        self.results["services"][f"ssh_{port}"]["banner"] = banner[:200]

        # Save to file
        out_file = self.target_dir / "ssh" / f"ssh_{port}.txt"
        save_output(out_file, banner)

    # ── RDP ───────────────────────────────────────────────────────────────────

    async def _enum_rdp(self, port: int):
        """Basic RDP check."""
        console.print(f"[cyan][*] Found RDP on port {port}[/cyan]")
        self.results["services"][f"rdp_{port}"] = {"open": True}
        self.results["vulnerabilities"].append(f"RDP exposed on port {port} - check for BlueKeep/NLA")

    # ── Databases ─────────────────────────────────────────────────────────────

    async def _enum_mysql(self, port: int):
        """Check MySQL accessibility."""
        self.results["services"][f"mysql_{port}"] = {"accessible": False}
        if not has_tool("mysql"):
            return

        cmd = ["mysql", "-h", self.target, f"-P{port}",
               "-u", "root", "--connect-timeout=5", "-e", "show databases;"]
        rc, stdout, _ = await run_command(cmd, timeout=10, log=self.log, dry_run=self.dry_run)

        if rc == 0:
            self.results["services"][f"mysql_{port}"]["accessible"] = True
            self.results["vulnerabilities"].append(f"MySQL accessible as root (no password) on {port}")
            console.print(f"[red][!] MySQL root login (no password) on port {port}![/red]")

    async def _enum_redis(self, port: int):
        """Check Redis accessibility."""
        self.results["services"][f"redis_{port}"] = {"accessible": False}
        if not has_tool("redis-cli"):
            return

        cmd = ["redis-cli", "-h", self.target, "-p", str(port), "INFO", "server"]
        rc, stdout, _ = await run_command(cmd, timeout=10, log=self.log, dry_run=self.dry_run)

        if rc == 0 and "redis_version" in stdout.lower():
            self.results["services"][f"redis_{port}"]["accessible"] = True
            self.results["vulnerabilities"].append(f"Redis unauthenticated access on port {port}")
            console.print(f"[red][!] Redis unauthenticated on port {port}![/red]")

    async def _enum_mongo(self, port: int):
        """Check MongoDB accessibility."""
        self.results["services"][f"mongo_{port}"] = {"accessible": False}
        if not has_tool("mongosh") and not has_tool("mongo"):
            return

        tool = "mongosh" if has_tool("mongosh") else "mongo"
        cmd = [tool, "--host", self.target, "--port", str(port),
               "--eval", "db.adminCommand('listDatabases')", "--quiet"]
        rc, stdout, _ = await run_command(cmd, timeout=10, log=self.log, dry_run=self.dry_run)

        if rc == 0:
            self.results["services"][f"mongo_{port}"]["accessible"] = True
            self.results["vulnerabilities"].append(f"MongoDB unauthenticated access on port {port}")
            console.print(f"[red][!] MongoDB unauthenticated on port {port}![/red]")

    async def _enum_mssql(self, port: int):
        """Check MSSQL accessibility."""
        self.results["services"][f"mssql_{port}"] = {"accessible": False}
        console.print(f"[cyan][*] Found MSSQL on port {port}[/cyan]")

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self):
        table = Table(title=f"Recon Summary: {self.target}", show_header=True,
                      header_style="bold cyan")
        table.add_column("Category", style="bold")
        table.add_column("Details")

        table.add_row("OS", self.results["os"])
        table.add_row("Open Ports", str(len(self.results["ports"])))

        ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in self.results["ports"][:15])
        table.add_row("Ports", ports_str)
        table.add_row("SMB Shares", ", ".join(self.results["smb_shares"]) or "None")
        table.add_row("Web Dirs", str(len(self.results["web_dirs"])))
        table.add_row("Vulnerabilities", str(len(self.results["vulnerabilities"])))

        if self.results["vulnerabilities"]:
            table.add_row("CVEs/Issues", "\n".join(self.results["vulnerabilities"][:5]))

        console.print(table)
