"""
utils.py - Shared utilities, helpers, and dependency checking
v2: XML nmap parser, structured findings, async runner improvements
"""

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
)
from rich.table import Table

console = Console()

# ─── Tool registry ────────────────────────────────────────────────────────────
REQUIRED_TOOLS = ["nmap", "python3"]
OPTIONAL_TOOLS = {
    # Recon
    "gobuster": "Directory brute-forcing",
    "ffuf": "Fast HTTP fuzzing",
    "feroxbuster": "Recursive content discovery",
    "nikto": "Web vulnerability scanner",
    "whatweb": "Web technology detection",
    "wpscan": "WordPress scanner",
    "gowitness": "Web screenshots",
    "enum4linux-ng": "SMB enumeration",
    "smbclient": "SMB client",
    "smbmap": "SMB share mapper",
    "crackmapexec": "Multi-protocol exploitation",
    "rpcclient": "RPC enumeration",
    "snmpwalk": "SNMP enumeration",
    "showmount": "NFS enumeration",
    # Exploit
    "searchsploit": "Exploit-DB search",
    "msfconsole": "Metasploit Framework",
    "msfvenom": "Payload generator",
    "nuclei": "Template-based scanner",
    "sqlmap": "SQL injection automation",
    # Brute force
    "hydra": "Network password brute-forcer",
    "kerbrute": "Kerberos user enumeration",
    "hashcat": "GPU hash cracker",
    "john": "John the Ripper",
    # Active Directory
    "impacket-secretsdump": "AD secrets dumper",
    "impacket-GetNPUsers": "ASREPRoasting",
    "impacket-GetUserSPNs": "Kerberoasting",
    "impacket-psexec": "Impacket psexec",
    "bloodhound-python": "BloodHound collector",
    "evil-winrm": "WinRM shell",
    # Misc
    "nc": "Netcat",
    "rlwrap": "Readline wrapper (better shells)",
    "curl": "HTTP client",
    "wget": "File downloader",
    "pwncat-cs": "Advanced shell catcher",
}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


# ─── Structured findings (used across modules) ────────────────────────────────

@dataclass
class Finding:
    """A structured finding from any phase."""
    category: str           # recon|exploit|privesc|flag
    severity: str           # info|low|medium|high|critical
    title: str
    detail: str = ""
    source: str = ""
    target: str = ""
    cmd_hint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Port:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)

    @property
    def banner(self) -> str:
        return f"{self.service} {self.product} {self.version}".strip()


# ─── Logging ──────────────────────────────────────────────────────────────────

def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / "autopwn.log"
    level = logging.DEBUG if verbose else logging.INFO

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            RichHandler(console=console, rich_tracebacks=True, show_path=False,
                        show_time=False, markup=False),
            logging.FileHandler(log_file),
        ],
    )
    return logging.getLogger("autopwn")


def print_banner():
    banner = """
[bold red]  ██████╗ ███████╗ ██████╗██████╗     ██████╗ ██╗    ██╗███╗   ██╗[/bold red]
[bold red] ██╔═══██╗██╔════╝██╔════╝██╔══██╗   ██╔══██╗██║    ██║████╗  ██║[/bold red]
[bold red] ██║   ██║███████╗██║     ██████╔╝   ██████╔╝██║ █╗ ██║██╔██╗ ██║[/bold red]
[bold yellow] ██║   ██║╚════██║██║     ██╔═══╝    ██╔═══╝ ██║███╗██║██║╚██╗██║[/bold yellow]
[bold yellow] ╚██████╔╝███████║╚██████╗██║        ██║     ╚███╔███╔╝██║ ╚████║[/bold yellow]
[bold yellow]  ╚═════╝ ╚══════╝ ╚═════╝╚═╝        ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝[/bold yellow]
[dim]              OSCP Lab Automation Framework v2.1[/dim]
[dim]         ⚠  For Authorized Lab / CTF Environments Only  ⚠[/dim]
"""
    console.print(banner)


def print_phase(num: int, name: str, target: str):
    colors = {1: "cyan", 2: "yellow", 3: "red", 4: "magenta", 5: "green"}
    color = colors.get(num, "white")
    bar = "─" * 60
    console.print(f"\n[bold {color}]┌{bar}┐[/bold {color}]")
    console.print(f"[bold {color}]│ PHASE {num}: {name:<48} │[/bold {color}]")
    console.print(f"[bold {color}]│ Target: {target:<50} │[/bold {color}]")
    console.print(f"[bold {color}]└{bar}┘[/bold {color}]\n")


def check_dependencies(dry_run: bool = False, quiet: bool = False) -> Dict[str, bool]:
    available = {}
    missing_required = []

    for tool in REQUIRED_TOOLS:
        ok = shutil.which(tool) is not None
        available[tool] = ok
        if not ok:
            missing_required.append(tool)
    for tool in OPTIONAL_TOOLS:
        available[tool] = shutil.which(tool) is not None

    if not quiet:
        table = Table(title="Tool Availability", show_header=True, header_style="bold cyan")
        table.add_column("Tool", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Purpose")

        for tool in REQUIRED_TOOLS:
            table.add_row(tool,
                          "[green]✔[/green]" if available[tool] else "[red]✘[/red]",
                          "[bold]REQUIRED[/bold]")
        for tool, purpose in OPTIONAL_TOOLS.items():
            ok = available[tool]
            table.add_row(tool,
                          "[green]✔[/green]" if ok else "[dim yellow]~[/dim yellow]",
                          purpose if ok else f"[dim]{purpose}[/dim]")
        console.print(table)

    if missing_required and not dry_run:
        console.print(f"[red][!] Missing required tools: {missing_required}[/red]")
        sys.exit(1)
    return available


def expand_targets(target: str) -> List[str]:
    targets: List[str] = []
    p = Path(target)
    if p.is_file():
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.extend(expand_targets(line))
        return targets
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            return [str(ip) for ip in net.hosts()]
        return [str(net.network_address)]
    except ValueError:
        pass
    targets.append(target)
    return targets


async def run_command(
    cmd: List[Any],
    timeout: int = 300,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    log: Optional[logging.Logger] = None,
    dry_run: bool = False,
    input_data: Optional[bytes] = None,
) -> Tuple[int, str, str]:
    cmd_list = [str(c) for c in cmd]
    cmd_str = " ".join(cmd_list)
    if log:
        log.debug(f"[CMD] {cmd_str}")
    if dry_run:
        console.print(f"[dim][DRY-RUN] {cmd_str}[/dim]")
        return 0, "", ""

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_list,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **(env or {})},
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=input_data), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
            if log:
                log.warning(f"Timeout {timeout}s: {cmd_str}")
            return -1, "", f"TIMEOUT after {timeout}s"
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except FileNotFoundError:
        if log:
            log.error(f"Command not found: {cmd_list[0]}")
        return 127, "", f"Command not found: {cmd_list[0]}"
    except Exception as e:
        if log:
            log.error(f"Command error: {e}")
        return -1, "", str(e)


async def run_command_shell(cmd: str, timeout: int = 300, cwd: Optional[Path] = None,
                            log=None, dry_run: bool = False) -> Tuple[int, str, str]:
    if log:
        log.debug(f"[SHELL] {cmd}")
    if dry_run:
        console.print(f"[dim][DRY-RUN] {cmd}[/dim]")
        return 0, "", ""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return -1, "", f"TIMEOUT after {timeout}s"
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except Exception as e:
        return -1, "", str(e)


def save_output(path: Path, content: str, mode: str = "w"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode) as f:
        f.write(content)


# ─── Nmap XML parser (replaces fragile text parsing) ──────────────────────────

def parse_nmap_xml(xml_path: Path) -> Tuple[List[Port], Dict[str, Any]]:
    """Parse nmap -oX output. Returns (ports, host_info)."""
    ports: List[Port] = []
    host_info: Dict[str, Any] = {"os": "Unknown", "hostnames": [], "scripts": {}}

    if not xml_path.exists():
        return ports, host_info
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return ports, host_info

    for host in root.findall("host"):
        for hn in host.findall(".//hostname"):
            name = hn.get("name")
            if name:
                host_info["hostnames"].append(name)

        os_elem = host.find(".//osmatch")
        if os_elem is not None:
            host_info["os"] = os_elem.get("name", "Unknown")

        for script in host.findall(".//hostscript/script"):
            sid = script.get("id", "")
            host_info["scripts"][sid] = script.get("output", "")

        for port_elem in host.findall(".//port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_elem.find("service")
            scripts = {}
            for sc in port_elem.findall("script"):
                scripts[sc.get("id", "")] = sc.get("output", "")
            p = Port(
                port=int(port_elem.get("portid", 0)),
                protocol=port_elem.get("protocol", "tcp"),
                state="open",
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extrainfo=svc.get("extrainfo", "") if svc is not None else "",
                scripts=scripts,
            )
            ports.append(p)
    return ports, host_info


def identify_os(host_info: dict, ports: List[Port]) -> str:
    osname = host_info.get("os", "").lower()
    if any(w in osname for w in ("windows", "microsoft")):
        return "Windows"
    if any(w in osname for w in ("linux", "ubuntu", "debian", "centos", "fedora", "unix")):
        return "Linux"
    win, nix = 0, 0
    for p in ports:
        banner = (p.banner + " " + " ".join(p.scripts.values())).lower()
        if any(w in banner for w in ("microsoft", "windows", "iis", "smb", "netbios", "ms-wbt")):
            win += 1
        if any(w in banner for w in ("openssh", "ubuntu", "debian", "linux", "unix", "apache")):
            nix += 1
    if win > nix:
        return "Windows"
    if nix > win:
        return "Linux"
    return "Unknown"


# ─── Backwards-compat helpers for old text parsing ───────────────────────────

def parse_ports_from_nmap(nmap_output: str) -> List[dict]:
    """Legacy text-based parser. Prefer parse_nmap_xml when XML is available."""
    ports = []
    port_re = re.compile(r"(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)")
    for line in nmap_output.splitlines():
        m = port_re.match(line.strip())
        if m:
            ports.append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip(),
            })
    return ports


def get_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def url_join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def sanitize(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._\-]", "_", s)