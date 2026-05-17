#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          OSCP AUTOPWN FRAMEWORK - AUTHORIZED LAB USE ONLY                  ║
║                                                                              ║
║  ██████╗ ███████╗ ██████╗██████╗     ██████╗ ██╗    ██╗███╗   ██╗          ║
║ ██╔═══██╗██╔════╝██╔════╝██╔══██╗   ██╔══██╗██║    ██║████╗  ██║          ║
║ ██║   ██║███████╗██║     ██████╔╝   ██████╔╝██║ █╗ ██║██╔██╗ ██║          ║
║ ██║   ██║╚════██║██║     ██╔═══╝    ██╔═══╝ ██║███╗██║██║╚██╗██║          ║
║ ╚██████╔╝███████║╚██████╗██║        ██║     ╚███╔███╔╝██║ ╚████║          ║
║  ╚═════╝ ╚══════╝ ╚═════╝╚═╝        ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝          ║
║                                                                              ║
║  ⚠️  WARNING: FOR AUTHORIZED PENETRATION TESTING AND CTF/LAB USE ONLY ⚠️   ║
║  Unauthorized use against systems you don't own is ILLEGAL.                 ║
║  The author assumes NO liability for misuse of this tool.                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import sys
import os
import signal
import typer
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

# Add framework root to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.config_manager import ConfigManager
from modules.session_manager import SessionManager
from modules.recon import ReconModule
from modules.exploit import ExploitModule
from modules.shell_handler import ShellHandler
from modules.privesc import PrivescModule
from modules.flag_hunter import FlagHunter
from modules.reporter import Reporter
from modules.utils import (
    setup_logging, validate_target, expand_targets,
    print_banner, print_phase, check_dependencies
)

console = Console()
app = typer.Typer(
    name="oscp-autopwn",
    help="Automated OSCP Lab Penetration Testing Framework",
    add_completion=False,
    rich_markup_mode="rich",
)


def show_warning():
    """Display mandatory legal warning."""
    warning = Text()
    warning.append("⚠️  LEGAL WARNING  ⚠️\n\n", style="bold red blink")
    warning.append("This tool is designed EXCLUSIVELY for:\n", style="bold yellow")
    warning.append("  • Authorized OSCP lab environments\n", style="green")
    warning.append("  • CTF competitions you are participating in\n", style="green")
    warning.append("  • Systems you OWN or have EXPLICIT written permission to test\n", style="green")
    warning.append("\nUnauthorized use is a CRIMINAL OFFENSE under:\n", style="bold red")
    warning.append("  • Computer Fraud and Abuse Act (CFAA) - USA\n", style="red")
    warning.append("  • Computer Misuse Act - UK\n", style="red")
    warning.append("  • Similar laws in most jurisdictions worldwide\n", style="red")
    warning.append("\nBy continuing, you confirm you have EXPLICIT authorization.", style="bold yellow")

    console.print(Panel(warning, title="[bold red]⚠️  AUTHORIZED USE ONLY  ⚠️", border_style="red"))


@app.command()
def pwn(
    target: str = typer.Argument(..., help="Target IP, CIDR range, or file with IPs"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML/JSON config file"),
    output_dir: Path = typer.Option(Path("./output"), "--output", "-o", help="Output directory"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Domain name"),
    username: Optional[str] = typer.Option(None, "--user", "-u", help="Known username"),
    password: Optional[str] = typer.Option(None, "--pass", "-p", help="Known password"),
    vpn_iface: Optional[str] = typer.Option(None, "--vpn", help="VPN interface (e.g., tun0)"),
    lhost: Optional[str] = typer.Option(None, "--lhost", help="Local IP for reverse shells"),
    lport: int = typer.Option(4444, "--lport", help="Local port for reverse shells"),
    phases: Optional[str] = typer.Option(None, "--phases", help="Phases to run: recon,exploit,shell,privesc,flags"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without executing"),
    resume: bool = typer.Option(False, "--resume", help="Resume from previous session"),
    threads: int = typer.Option(10, "--threads", "-t", help="Concurrent threads"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", "-w", help="Custom wordlist"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    no_metasploit: bool = typer.Option(False, "--no-msf", help="Disable Metasploit integration"),
    timeout: int = typer.Option(300, "--timeout", help="Per-tool timeout in seconds"),
    skip_warnings: bool = typer.Option(False, "--skip-warnings", help="Skip legal warnings (implies you accept)"),
):
    """
    [bold green]OSCP AutoPwn[/bold green] - Full automated lab machine compromise pipeline.

    Examples:\n
      [cyan]python main.py 10.10.10.5[/cyan]\n
      [cyan]python main.py 10.10.10.0/24 --phases recon,exploit[/cyan]\n
      [cyan]python main.py targets.txt --config lab.yaml --lhost 10.10.14.1[/cyan]
    """
    print_banner()

    if not skip_warnings:
        show_warning()
        confirm = typer.confirm("\n[!] Do you confirm you have explicit authorization to test these targets?")
        if not confirm:
            console.print("[red]Aborted. No authorization confirmed.[/red]")
            raise typer.Exit(1)

    # Setup logging
    log = setup_logging(output_dir, verbose)
    log.info("OSCP AutoPwn Framework started")

    # Load config
    cfg = ConfigManager(config_file=config)
    cfg.set("dry_run", dry_run)
    cfg.set("threads", threads)
    cfg.set("timeout", timeout)
    cfg.set("verbose", verbose)
    cfg.set("lport", lport)
    cfg.set("no_metasploit", no_metasploit)
    if wordlist:
        cfg.set("wordlist", str(wordlist))

    # Determine LHOST
    if not lhost:
        lhost = cfg.get_lhost(vpn_iface)
    cfg.set("lhost", lhost)
    console.print(f"[cyan][*] LHOST set to:[/cyan] [bold]{lhost}[/bold]")

    # Parse phases
    run_phases = set(phases.lower().split(",")) if phases else {"recon", "exploit", "shell", "privesc", "flags"}
    console.print(f"[cyan][*] Active phases:[/cyan] [bold]{', '.join(sorted(run_phases))}[/bold]")

    if dry_run:
        console.print("[yellow][DRY-RUN] No commands will be executed[/yellow]")

    # Check dependencies
    check_dependencies(dry_run)

    # Expand targets
    targets = expand_targets(target)
    console.print(f"[cyan][*] Targets:[/cyan] [bold]{len(targets)} host(s)[/bold]")

    # Known creds
    known_creds = {}
    if username and password:
        known_creds = {"username": username, "password": password}
        cfg.set("known_creds", known_creds)

    if domain:
        cfg.set("domain", domain)

    # Run async pipeline
    try:
        asyncio.run(
            run_pipeline(
                targets=targets,
                output_dir=output_dir,
                cfg=cfg,
                run_phases=run_phases,
                resume=resume,
                log=log,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user. Saving state...[/yellow]")
        sys.exit(0)


async def run_pipeline(targets, output_dir, cfg, run_phases, resume, log):
    """Main async pipeline orchestrator."""
    session = SessionManager(output_dir, resume)
    reporter = Reporter(output_dir)
    all_results = {}

    for target_ip in targets:
        console.print(f"\n[bold magenta]{'='*60}[/bold magenta]")
        console.print(f"[bold magenta]  TARGET: {target_ip}[/bold magenta]")
        console.print(f"[bold magenta]{'='*60}[/bold magenta]\n")

        target_dir = Path(output_dir) / target_ip.replace("/", "_")
        target_dir.mkdir(parents=True, exist_ok=True)

        results = session.load_state(target_ip) or {}
        results["target"] = target_ip

        try:
            # ── Phase 1: Recon ──────────────────────────────────────────────
            if "recon" in run_phases:
                print_phase(1, "RECONNAISSANCE & ENUMERATION", target_ip)
                recon = ReconModule(target_ip, target_dir, cfg, log)
                recon_results = await recon.run()
                results["recon"] = recon_results
                session.save_state(target_ip, results)

            # ── Phase 2: Exploit ────────────────────────────────────────────
            if "exploit" in run_phases and results.get("recon"):
                print_phase(2, "VULNERABILITY ANALYSIS & EXPLOITATION", target_ip)
                exploiter = ExploitModule(target_ip, target_dir, cfg, log, results["recon"])
                exploit_results = await exploiter.run()
                results["exploit"] = exploit_results
                session.save_state(target_ip, results)

            # ── Phase 3: Shell ──────────────────────────────────────────────
            if "shell" in run_phases:
                print_phase(3, "INITIAL ACCESS / SHELL", target_ip)
                shell_mgr = ShellHandler(target_ip, target_dir, cfg, log, results)
                shell_results = await shell_mgr.run()
                results["shell"] = shell_results
                session.save_state(target_ip, results)

            # ── Phase 4: PrivEsc ────────────────────────────────────────────
            if "privesc" in run_phases and results.get("shell", {}).get("success"):
                print_phase(4, "POST-EXPLOITATION & PRIVILEGE ESCALATION", target_ip)
                privesc = PrivescModule(target_ip, target_dir, cfg, log, results)
                privesc_results = await privesc.run()
                results["privesc"] = privesc_results
                session.save_state(target_ip, results)

            # ── Phase 5: Flags ──────────────────────────────────────────────
            if "flags" in run_phases:
                print_phase(5, "FLAG HUNTING", target_ip)
                hunter = FlagHunter(target_ip, target_dir, cfg, log, results)
                flag_results = await hunter.run()
                results["flags"] = flag_results
                session.save_state(target_ip, results)

        except Exception as e:
            log.error(f"Pipeline error for {target_ip}: {e}", exc_info=True)
            console.print(f"[red][!] Pipeline error for {target_ip}: {e}[/red]")

        all_results[target_ip] = results

    # Generate final report
    reporter.generate(all_results)
    console.print("\n[bold green]✔ Framework run complete. Report saved to output/report.html[/bold green]")


if __name__ == "__main__":
    app()
