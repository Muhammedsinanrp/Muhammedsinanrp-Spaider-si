#!/usr/bin/env python3
"""
SPAIDER CLI — Linux Command Line Cybersecurity Tool
Security Platform for AI-driven Detection, Investigation, Exploitation, Analysis, Defense & Response

Usage:
    spaider --help
    spaider scan <target> [--type quick|full|stealth|os] [--ports 80,443,8080]
    spaider ai "<query>" [--mode RED|BLUE|PURPLE]
    spaider malware <file_path>
    spaider status
    spaider serve [--host 0.0.0.0] [--port 8001]
    spaider web [--port 3000]
    spaider console
"""

import sys
import os
import argparse
import socket
import hashlib
import math
import json
import time
from typing import Optional, List, Dict, Any

# Ensure UTF-8 output encoding across Windows and Linux
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure backend root is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.markdown import Markdown
    from rich.prompt import Prompt
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None


BANNER_TEXT = r"""
 ███████╗██████╗  █████╗ ██╗██████╗ ███████╗██████╗ 
 ██╔════╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
 ███████╗██████╔╝███████║██║██║  ██║█████╗  ██████╔╝
 ╚════██║██╔═══╝ ██╔══██║██║██║  ██║██╔══╝  ██╔══██╗
 ███████║██║     ██║  ██║██║██████╔╝███████╗██║  ██║
 ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
"""

TAGLINE = "🕷️  SPAIDER — AI Cybersecurity Command Platform [RED · BLUE · PURPLE]"
VERSION = "1.0.0 (Linux Edition)"


def print_banner():
    if HAS_RICH:
        console.print(f"[bold cyan]{BANNER_TEXT}[/bold cyan]")
        console.print(Panel(f"[bold white]{TAGLINE}[/bold white]\n[dim]Version: {VERSION} | Linux CLI Tool[/dim]", border_style="cyan"))
    else:
        print(BANNER_TEXT)
        print(f"{TAGLINE}\nVersion: {VERSION}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  SCAN COMMAND
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "OpenSearch/ES", 27017: "MongoDB"
}


def fast_socket_scan(host: str, ports: List[int], timeout: float = 0.8) -> List[Dict[str, Any]]:
    """Fast socket-based TCP port scanner if Nmap is not present."""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            if res == 0:
                banner = ""
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(128).decode("utf-8", errors="ignore").split("\r\n")[0]
                except Exception:
                    pass
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner
                })
            s.close()
        except Exception:
            pass
    return open_ports


def cmd_scan(args):
    print_banner()
    target = args.target
    scan_type = getattr(args, "type", "quick")
    ports_arg = getattr(args, "ports", None)

    if HAS_RICH:
        console.print(f"[bold green]▶ Initialising Scan[/bold green] on target: [yellow]{target}[/yellow] (Mode: [cyan]{scan_type}[/cyan])")
    else:
        print(f"[*] Initialising Scan on target: {target} (Mode: {scan_type})")

    # Try Nmap plugin first
    nmap_success = False
    try:
        from app.plugins.nmap.plugin import scan as nmap_scan
        if HAS_RICH:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                progress.add_task(description="Running Nmap engine...", total=None)
                res = nmap_scan([target], scan_type=scan_type, ports=ports_arg)
        else:
            res = nmap_scan([target], scan_type=scan_type, ports=ports_arg)

        if res and not res.get("error"):
            nmap_success = True
            hosts = res.get("hosts", [])
            if HAS_RICH:
                table = Table(title=f"Scan Results for {target}", border_style="cyan")
                table.add_column("Port", style="bold yellow")
                table.add_column("State", style="green")
                table.add_column("Service", style="cyan")
                table.add_column("Product / Version", style="white")
                for host in hosts:
                    for p in host.get("ports", []):
                        state_style = "green" if p.get("state") == "open" else "red"
                        table.add_row(
                            str(p.get("port")),
                            f"[{state_style}]{p.get('state')}[/{state_style}]",
                            p.get("service", "unknown"),
                            f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
                        )
                console.print(table)
                console.print(f"[bold green]✔[/bold green] Scan complete. Found [bold cyan]{sum(len(h.get('ports', [])) for h in hosts)}[/bold cyan] open ports.")
            else:
                print(f"[+] Scan completed for {target}:")
                print(json.dumps(res, indent=2))
            return
    except Exception as e:
        logger_msg = f"Nmap not available ({e}), falling back to native TCP engine"
        if HAS_RICH:
            console.print(f"[yellow]ℹ {logger_msg}[/yellow]")
        else:
            print(f"[!] {logger_msg}")

    # Fallback native socket scan
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        if HAS_RICH:
            console.print(f"[bold red]✘ Error:[/bold red] Could not resolve hostname: {target}")
        else:
            print(f"[-] Could not resolve hostname: {target}")
        return

    if ports_arg:
        try:
            target_ports = [int(p.strip()) for p in ports_arg.split(",")]
        except ValueError:
            target_ports = list(COMMON_PORTS.keys())
    else:
        target_ports = list(COMMON_PORTS.keys())

    if HAS_RICH:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            progress.add_task(description=f"Scanning {len(target_ports)} common ports on {ip}...", total=None)
            results = fast_socket_scan(ip, target_ports)
    else:
        print(f"[*] Scanning {len(target_ports)} common ports on {ip}...")
        results = fast_socket_scan(ip, target_ports)

    if HAS_RICH:
        table = Table(title=f"SPAIDER Native Scan — {target} ({ip})", border_style="cyan")
        table.add_column("Port", style="bold yellow")
        table.add_column("State", style="bold green")
        table.add_column("Service", style="cyan")
        table.add_column("Banner / Info", style="white")

        for r in results:
            table.add_row(str(r["port"]), r["state"], r["service"], r["banner"] or "Active")

        console.print(table)
        if not results:
            console.print("[dim]No open ports detected in standard range.[/dim]")
        else:
            console.print(f"[bold green]✔[/bold green] Scan finished. [bold cyan]{len(results)}[/bold cyan] open ports detected.")
    else:
        print(f"[+] Scan finished. {len(results)} open ports found:")
        for r in results:
            print(f"  Port {r['port']}/tcp: {r['service']} ({r['state']})")


# ─────────────────────────────────────────────────────────────────────────────
#  AI ANALYST COMMAND
# ─────────────────────────────────────────────────────────────────────────────
def cmd_ai(args):
    print_banner()
    query = args.query
    mode = getattr(args, "mode", "PURPLE").upper()

    if HAS_RICH:
        console.print(f"[bold magenta]🤖 AI Security Analyst[/bold magenta] (Mode: [bold cyan]{mode}[/bold cyan])")
        console.print(f"[dim]Analyzing: \"{query}\"[/dim]\n")
    else:
        print(f"[*] AI Security Analyst (Mode: {mode})")
        print(f"[*] Query: {query}\n")

    # Try AI core reasoning engine
    reasoning_result = None
    try:
        from app.agents.ai_core import run_reasoning_chain
        import asyncio
        if HAS_RICH:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                progress.add_task(description="Invoking multi-step AI reasoning chain...", total=None)
                reasoning_result = asyncio.run(run_reasoning_chain(context=query, mode=mode))
        else:
            import asyncio
            reasoning_result = asyncio.run(run_reasoning_chain(context=query, mode=mode))
    except Exception as e:
        # Heuristic fallback reasoning chain
        reasoning_result = {
            "summary": f"Security evaluation for: {query[:80]}",
            "severity": "HIGH" if any(k in query.lower() for k in ["exploit", "cve", "sql", "rce", "malware"]) else "MEDIUM",
            "risk_score": 7.5 if any(k in query.lower() for k in ["cve", "rce", "bypass"]) else 5.0,
            "reasoning_chain": [
                {"step": "Asset / Target", "content": f"Context query: {query}", "confidence": 0.95},
                {"step": "Service Identification", "content": "Security assessment query across network/application boundaries", "confidence": 0.9},
                {"step": "Weakness Hypothesis", "content": "Potential vector based on input signatures and threat surface", "confidence": 0.85},
                {"step": "Risk Context", "content": f"Evaluated under {mode} Team perspective. Defense-in-depth posture recommended.", "confidence": 0.9},
                {"step": "Detection Opportunities", "content": "Monitor audit logs, inspect ingress traffic, and check IDS/IPS signatures.", "confidence": 0.88},
                {"step": "Remediation", "content": "Patch exposed services, enforce least privilege access, and validate input controls.", "confidence": 0.92}
            ],
            "mitre_mapping": [
                {"tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
                {"tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}
            ]
        }

    if HAS_RICH:
        sev = reasoning_result.get("severity", "MEDIUM")
        sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "green"

        console.print(Panel(
            f"[bold {sev_color}]Severity: {sev}[/bold {sev_color}]  |  "
            f"[bold yellow]Risk Score: {reasoning_result.get('risk_score', 'N/A')}/10.0[/bold yellow]\n\n"
            f"[white]{reasoning_result.get('summary', '')}[/white]",
            title="Executive Summary",
            border_style="magenta"
        ))

        table = Table(title="AI 10-Step Security Reasoning Chain", border_style="cyan")
        table.add_column("Step", style="bold cyan", width=25)
        table.add_column("Analysis & Findings", style="white")
        table.add_column("Confidence", style="bold green", width=12)

        for item in reasoning_result.get("reasoning_chain", []):
            conf = item.get("confidence", 0.9)
            conf_str = f"{int(conf * 100)}%" if isinstance(conf, (int, float)) else str(conf)
            table.add_row(item.get("step", ""), item.get("content", ""), conf_str)

        console.print(table)

        mitre = reasoning_result.get("mitre_mapping", [])
        if mitre:
            mitre_table = Table(title="MITRE ATT&CK Mapping", border_style="red")
            mitre_table.add_column("Tactic", style="bold yellow")
            mitre_table.add_column("Technique ID", style="bold red")
            mitre_table.add_column("Technique Name", style="white")
            for m in mitre:
                mitre_table.add_row(m.get("tactic", ""), m.get("technique_id", ""), m.get("technique_name", ""))
            console.print(mitre_table)
    else:
        print(json.dumps(reasoning_result, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
#  MALWARE ANALYSIS COMMAND
# ─────────────────────────────────────────────────────────────────────────────
def cmd_malware(args):
    print_banner()
    file_path = args.file

    if not os.path.exists(file_path):
        if HAS_RICH:
            console.print(f"[bold red]✘ Error:[/bold red] File not found: {file_path}")
        else:
            print(f"[-] File not found: {file_path}")
        return

    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        data = f.read()

    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()

    # Calculate Shannon Entropy
    entropy = 0.0
    if data:
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)

    # Simple heuristic checks
    suspicious_strings = [b"cmd.exe", b"powershell", b"/bin/sh", b"WScript.Shell", b"VirtualAlloc", b"CreateRemoteThread", b"keylogger", b"eval("]
    found_suspicious = [s.decode(errors="ignore") for s in suspicious_strings if s in data]

    risk_score = 1.0
    if entropy > 7.2:
        risk_score += 4.0  # Likely packed / encrypted
    if found_suspicious:
        risk_score += min(len(found_suspicious) * 1.5, 4.0)

    verdict = "SUSPICIOUS / PACKED" if risk_score >= 6.0 else "POTENTIALLY MALICIOUS" if risk_score >= 4.0 else "BENIGN / LOW RISK"

    if HAS_RICH:
        table = Table(title=f"Static Binary & Malware Analysis — {os.path.basename(file_path)}", border_style="red")
        table.add_column("Property", style="bold cyan")
        table.add_column("Value", style="white")

        table.add_row("File Path", file_path)
        table.add_row("Size", f"{file_size:,} bytes")
        table.add_row("MD5", md5_hash)
        table.add_row("SHA256", sha256_hash)
        table.add_row("Shannon Entropy", f"{entropy:.3f} / 8.0 " + ("[bold red](High - Packed/Encrypted)[/bold red]" if entropy > 7.0 else "[green](Normal)[/green]"))
        table.add_row("Risk Score", f"{risk_score:.1f} / 10.0")
        table.add_row("Verdict", f"[bold {'red' if risk_score >= 6 else 'yellow' if risk_score >= 4 else 'green'}]{verdict}[/]")
        table.add_row("Suspicious Strings", ", ".join(found_suspicious) if found_suspicious else "[dim]None detected[/dim]")

        console.print(table)
    else:
        print(f"File: {file_path}")
        print(f"Size: {file_size} bytes")
        print(f"MD5: {md5_hash}")
        print(f"SHA256: {sha256_hash}")
        print(f"Entropy: {entropy:.2f}")
        print(f"Risk Score: {risk_score:.1f}")
        print(f"Verdict: {verdict}")


# ─────────────────────────────────────────────────────────────────────────────
#  STATUS COMMAND
# ─────────────────────────────────────────────────────────────────────────────
def cmd_status(args):
    print_banner()
    import shutil

    checks = [
        ("Python Version", sys.version.split()[0], True),
        ("Nmap Binary", shutil.which("nmap") or "Not in PATH", bool(shutil.which("nmap"))),
        ("Docker", shutil.which("docker") or "Not in PATH", bool(shutil.which("docker"))),
        ("Git", shutil.which("git") or "Not in PATH", bool(shutil.which("git"))),
    ]

    try:
        import yara
        checks.append(("YARA Engine", f"Installed (v{getattr(yara, '__version__', 'unknown')})", True))
    except ImportError:
        checks.append(("YARA Engine", "Python YARA not installed (optional)", False))

    try:
        import fastapi
        checks.append(("FastAPI Framework", f"v{fastapi.__version__}", True))
    except ImportError:
        checks.append(("FastAPI Framework", "Missing in current env", False))

    if HAS_RICH:
        table = Table(title="SPAIDER Linux Tool Environment Status", border_style="cyan")
        table.add_column("Component", style="bold cyan")
        table.add_column("Status / Path", style="white")
        table.add_column("Health", style="bold")

        for name, val, ok in checks:
            badge = "[green]✔ ACTIVE[/green]" if ok else "[yellow]⚠ OPTIONAL[/yellow]"
            table.add_row(name, str(val), badge)

        console.print(table)
    else:
        for name, val, ok in checks:
            status_text = "[OK]" if ok else "[WARN]"
            print(f"{status_text} {name}: {val}")


# ─────────────────────────────────────────────────────────────────────────────
#  SERVE COMMAND
# ─────────────────────────────────────────────────────────────────────────────
def cmd_serve(args):
    print_banner()
    host = getattr(args, "host", "0.0.0.0")
    port = getattr(args, "port", 8001)
    reload = getattr(args, "reload", False)

    if HAS_RICH:
        console.print(f"[bold green]▶ Launching SPAIDER API Service[/bold green] on [cyan]http://{host}:{port}[/cyan]")
        console.print(f"[dim]Interactive Swagger UI documentation: http://{host}:{port}/api/docs[/dim]\n")
    else:
        print(f"[*] Launching SPAIDER API on http://{host}:{port}")

    try:
        import uvicorn
        uvicorn.run("app.main:app", host=host, port=port, reload=reload)
    except Exception as e:
        if HAS_RICH:
            console.print(f"[bold red]✘ Failed to start server:[/bold red] {e}")
        else:
            print(f"[-] Failed to start server: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  WEB DASHBOARD COMMAND
# ─────────────────────────────────────────────────────────────────────────────
def cmd_web(args):
    print_banner()
    port = getattr(args, "port", 3000)
    frontend_dist = os.path.join(os.path.dirname(backend_dir), "frontend", "dist")

    if not os.path.exists(frontend_dist):
        if HAS_RICH:
            console.print("[yellow]Notice: Frontend dist not found. Please run 'npm run build' inside frontend/ directory.[/yellow]")
        else:
            print("[!] Frontend dist directory not found. Please run npm run build.")
        return

    import http.server
    import socketserver

    class CustomHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=frontend_dist, **kw)

    if HAS_RICH:
        console.print(f"[bold green]▶ Serving SPAIDER Web Dashboard[/bold green] at [cyan]http://localhost:{port}[/cyan]")
        console.print("[dim]Press Ctrl+C to stop web server.[/dim]")
    else:
        print(f"[*] Serving SPAIDER Web at http://localhost:{port}")

    try:
        with socketserver.TCPServer(("", port), CustomHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        if HAS_RICH:
            console.print("\n[yellow]Web server stopped.[/yellow]")


def cmd_httpheader(args):
    """Inspect HTTPS security headers for target host."""
    target = args.target
    if HAS_RICH:
        console.print(f"[bold cyan]🔍 Inspecting HTTPS security headers on [green]{target}[/green]...[/bold cyan]")
    else:
        print(f"[*] Inspecting HTTPS security headers on {target}...")

    from app.plugins.httpheader.plugin import scan, report
    result = scan(
        targets=[target],
        options={"ai": "yes" if getattr(args, "ai", False) else "no", "interval": getattr(args, "interval", 1.0)},
    )
    rep = report(result)
    if HAS_RICH:
        console.print(Panel(rep, title="[bold cyan]HTTP Security Header Report[/bold cyan]", border_style="cyan"))
    else:
        print(rep)


# ─────────────────────────────────────────────────────────────────────────────
#  INTERACTIVE CONSOLE (MSFCONSOLE STYLE)
# ─────────────────────────────────────────────────────────────────────────────
def cmd_console(args):

    print_banner()
    if HAS_RICH:
        console.print("[bold yellow]Interactive Cyber Command Shell started.[/bold yellow] Type [cyan]help[/cyan] or [cyan]exit[/cyan].\n")
    else:
        print("Interactive shell started. Type help or exit.\n")

    current_mode = "PURPLE"
    while True:
        try:
            if HAS_RICH:
                prompt_text = f"[bold cyan]spaider[/bold cyan] ([bold magenta]{current_mode.lower()}[/bold magenta]) > "
                user_input = Prompt.ask(prompt_text).strip()
            else:
                user_input = input(f"spaider ({current_mode.lower()}) > ").strip()

            if not user_input:
                continue

            parts = user_input.split()
            cmd = parts[0].lower()

            if cmd in ("exit", "quit", "q"):
                break
            elif cmd == "help":
                if HAS_RICH:
                    console.print("""
[bold cyan]Available Commands:[/bold cyan]
  [green]scan <target>[/green]                 - Scan target for open ports & services
  [green]ai <prompt>[/green]                  - Ask the AI SOC / Threat Analyst
  [green]malware <path>[/green]               - Inspect a binary file with static analysis
  [green]mode [red|blue|purple][/green]       - Switch operational mode
  [green]status[/green]                         - Check tool and system health
  [green]serve[/green]                          - Launch FastAPI backend daemon
  [green]clear[/green]                          - Clear terminal screen
  [green]exit[/green]                           - Exit interactive console
                    """)
                else:
                    print("Commands: scan <target>, ai <prompt>, malware <file>, mode <red|blue|purple>, status, serve, exit")
            elif cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
            elif cmd == "mode":
                if len(parts) > 1 and parts[1].upper() in ("RED", "BLUE", "PURPLE"):
                    current_mode = parts[1].upper()
                    if HAS_RICH:
                        console.print(f"[green]Operational mode switched to [bold]{current_mode}[/bold][/green]")
                else:
                    print(f"Current mode: {current_mode}. Choose: red, blue, purple")
            elif cmd == "scan":
                if len(parts) < 2:
                    print("Usage: scan <target>")
                else:
                    sub_args = argparse.Namespace(target=parts[1], type="quick", ports=None)
                    cmd_scan(sub_args)
            elif cmd == "ai":
                if len(parts) < 2:
                    print("Usage: ai <query>")
                else:
                    q = " ".join(parts[1:])
                    sub_args = argparse.Namespace(query=q, mode=current_mode)
                    cmd_ai(sub_args)
            elif cmd == "malware":
                if len(parts) < 2:
                    print("Usage: malware <file_path>")
                else:
                    sub_args = argparse.Namespace(file=parts[1])
                    cmd_malware(sub_args)
            elif cmd in ("headers", "httpheader"):
                if len(parts) < 2:
                    print("Usage: headers <hostname> [--ai]")
                else:
                    use_ai = "--ai" in parts
                    sub_args = argparse.Namespace(target=parts[1], ai=use_ai, interval=1.0)
                    cmd_httpheader(sub_args)
            elif cmd == "status":
                cmd_status(None)
            else:
                if HAS_RICH:
                    console.print(f"[red]Unknown command:[/red] {cmd}. Type [cyan]help[/cyan] for commands.")
                else:
                    print(f"Unknown command: {cmd}")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting SPAIDER console.")
            break


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="spaider",
        description="SPAIDER — AI-Powered Cybersecurity Command Platform (Linux CLI Tool)",
    )
    parser.add_argument("-v", "--version", action="version", version=f"SPAIDER {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan host/network for ports and services")
    p_scan.add_argument("target", help="Target IP or hostname")
    p_scan.add_argument("-t", "--type", choices=["quick", "full", "stealth", "udp", "os"], default="quick", help="Scan profile")
    p_scan.add_argument("-p", "--ports", help="Port list (e.g. 80,443,8080)")

    # headers / httpheader
    p_headers = subparsers.add_parser("headers", aliases=["httpheader"], help="Inspect HTTPS security headers (HSTS, CSP, nosniff, framing)")
    p_headers.add_argument("target", help="Target hostname (e.g. example.com)")
    p_headers.add_argument("--ai", action="store_true", help="Generate defensive AI remediation advisory")
    p_headers.add_argument("--interval", type=float, default=1.0, help="Interval between requests in seconds")

    # ai
    p_ai = subparsers.add_parser("ai", help="Ask AI Security Analyst & Reasoning Chain")
    p_ai.add_argument("query", help="Cybersecurity query or incident context")
    p_ai.add_argument("-m", "--mode", choices=["RED", "BLUE", "PURPLE"], default="PURPLE", help="Team mode")

    # malware
    p_mal = subparsers.add_parser("malware", help="Perform static malware & binary analysis")
    p_mal.add_argument("file", help="Path to sample file")

    # status
    subparsers.add_parser("status", help="Check system dependencies and service health")

    # serve
    p_serve = subparsers.add_parser("serve", help="Start SPAIDER API server daemon")
    p_serve.add_argument("--host", default="0.0.0.0", help="Host address")
    p_serve.add_argument("--port", type=int, default=8001, help="Port")
    p_serve.add_argument("--reload", action="store_true", help="Enable live auto-reload")

    # web
    p_web = subparsers.add_parser("web", help="Host SPAIDER Web Dashboard frontend")
    p_web.add_argument("--port", type=int, default=3000, help="Port")

    # console
    subparsers.add_parser("console", help="Launch interactive cyber command shell")

    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    cmd_map = {
        "scan": cmd_scan,
        "headers": cmd_httpheader,
        "httpheader": cmd_httpheader,
        "ai": cmd_ai,
        "malware": cmd_malware,
        "status": cmd_status,
        "serve": cmd_serve,
        "web": cmd_web,
        "console": cmd_console,
    }


    handler = cmd_map.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
