"""
SPAIDER Tools Direct-Run Endpoint
Executes plugin logic synchronously and returns structured results immediately.
No Celery / queue required — ideal for interactive tool use from the UI.
"""

import time
from typing import List, Optional, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter()


class ToolRunRequest(BaseModel):
    plugin: str
    targets: List[str] = []
    options: dict = {}


class ToolRunResponse(BaseModel):
    plugin: str
    success: bool
    elapsed_ms: float
    result: Any
    report: Optional[str] = None
    analysis: Optional[Any] = None
    normalized: Optional[Any] = None
    mock: bool = False


@router.post("/run", response_model=ToolRunResponse)
async def run_tool(payload: ToolRunRequest):
    """Execute a plugin directly and return results synchronously."""
    plugin = payload.plugin.lower().strip()
    targets = payload.targets or []
    options = payload.options or {}

    t0 = time.time()
    result = {}
    report_str = None
    analysis = None
    normalized = None

    try:
        if plugin == "nmap":
            from app.plugins.nmap.plugin import scan, analyze, normalize, report
            result = scan(targets=targets or ["192.168.1.0/24"],
                          scan_type=options.get("scan_type", "quick"),
                          ports=options.get("ports"))
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)

        elif plugin == "nuclei":
            from app.plugins.nuclei.plugin import scan_web
            result = scan_web(targets=targets or ["https://example.com"],
                              categories=[options.get("templates", "cves")],
                              results_dir="./scan_results")

        elif plugin == "zeek":
            from app.plugins.zeek.plugin import scan, analyze, normalize, report
            result = scan(pcap_file=options.get("pcap", ""),
                          interface=options.get("interface", ""),
                          scripts=[options.get("scripts", "default")])
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)

        elif plugin == "suricata":
            from app.plugins.suricata.plugin import scan, analyze, normalize, report
            result = scan(pcap_file=options.get("pcap", "/tmp/capture.pcap"),
                          rules=options.get("ruleset"))
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)

        elif plugin == "yara":
            from app.plugins.yara.plugin import scan
            result = scan(file_path=options.get("file", targets[0] if targets else "/tmp/sample"),
                          rules_dir=options.get("rules_dir", "/app/yara_rules"),
                          recursive=options.get("recursive", "no") == "yes")

        elif plugin == "shodan":
            from app.plugins.shodan.plugin import lookup
            result = lookup(query=options.get("query") or (targets[0] if targets else "8.8.8.8"),
                            query_type=options.get("query_type", "host"),
                            api_key=options.get("api_key"))

        elif plugin == "virustotal":
            from app.plugins.virustotal.plugin import lookup
            result = lookup(target=options.get("target") or (targets[0] if targets else "https://google.com"),
                            scan_type=options.get("scan_type", "url"),
                            api_key=options.get("api_key"))

        elif plugin == "truecaller":
            from app.plugins.truecaller.plugin import lookup
            result = lookup(phone=options.get("phone") or (targets[0] if targets else "9876543210"),
                            country_code=options.get("country_code", "IN"),
                            auth_token=options.get("auth_token"))

        elif plugin == "wifite":
            from app.plugins.wifite.plugin import scan
            result = scan(interface=options.get("interface", "wlan0"),
                          attack=options.get("attack", "all"),
                          bssid=options.get("bssid"),
                          channel=options.get("channel"))

        elif plugin == "zingela":
            from app.plugins.zingela.plugin import scan, analyze, normalize, report
            result = scan(targets=targets or ["192.168.1.0/24"],
                          ports=options.get("ports", "1-1024"),
                          rate=int(options.get("rate", 10000)),
                          scan_mode=options.get("scan_mode", "syn"),
                          interface=options.get("interface"))
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)

        elif plugin == "lisdex":
            from app.plugins.lisdex.plugin import audit, analyze, normalize, report
            modules_raw = options.get("modules", "")
            modules = [m.strip() for m in modules_raw.split(",") if m.strip()] or None
            result = audit(target_host=targets[0] if targets else "localhost",
                           audit_level=options.get("audit_level", "deep"),
                           modules=modules)
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)

        elif plugin == "cre":
            from app.plugins.cre.plugin import query, analyze, normalize, report
            keyword = options.get("query") or (targets[0] if targets else "Authentication")
            framework = options.get("framework", "All Frameworks")
            result = query(keyword, framework_filter=framework if framework != "All Frameworks" else None)
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)

        elif plugin == "fwrule":
            from app.plugins.fwrule.plugin import generate_rules, analyze, normalize, report
            result = generate_rules(engine=options.get("engine", "iptables"),
                                    action=options.get("action", "block_ip"),
                                    target_ip=targets[0] if targets else "192.168.1.100",
                                    port=options.get("port", "any"),
                                    protocol=options.get("protocol", "tcp"))
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)

        elif plugin == "httpheader":
            from app.plugins.httpheader.plugin import scan, analyze, normalize, report
            effective_targets = targets if targets else ([options.get("target")] if options.get("target") else ["example.com"])
            result = scan(
                targets=effective_targets,
                options=options,
            )
            analysis = analyze(result)
            normalized = normalize(result)
            report_str = report(result)


        elif plugin == "masscan":
            result = _run_masscan(
                target=targets[0] if targets else "192.168.1.0/24",
                ports=options.get("ports", "0-65535"),
                rate=options.get("rate", "1000"))
            report_str = _masscan_report(result)

        elif plugin == "tshark":
            result = _run_tshark(
                file=options.get("file") or (targets[0] if targets else "/tmp/capture.pcap"),
                display_filter=options.get("filter", ""),
                protocol=options.get("protocol", "all"))
            report_str = _tshark_report(result)

        elif plugin in ("burp", "caido", "maltego", "godseye"):
            result = _external_tool_guidance(plugin, targets, options)
            report_str = "\n".join(result.get("setup_steps", []))

        elif plugin == "wazuh":
            result = {
                "type": "configuration_required",
                "tool": "Wazuh SIEM/XDR",
                "status": "Not configured",
                "setup_steps": [
                    "1. Deploy: curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh && sudo bash wazuh-install.sh -a",
                    "2. Set WAZUH_URL and WAZUH_API_USER env vars in backend/.env",
                    "3. Install agents on endpoints",
                    "4. Configure manager_url and restart SPAIDER backend",
                ],
            }
            report_str = "\n".join(result["setup_steps"])

        else:
            raise HTTPException(status_code=400, detail=f"Unknown plugin: '{plugin}'")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Tool execution error", plugin=plugin, error=str(e))
        result = {"error": str(e), "plugin": plugin}

    elapsed = round((time.time() - t0) * 1000, 1)
    mock = bool(result.get("mock") or result.get("type") in ("external_tool", "configuration_required"))

    return ToolRunResponse(
        plugin=plugin,
        success="error" not in result,
        elapsed_ms=elapsed,
        result=result,
        report=report_str,
        analysis=analysis,
        normalized=normalized,
        mock=mock,
    )


# ── External tool guidance ────────────────────────────────────────────────────

def _external_tool_guidance(plugin: str, targets: list, options: dict) -> dict:
    target = options.get("target") or (targets[0] if targets else "example.com")
    if plugin == "burp":
        return {
            "type": "external_tool", "tool": "Burp Suite Professional",
            "setup_steps": [
                "1. Launch Burp Suite Professional",
                "2. Proxy → Options → listener on 127.0.0.1:8080",
                "3. Configure browser proxy to 127.0.0.1:8080",
                f"4. Browse target: {options.get('scope', target)}",
                "5. Scanner → Active Scan on captured requests",
                "6. REST API: GET http://127.0.0.1:1337/v0.1/issue-definitions",
            ],
        }
    if plugin == "caido":
        return {
            "type": "external_tool", "tool": "Caido",
            "setup_steps": [
                "1. caido start  (or docker run caido/caido)",
                "2. Open http://127.0.0.1:8080 in browser",
                "3. Create project and set scope",
                "4. Use Automate tab for fuzzing / scanning",
                "5. Import requests to Replay for manual testing",
            ],
        }
    if plugin == "maltego":
        return {
            "type": "external_tool", "tool": "Maltego",
            "seed_entity": target,
            "entity_type": options.get("entity_type", "domain"),
            "setup_steps": [
                "1. Open Maltego desktop (maltego.com/maltego-community/)",
                "2. New Graph (Ctrl+N)",
                f"3. Drag '{options.get('entity_type','Domain')}' entity onto canvas",
                f"4. Set value: {target}",
                f"5. Right-click → Run Transforms → {options.get('transforms','All Transforms')}",
                "6. Watch intelligence graph expand",
            ],
        }
    if plugin == "godseye":
        layers = options.get("layers", "maritime,cctv,live_news,earthquakes,global_incidents")
        return {
            "type": "external_tool", "tool": "GodsEYE Global Intel Platform",
            "url": f"https://godseye.network/dashboard?layers={layers}",
            "setup_steps": [
                f"Open: https://godseye.network/dashboard?layers={layers}",
                "The GodsEYE platform opens in browser with all selected intelligence layers active.",
                f"Active layers: {layers}",
                f"Region focus: {options.get('region', 'Global')}",
            ],
        }
    return {"type": "external_tool", "tool": plugin}


# ── Masscan runner ────────────────────────────────────────────────────────────

def _run_masscan(target: str, ports: str, rate: str) -> dict:
    import subprocess, shutil, json as _json
    bin_path = shutil.which("masscan")
    if bin_path:
        try:
            cmd = [bin_path, target, "-p", ports, "--rate", str(rate),
                   "--output-format", "json", "--output-file", "-"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                data = _json.loads(res.stdout or "[]")
                return {"engine": "masscan", "target": target, "ports": ports,
                        "rate": rate, "results": data, "count": len(data)}
        except Exception:
            pass
    return {
        "engine": "masscan", "target": target, "ports": ports, "rate": rate, "mock": True,
        "results": [
            {"ip": "192.168.1.1",  "ports": [{"port": 80, "proto": "tcp", "status": "open"}, {"port": 443, "proto": "tcp", "status": "open"}]},
            {"ip": "192.168.1.10", "ports": [{"port": 22, "proto": "tcp", "status": "open"}, {"port": 8080, "proto": "tcp", "status": "open"}]},
            {"ip": "192.168.1.20", "ports": [{"port": 5432, "proto": "tcp", "status": "open"}]},
            {"ip": "192.168.1.50", "ports": [{"port": 3306, "proto": "tcp", "status": "open"}, {"port": 6379, "proto": "tcp", "status": "open"}]},
        ],
        "count": 4,
        "elapsed_seconds": 2.1,
        "packets_sent": int(str(rate)) * 3,
    }


def _masscan_report(result: dict) -> str:
    lines = ["MASSCAN ULTRA-FAST PORT SCAN REPORT", "=" * 45,
             f"Target: {result['target']}  Ports: {result['ports']}  Rate: {result['rate']} pps", ""]
    for host in result.get("results", []):
        lines.append(f"Host: {host['ip']}")
        for p in host.get("ports", []):
            lines.append(f"  {p['port']}/{p['proto']}  [open]")
    return "\n".join(lines)


# ── tshark runner ─────────────────────────────────────────────────────────────

def _run_tshark(file: str, display_filter: str, protocol: str) -> dict:
    import subprocess, shutil, os, json as _json
    bin_path = shutil.which("tshark")
    if bin_path and os.path.exists(file):
        try:
            cmd = [bin_path, "-r", file, "-T", "json"]
            if display_filter:
                cmd += ["-Y", display_filter]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                data = _json.loads(res.stdout or "[]")
                return {"engine": "tshark", "file": file, "packet_count": len(data),
                        "filter": display_filter, "packets": data[:50]}
        except Exception:
            pass
    return {
        "engine": "tshark / Wireshark", "file": file, "mock": True,
        "filter": display_filter or "(none)", "protocol": protocol,
        "packet_count": 3847,
        "statistics": {
            "http_requests": 156, "dns_queries": 89, "tls_handshakes": 203,
            "tcp_streams": 412, "udp_flows": 78, "icmp_packets": 14,
            "total_bytes": 2847392,
        },
        "top_talkers": [
            {"src": "192.168.1.10", "dst": "8.8.8.8", "packets": 89, "bytes": 12043, "proto": "DNS"},
            {"src": "192.168.1.10", "dst": "93.184.216.34", "packets": 156, "bytes": 87234, "proto": "HTTP"},
            {"src": "192.168.1.10", "dst": "142.250.80.14", "packets": 203, "bytes": 193400, "proto": "TLS"},
            {"src": "192.168.1.50", "dst": "185.220.101.1", "packets": 12, "bytes": 4320, "proto": "TCP", "suspicious": True},
        ],
        "interesting_findings": [
            {"type": "SUSPICIOUS", "detail": "Unencrypted HTTP with sensitive keywords (password=) in stream 14"},
            {"type": "SUSPICIOUS", "detail": "TLS to known Tor exit node: 185.220.101.1:443"},
            {"type": "INFO", "detail": "DNS queries to non-standard resolver: 1.1.1.1 (Cloudflare)"},
        ],
    }


def _tshark_report(result: dict) -> str:
    stats = result.get("statistics", {})
    lines = ["TSHARK / WIRESHARK PACKET ANALYSIS", "=" * 45,
             f"File: {result['file']}  Filter: {result['filter']}",
             f"Total Packets: {result['packet_count']}", ""]
    if stats:
        lines.append("Protocol Breakdown:")
        for k, v in stats.items():
            lines.append(f"  {k}: {v}")
    lines.append("\nInteresting Findings:")
    for f in result.get("interesting_findings", []):
        lines.append(f"  [{f['type']}] {f['detail']}")
    return "\n".join(lines)
