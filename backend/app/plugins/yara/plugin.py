"""
SPAIDER YARA Plugin — Static malware analysis and IOC detection.
"""

import os
import math
import subprocess
from typing import List, Dict, Any, Optional
import structlog

logger = structlog.get_logger(__name__)

PLUGIN_META = {
    "name": "yara",
    "version": "4.5.1",
    "category": "Malware Analysis",
    "description": "YARA rule-based malware detection, string extraction, and IOC identification.",
}

DEFAULT_RULES_DIR = "/app/yara_rules"


def discover(path: str) -> dict:
    """List files available for analysis in the given path."""
    files = []
    if os.path.isdir(path):
        for f in os.listdir(path):
            full = os.path.join(path, f)
            if os.path.isfile(full):
                files.append({"path": full, "size": os.path.getsize(full)})
    return {"files": files, "count": len(files)}


def scan(file_path: str, rules_dir: str = DEFAULT_RULES_DIR) -> dict:
    """Run YARA rules against a file and return matches."""
    return {"matches": _run_yara(file_path, rules_dir), "file": file_path}


def _run_yara(file_path: str, rules_dir: str) -> list:
    try:
        import yara
        if not os.path.exists(rules_dir):
            return []
        rule_files = {
            f: os.path.join(rules_dir, f)
            for f in os.listdir(rules_dir)
            if f.endswith(".yar") or f.endswith(".yara")
        }
        if not rule_files:
            return []
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(file_path)
        return [{"rule": m.rule, "tags": m.tags, "meta": m.meta, "strings": [
            {"offset": s[0], "identifier": s[1], "data": s[2].hex()}
            for s in m.strings
        ]} for m in matches]
    except ImportError:
        logger.warning("yara-python not installed")
        return []
    except Exception as e:
        logger.error("YARA scan failed", error=str(e))
        return []


def analyze(file_path: str) -> dict:
    """Full static analysis: file type, entropy, strings, PE info, YARA."""
    return {
        "file_path": file_path,
        "file_type": _file_type(file_path),
        "entropy": _entropy(file_path),
        "strings": _extract_strings(file_path),
        "yara_matches": _run_yara(file_path, DEFAULT_RULES_DIR),
        "pe_info": _pe_info(file_path),
    }


def _file_type(path: str) -> str:
    try:
        result = subprocess.run(["file", path], capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return "unknown"


def _entropy(path: str) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        for c in counts:
            if c:
                p = c / len(data)
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0


def _extract_strings(path: str, min_len: int = 6) -> list:
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_len), path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.splitlines()[:200]
    except Exception:
        return []


def _pe_info(path: str) -> dict:
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        return {
            "machine": hex(pe.FILE_HEADER.Machine),
            "num_sections": pe.FILE_HEADER.NumberOfSections,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "imports": [
                e.dll.decode() if e.dll else ""
                for e in (pe.DIRECTORY_ENTRY_IMPORT or [])
            ],
        }
    except Exception:
        return {}


def collect(results: dict) -> list:
    """Extract IOCs from analysis results."""
    import re
    iocs = []
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_re = re.compile(r"https?://[^\s'\"]+")
    domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|ru|cn)\b")

    for s in results.get("strings", []):
        for ip in ip_re.findall(s):
            iocs.append({"type": "ip", "value": ip})
        for url in url_re.findall(s):
            iocs.append({"type": "url", "value": url})
        for domain in domain_re.findall(s):
            iocs.append({"type": "domain", "value": domain})

    return iocs


def normalize(results: dict) -> dict:
    """Normalize analysis to SPAIDER schema."""
    yara_matches = results.get("yara_matches", [])
    entropy = results.get("entropy", 0.0)
    strings = results.get("strings", [])
    suspicious_keywords = ["cmd.exe", "powershell", "CreateRemoteThread", "VirtualAlloc", "WinExec"]
    is_malicious = (
        len(yara_matches) > 0 or
        entropy > 7.5 or
        any(kw in " ".join(strings) for kw in suspicious_keywords)
    )
    return {
        "is_malicious": is_malicious,
        "confidence_score": 0.85 if is_malicious else 0.1,
        "yara_matches": yara_matches,
        "entropy": entropy,
        "iocs": collect(results),
        "static_analysis": results,
    }


def report(results: dict) -> str:
    """Generate plain-text YARA analysis report."""
    lines = ["YARA Static Analysis Report", "=" * 40]
    lines.append(f"File: {results.get('file_path', 'unknown')}")
    lines.append(f"Type: {results.get('file_type', 'unknown')}")
    lines.append(f"Entropy: {results.get('entropy', 0.0)}")
    matches = results.get("yara_matches", [])
    if matches:
        lines.append(f"\nYARA Matches ({len(matches)}):")
        for m in matches:
            lines.append(f"  Rule: {m['rule']} — Tags: {', '.join(m.get('tags', []))}")
    else:
        lines.append("\nNo YARA matches.")
    return "\n".join(lines)
