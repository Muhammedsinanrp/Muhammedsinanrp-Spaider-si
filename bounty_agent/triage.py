"""AI triage and report drafting via the AshnaAI OpenAI-compatible API.

Config (environment variables, never committed):
- ASHNA_API_KEY  — from https://app.ashna.ai/account?tab=api
- ASHNA_MODEL   — optional; default "ashna-x1" ("glm-5.3-flash" for cheap bulk triage)

The AI never decides scope, never chooses targets, and never submits anything.
It only classifies eligibility and drafts text for human review.
"""

from __future__ import annotations

import json
import os
from typing import Any

from openai import OpenAI

BASE_URL = "https://api.ashna.ai/v1/api"
DEFAULT_MODEL = "ashna-x1"

TRIAGE_SYSTEM_PROMPT = (
    "You are a bug bounty triage assistant. You receive raw observations from authorized, "
    "scope-limited recon of a single host. Classify each finding as 'likely_eligible', "
    "'likely_ineligible', or 'needs_manual_review' for a typical bug bounty program, and give a "
    "one-sentence reason. Never claim a vulnerability is confirmed. Never suggest exploitation. "
    "Output strict JSON: {\"triage\": [{\"check\": ..., \"classification\": ..., \"reason\": ...}]}"
)

REPORT_SYSTEM_PROMPT = (
    "You draft bug bounty report sections from human-approved findings. Keep the tone factual, "
    "include steps to reproduce that use only passive observation or single low-impact requests, "
    "and clearly label impact as hypothetical until the program confirms it. Never invent "
    "evidence, request payloads, or targets beyond those provided."
)


def _client() -> OpenAI | None:
    api_key = os.environ.get("ASHNA_API_KEY", "").strip()
    if not api_key:
        return None
    return OpenAI(base_url=BASE_URL, api_key=api_key)


def triage_findings(host: str, audit_result: dict[str, Any]) -> dict[str, Any]:
    """Ask AshnaAI to classify findings. Returns an error notice if no API key is set."""
    client = _client()
    if client is None:
        return {
            "host": host,
            "triage": "skipped — set ASHNA_API_KEY (https://app.ashna.ai/account?tab=api)",
        }
    model = os.environ.get("ASHNA_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    user_msg = json.dumps({"host": host, "findings": audit_result.get("findings", [])}, ensure_ascii=False)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.2,
        )
        content = response.choices[0].message.content or ""
        start, end = content.find("{"), content.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("model response contained no JSON object")
        parsed = json.loads(content[start : end + 1])
        return {"host": host, "model": model, "triage": parsed.get("triage", [])}
    except Exception as exc:
        return {"host": host, "triage": f"failed — {type(exc).__name__}: {exc}", "raw": True}


def draft_report_section(host: str, audit_result: dict[str, Any], triage: dict[str, Any]) -> dict[str, Any]:
    """Ask AshnaAI to draft a report section for human review (never auto-submitted)."""
    client = _client()
    if client is None:
        return {"host": host, "draft": "skipped — set ASHNA_API_KEY (https://app.ashna.ai/account?tab=api)"}
    model = os.environ.get("ASHNA_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    user_msg = json.dumps({"host": host, "audit": audit_result, "triage": triage}, ensure_ascii=False)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": "Draft a bug bounty report section for this host. Output Markdown only."},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
        )
        return {"host": host, "model": model, "draft": response.choices[0].message.content or ""}
    except Exception as exc:
        return {"host": host, "draft": f"failed — {type(exc).__name__}: {exc}"}
