"""
SPAIDER AI Core — Security reasoning chain engine.

Architecture:
  Input Context
      ↓
  Asset Enrichment
      ↓
  Service/Technology Identification
      ↓
  Weakness Hypothesis
      ↓
  Evidence Correlation
      ↓
  CVE/CWE Lookup
      ↓
  MITRE ATT&CK Mapping
      ↓
  Risk Scoring
      ↓
  Detection Opportunities
      ↓
  Remediation Guidance
"""

import json
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.config import settings

logger = structlog.get_logger(__name__)

REASONING_CHAIN_PROMPT = """You are SPAIDER's AI Security Core — an expert cybersecurity analyst.

Your task is to perform a structured security reasoning chain for the following context.

CONTEXT:
{context}

MODE: {mode} (RED=offensive, BLUE=defensive, PURPLE=both)

Produce a JSON response with this exact structure:
{{
  "summary": "<one-line executive summary>",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "risk_score": <0.0-10.0>,
  "reasoning_chain": [
    {{"step": "Asset", "content": "...", "confidence": 0.9}},
    {{"step": "Service", "content": "...", "confidence": 0.9}},
    {{"step": "Technology", "content": "...", "confidence": 0.8}},
    {{"step": "Potential Weakness", "content": "...", "confidence": 0.7}},
    {{"step": "Evidence", "content": "...", "confidence": 0.9}},
    {{"step": "Risk Context", "content": "...", "confidence": 0.85}},
    {{"step": "Related CVEs", "content": "...", "confidence": 0.6}},
    {{"step": "Detection Opportunities", "content": "...", "confidence": 0.8}},
    {{"step": "Recommended Remediation", "content": "...", "confidence": 0.9}},
    {{"step": "Verification", "content": "...", "confidence": 0.85}}
  ],
  "mitre_techniques": [
    {{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}}
  ],
  "recommended_actions": [
    "Patch the service to version X",
    "Implement network segmentation",
    "Add detection rule for this pattern"
  ],
  "detection_rules": [
    "alert tcp any any -> $HOME_NET 445 (msg:\\"SMB scan\\"; sid:1000001;)"
  ],
  "remediation": "<detailed remediation guidance>",
  "evidence_summary": "<summary of supporting evidence>"
}}

Always provide evidence-based analysis. Never fabricate CVE numbers without context.
Map findings to MITRE ATT&CK whenever possible.
"""


class SPAIDERAICore:
    """AI analyst that only reports model-generated results or explicit unavailability."""

    def __init__(self):
        configured = (settings.default_llm_provider or "openai").lower()
        if configured == "anthropic" and settings.anthropic_api_key:
            self.provider = "anthropic"
        elif configured == "openai" and settings.openai_api_key:
            self.provider = "openai"
        elif settings.openai_api_key:
            self.provider = "openai"
        elif settings.anthropic_api_key:
            self.provider = "anthropic"
        else:
            self.provider = None
        self.llm = self._init_llm()

    def _init_llm(self):
        """Initialize only a configured provider; never replace missing AI with mock results."""
        if self.provider == "openai":
            try:
                from openai import AsyncOpenAI
                return AsyncOpenAI(api_key=settings.openai_api_key)
            except ImportError as exc:
                logger.error("OpenAI SDK is not installed", error=str(exc))
                return None
        if self.provider == "anthropic":
            try:
                import anthropic
                return anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            except ImportError as exc:
                logger.error("Anthropic SDK is not installed", error=str(exc))
                return None
        logger.info("No AI provider configured; AI analysis is unavailable")
        return None

    def _require_llm(self):
        if self.llm is None or self.provider is None:
            raise RuntimeError(
                "AI analysis is unavailable. Configure OPENAI_API_KEY or ANTHROPIC_API_KEY "
                "and install the matching SDK in the backend environment."
            )

    @staticmethod
    def _parse_json_response(text: str) -> Dict[str, Any]:
        """Parse model output without silently manufacturing replacement content."""
        raw = (text or "").strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            first, last = raw.find("{"), raw.rfind("}")
            if first < 0 or last <= first:
                raise RuntimeError("Configured AI provider returned a non-JSON response.")
            try:
                parsed = json.loads(raw[first:last + 1])
            except json.JSONDecodeError as exc:
                raise RuntimeError("Configured AI provider returned invalid JSON.") from exc
        if not isinstance(parsed, dict):
            raise RuntimeError("Configured AI provider returned an unexpected response shape.")
        required = {
            "summary", "severity", "reasoning_chain", "mitre_techniques",
            "recommended_actions", "detection_rules", "remediation",
            "evidence_summary", "risk_score",
        }
        missing = sorted(required - parsed.keys())
        if missing:
            raise RuntimeError("AI response omitted required fields: " + ", ".join(missing))
        return parsed

    async def analyze(
        self,
        context: str,
        mode: str = "blue",
        asset_id: Optional[str] = None,
        finding_ids: List[str] = [],
        alert_ids: List[str] = [],
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Analyze the supplied context with the configured model."""
        self._require_llm()
        prompt = REASONING_CHAIN_PROMPT.format(context=context, mode=mode.upper())
        try:
            if self.provider == "openai":
                response = await self.llm.chat.completions.create(
                    model=settings.default_llm_model,
                    messages=[
                        {"role": "system", "content": "You are SPAIDER AI Security Core. Return only valid JSON. Distinguish observed evidence from hypotheses; never claim a test was passed or exploited unless its evidence says so."},
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                )
                content = response.choices[0].message.content or ""
            else:
                response = await self.llm.messages.create(
                    model=settings.anthropic_model,
                    max_tokens=4096,
                    system="You are SPAIDER AI Security Core. Return only valid JSON. Distinguish observed evidence from hypotheses; never claim a test was passed or exploited unless its evidence says so.",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                )
                content = "".join(
                    block.text for block in (response.content or [])
                    if getattr(block, "type", "") == "text"
                )
            result = self._parse_json_response(content)
            result.setdefault("mitre_techniques", [])
            result.setdefault("recommended_actions", [])
            result.setdefault("detection_rules", [])
            result.setdefault("reasoning_chain", [])
            result.setdefault("evidence_summary", "")
            return result
        except Exception as exc:
            logger.exception("Configured AI analysis failed", provider=self.provider, error=str(exc))
            raise RuntimeError(f"AI analysis failed using the configured {self.provider} provider: {exc}") from exc

    async def query(self, question: str, db: Optional[AsyncSession] = None) -> str:
        """Answer a natural-language security question using the configured model."""
        self._require_llm()
        try:
            system = (
                "You are SPAIDER, a cybersecurity analyst. Be precise, separate verified observations "
                "from hypotheses, and do not invent scan results or CVEs."
            )
            if self.provider == "openai":
                response = await self.llm.chat.completions.create(
                    model=settings.default_llm_model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": question},
                    ],
                    temperature=0.2,
                )
                return response.choices[0].message.content or ""
            response = await self.llm.messages.create(
                model=settings.anthropic_model,
                max_tokens=2048,
                system=system,
                messages=[{"role": "user", "content": question}],
                temperature=0.2,
            )
            return "".join(
                block.text for block in (response.content or [])
                if getattr(block, "type", "") == "text"
            )
        except Exception as exc:
            logger.exception("AI query failed", provider=self.provider, error=str(exc))
            raise RuntimeError(f"AI query failed using the configured {self.provider} provider: {exc}") from exc

    async def generate_dashboard_summary(self, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Return database-derived security posture, not illustrative hard-coded numbers."""
        if db is None:
            return {"status": "unavailable", "summary": "A database session is required to calculate posture metrics."}

        from sqlalchemy import func, select
        from app.models.models import Alert, AlertStatus, Asset, Finding, ScanJob, ScanStatus, Severity

        async def count(query):
            return int((await db.execute(query)).scalar() or 0)

        asset_count = await count(select(func.count(Asset.id)))
        scan_count = await count(select(func.count(ScanJob.id)))
        completed_scans = await count(select(func.count(ScanJob.id)).where(ScanJob.status == ScanStatus.COMPLETED))
        failed_scans = await count(select(func.count(ScanJob.id)).where(ScanJob.status == ScanStatus.FAILED))
        active_scans = await count(select(func.count(ScanJob.id)).where(ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING])))
        open_alerts = await count(select(func.count(Alert.id)).where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING])))

        by_severity = {}
        for severity in Severity:
            by_severity[severity.value.lower()] = await count(
                select(func.count(Finding.id)).where(Finding.severity == severity)
            )
        total_findings = sum(by_severity.values())
        priorities = [
            {"severity": severity, "count": by_severity[severity.lower()]}
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if by_severity[severity.lower()]
        ]
        if total_findings == 0 and open_alerts == 0:
            summary = "No findings or open alerts are currently recorded in the database."
        else:
            summary = (
                f"Database inventory contains {asset_count} asset(s), {total_findings} finding(s), "
                f"and {open_alerts} open or investigating alert(s). Metrics reflect stored records; "
                "unscanned systems and unconnected sensors are not assessed."
            )
        return {
            "status": "database_derived",
            "summary": summary,
            "assets": asset_count,
            "scans": {
                "total": scan_count,
                "completed": completed_scans,
                "failed": failed_scans,
                "active": active_scans,
            },
            "findings": by_severity,
            "total_findings": total_findings,
            "open_alerts": open_alerts,
            "top_risks": priorities,
            "recommended_priorities": [
                "Review and validate recorded critical/high findings." if any(p["severity"] in ("CRITICAL", "HIGH") for p in priorities)
                else "Run an authorized baseline scan against a saved in-scope target." if total_findings == 0
                else "Review findings and apply scanner-provided remediation."
            ],
        }

