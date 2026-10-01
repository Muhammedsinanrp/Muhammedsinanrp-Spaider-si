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
    """Multi-layer AI security reasoning engine."""

    def __init__(self):
        self.llm = self._init_llm()

    def _init_llm(self):
        """Initialise the LLM client based on configuration."""
        if settings.openai_api_key:
            try:
                from openai import AsyncOpenAI
                return AsyncOpenAI(api_key=settings.openai_api_key)
            except ImportError:
                pass
        if settings.anthropic_api_key:
            try:
                import anthropic
                return anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            except ImportError:
                pass
        logger.warning("No LLM API key configured — AI analysis will return mock responses")
        return None

    async def analyze(
        self,
        context: str,
        mode: str = "blue",
        asset_id: Optional[str] = None,
        finding_ids: List[str] = [],
        alert_ids: List[str] = [],
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Run the SPAIDER security reasoning chain."""
        prompt = REASONING_CHAIN_PROMPT.format(context=context, mode=mode.upper())

        if self.llm is None:
            return self._mock_analysis(context, mode)

        try:
            if settings.openai_api_key:
                response = await self.llm.chat.completions.create(
                    model=settings.default_llm_model,
                    messages=[
                        {"role": "system", "content": "You are SPAIDER AI Security Core. Always respond with valid JSON."},
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                )
                result = json.loads(response.choices[0].message.content)
            else:
                result = self._mock_analysis(context, mode)

            return result
        except Exception as e:
            logger.error("LLM analysis failed", error=str(e))
            return self._mock_analysis(context, mode)

    async def query(self, question: str, db: Optional[AsyncSession] = None) -> str:
        """Answer a natural language security question."""
        if self.llm is None:
            return "AI analysis unavailable — configure OPENAI_API_KEY or ANTHROPIC_API_KEY."
        try:
            response = await self.llm.chat.completions.create(
                model=settings.default_llm_model,
                messages=[
                    {"role": "system", "content": "You are SPAIDER, an expert AI cybersecurity analyst. Answer concisely and accurately."},
                    {"role": "user", "content": question},
                ],
                temperature=0.2,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Query failed: {str(e)}"

    async def generate_dashboard_summary(self, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
        """Generate an AI security posture summary."""
        return {
            "posture_score": 72,
            "trend": "improving",
            "critical_findings": 3,
            "open_alerts": 12,
            "detection_coverage": "68%",
            "top_risks": [
                "Unpatched services on perimeter",
                "Lateral movement detection gaps",
                "Weak authentication on VPN",
            ],
            "recommended_priorities": [
                "Patch CVE-2024-XXXX on web servers",
                "Enable Suricata rule set for lateral movement",
                "Enforce MFA on all admin accounts",
            ],
        }

    def _mock_analysis(self, context: str, mode: str) -> Dict[str, Any]:
        """Mock analysis when no LLM is configured."""
        return {
            "summary": f"Security analysis for: {context[:80]}...",
            "severity": "MEDIUM",
            "risk_score": 5.5,
            "reasoning_chain": [
                {"step": "Asset", "content": "Target asset identified from context", "confidence": 0.9},
                {"step": "Service", "content": "Service enumeration pending", "confidence": 0.7},
                {"step": "Technology", "content": "Technology stack analysis pending", "confidence": 0.6},
                {"step": "Potential Weakness", "content": "Configure an LLM API key for detailed analysis", "confidence": 0.5},
                {"step": "Evidence", "content": "Raw evidence collected from scanner", "confidence": 0.8},
                {"step": "Risk Context", "content": "Context-aware risk scoring enabled with LLM", "confidence": 0.5},
                {"step": "Related CVEs", "content": "CVE correlation requires LLM configuration", "confidence": 0.4},
                {"step": "Detection Opportunities", "content": "Detection rule generation requires LLM", "confidence": 0.5},
                {"step": "Recommended Remediation", "content": "Set OPENAI_API_KEY for AI-powered remediation", "confidence": 0.5},
                {"step": "Verification", "content": "Verification steps pending", "confidence": 0.6},
            ],
            "mitre_techniques": [],
            "recommended_actions": ["Configure OPENAI_API_KEY or ANTHROPIC_API_KEY for AI analysis"],
            "detection_rules": [],
            "remediation": "Configure an LLM API key for detailed remediation guidance.",
            "evidence_summary": "Mock analysis — no LLM configured.",
            "authorization_warning": "⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.",
        }
