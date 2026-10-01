"""AI SOC Analyst endpoint — security reasoning chain, CVE lookup, ATT&CK mapping."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import structlog

from app.core.database import get_db
from app.agents.ai_core import SPAIDERAICore

router = APIRouter()
logger = structlog.get_logger(__name__)
ai_core = SPAIDERAICore()


class AnalysisRequest(BaseModel):
    context: str                   # Description of finding / alert / event
    mode: str = "blue"             # red | blue | purple
    asset_id: Optional[str] = None
    finding_ids: List[str] = []
    alert_ids: List[str] = []


class ReasoningStep(BaseModel):
    step: str
    content: str
    confidence: float = 1.0


class AIAnalysisResponse(BaseModel):
    summary: str
    severity: str
    reasoning_chain: List[ReasoningStep]
    mitre_techniques: List[dict]
    recommended_actions: List[str]
    detection_rules: List[str]
    remediation: str
    evidence_summary: str
    risk_score: float


@router.post("/analyze", response_model=AIAnalysisResponse)
async def analyze(payload: AnalysisRequest, db: AsyncSession = Depends(get_db)):
    """Run the SPAIDER AI security reasoning chain on a finding or event."""
    try:
        result = await ai_core.analyze(
            context=payload.context,
            mode=payload.mode,
            asset_id=payload.asset_id,
            finding_ids=payload.finding_ids,
            alert_ids=payload.alert_ids,
            db=db,
        )
        return result
    except Exception as e:
        logger.error("AI analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")


@router.post("/query")
async def natural_language_query(query: str, db: AsyncSession = Depends(get_db)):
    """Answer security questions in natural language."""
    result = await ai_core.query(question=query, db=db)
    return {"answer": result}


@router.get("/dashboard-summary")
async def dashboard_summary(db: AsyncSession = Depends(get_db)):
    """Get AI-generated security posture summary for the dashboard."""
    summary = await ai_core.generate_dashboard_summary(db=db)
    return summary
