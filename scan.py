"""
FastAPI Threat Scanning Endpoints Router
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from schemas.scan import URLScanRequest, QRScanRequest, EmailScanRequest, UPIScanRequest, MultiStageScanRequest, ScanResponse
from database.connection import get_db
from database.models import IncidentLog
from core.risk_engine import MultiSignalRiskEngine
from core.xai_explainer import XAIExplainer
from services.url_analyzer import URLAnalyzer
from services.qr_decoder import QRDecoderService
from services.nlp_detector import NLPScamDetector
from services.impersonation import ImpersonationDetector
from services.financial_scam import FinancialScamDetector
from services.threat_intel import ThreatIntelAggregator

router = APIRouter(tags=["Detection Scans"])

risk_engine = MultiSignalRiskEngine()
url_analyzer = URLAnalyzer()
qr_decoder = QRDecoderService()
nlp_detector = NLPScamDetector()
impersonation_detector = ImpersonationDetector()
financial_detector = FinancialScamDetector()
threat_intel = ThreatIntelAggregator()

@router.post("/scan/url", response_model=ScanResponse)
async def scan_url(payload: URLScanRequest, db: AsyncSession = Depends(get_db)):
    url_signals = await url_analyzer.analyze_url(payload.url)
    intel_signals = await threat_intel.lookup_ioc(url_signals["domain"], "domain")
    
    merged_signals = {**url_signals, **intel_signals}
    eval_res = risk_engine.evaluate_signals(merged_signals)
    xai = XAIExplainer.generate_explanation(eval_res)

    incident = IncidentLog(
        scan_type="URL_INTELLIGENCE",
        target=payload.url,
        risk_score=eval_res["risk_score"],
        severity=eval_res["severity"],
        raw_signals=merged_signals,
        xai_report=xai
    )
    db.add(incident)
    await db.commit()

    return {
        "target": payload.url,
        "scan_type": "URL_INTELLIGENCE",
        "risk_score": eval_res["risk_score"],
        "severity": eval_res["severity"],
        "xai_explanation": xai,
        "detected_indicators": eval_res["indicators"]
    }

@router.post("/scan/email", response_model=ScanResponse)
async def scan_email(payload: EmailScanRequest, db: AsyncSession = Depends(get_db)):
    nlp_signals = nlp_detector.analyze_text(f"{payload.subject} {payload.body}")
    imp_signals = impersonation_detector.analyze_header_and_brand(payload.sender, payload.body)

    merged_signals = {**nlp_signals, **imp_signals}
    eval_res = risk_engine.evaluate_signals(merged_signals)
    xai = XAIExplainer.generate_explanation(eval_res)

    return {
        "target": payload.sender,
        "scan_type": "EMAIL_NLP_SCAM",
        "risk_score": eval_res["risk_score"],
        "severity": eval_res["severity"],
        "xai_explanation": xai,
        "detected_indicators": eval_res["indicators"]
    }

@router.post("/scan/upi", response_model=ScanResponse)
async def scan_upi(payload: UPIScanRequest, db: AsyncSession = Depends(get_db)):
    fin_signals = financial_detector.analyze_upi(payload.upi_handle)
    eval_res = risk_engine.evaluate_signals(fin_signals)
    xai = XAIExplainer.generate_explanation(eval_res)

    return {
        "target": payload.upi_handle,
        "scan_type": "UPI_FINANCIAL_FRAUD",
        "risk_score": eval_res["risk_score"],
        "severity": eval_res["severity"],
        "xai_explanation": xai,
        "detected_indicators": eval_res["indicators"]
    }
