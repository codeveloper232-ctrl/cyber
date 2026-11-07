"""
Pydantic Schemas for Input Validation and API Serialization
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class URLScanRequest(BaseModel):
    url: str = Field(..., example="http://login.secure-bank-verify.top/auth")

class QRScanRequest(BaseModel):
    qr_payload_b64: Optional[str] = None
    target_url: Optional[str] = Field(None, example="http://pay-upi.scam-domain.in")

class EmailScanRequest(BaseModel):
    sender: str = Field(..., example="security@bank-alert-update.com")
    subject: str = Field(..., example="URGENT: Account Locked - Verify Immediately")
    body: str = Field(..., example="Dear customer, your bank account is suspended. Click link to verify KYC.")

class UPIScanRequest(BaseModel):
    upi_handle: str = Field(..., example="support-refund@ybl")
    amount: Optional[float] = 0.0

class MultiStageScanRequest(BaseModel):
    url: Optional[str] = None
    email_text: Optional[str] = None
    upi_handle: Optional[str] = None

class ScanResponse(BaseModel):
    target: str
    scan_type: str
    risk_score: float
    severity: str
    xai_explanation: Dict[str, Any]
    detected_indicators: List[str]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
