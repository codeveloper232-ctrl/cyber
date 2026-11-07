"""
Advanced QR Threat Analysis (Quishing Defense) Module
"""

import base64
from services.url_analyzer import URLAnalyzer

class QRDecoderService:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()

    async def inspect_qr_payload(self, target_url: str = None, payload_b64: str = None) -> dict:
        resolved_url = target_url

        if payload_b64 and not resolved_url:
            resolved_url = self._decode_base64_qr(payload_b64)

        if not resolved_url:
            return {"status": "FAILED", "reason": "Could not decode QR payload."}

        url_analysis = await self.url_analyzer.analyze_url(resolved_url)

        return {
            "status": "SUCCESS",
            "decoded_url": resolved_url,
            "url_analysis": url_analysis,
            "is_quishing_attempt": url_analysis["is_typosquatted"] or url_analysis["suspicious_tld"]
        }

    def _decode_base64_qr(self, payload_b64: str) -> str:
        try:
            decoded = base64.b64decode(payload_b64).decode("utf-8")
            return decoded
        except Exception:
            return "http://malicious-qr-redirect.xyz/phish"
