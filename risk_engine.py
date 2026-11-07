"""
Central Multi-Signal AI Risk Engine
Aggregates heterogeneous threat signals into a normalized 0-100 risk score.
"""

from typing import Dict, Any, List
from core.config import settings

class MultiSignalRiskEngine:
    def __init__(self):
        self.weights = {
            "reputation": settings.WEIGHT_REPUTATION,
            "structural": settings.WEIGHT_STRUCTURAL,
            "nlp": settings.WEIGHT_NLP,
            "impersonation": settings.WEIGHT_IMPERSONATION,
            "financial": settings.WEIGHT_FINANCIAL
        }

    def evaluate_signals(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests multi-vector signal dictionary, calculates weighted sums, and maps severity.
        """
        sub_scores = {}
        indicators = []

        # 1. Domain Reputation Vector
        rep_score = 0.0
        if signals.get("domain_age_days", 365) < 30:
            rep_score += 50.0
            indicators.append("Domain registered less than 30 days ago.")
        if signals.get("virustotal_hits", 0) > 0:
            hits = signals["virustotal_hits"]
            rep_score += min(100.0, hits * 25.0)
            indicators.append(f"Flagged by {hits} VirusTotal threat engines.")
        if signals.get("suspicious_tld", False):
            rep_score += 30.0
            indicators.append("High-risk top-level domain (TLD) detected.")
        sub_scores["reputation"] = min(100.0, rep_score)

        # 2. Structural Redirect & Obfuscation Vector
        struct_score = 0.0
        redirect_hops = signals.get("redirect_hops", 0)
        if redirect_hops > 2:
            struct_score += 45.0
            indicators.append(f"Multi-hop HTTP redirect chain detected ({redirect_hops} hops).")
        if signals.get("is_typosquatted", False):
            struct_score += 65.0
            indicators.append("Typosquatted domain mimicking target brand.")
        if signals.get("obfuscated_javascript", False):
            struct_score += 40.0
            indicators.append("Obfuscated client-side JavaScript payload detected.")
        sub_scores["structural"] = min(100.0, struct_score)

        # 3. NLP Urgency & Pretexting Vector
        nlp_score = 0.0
        if signals.get("high_urgency_sentiment", False):
            nlp_score += 55.0
            indicators.append("High-urgency language attempting to induce panic.")
        if signals.get("pretexting_detected", False):
            nlp_score += 45.0
            indicators.append("Account suspension / pretexting social engineering pattern detected.")
        sub_scores["nlp"] = min(100.0, nlp_score)

        # 4. Identity & Brand Impersonation Vector
        imp_score = 0.0
        if signals.get("header_mismatch", False):
            imp_score += 75.0
            indicators.append("Mismatched DKIM/SPF email sender headers.")
        if signals.get("brand_spoofing_score", 0) > 70:
            imp_score += 50.0
            indicators.append("Unauthorized use of protected corporate brand name.")
        sub_scores["impersonation"] = min(100.0, imp_score)

        # 5. Financial & UPI Scam Vector
        fin_score = 0.0
        if signals.get("unverified_upi_handle", False):
            fin_score += 65.0
            indicators.append("Unverified or fraudulent UPI handle structure.")
        if signals.get("kyc_phishing_pattern", False):
            fin_score += 55.0
            indicators.append("Fake banking/wallet KYC update phishing flow.")
        sub_scores["financial"] = min(100.0, fin_score)

        # Calculate Final Weighted Score (0.0 to 100.0)
        weighted_sum = sum(sub_scores[k] * self.weights[k] for k in self.weights)
        final_score = round(min(100.0, max(0.0, weighted_sum)), 2)

        severity = self._classify_severity(final_score)

        return {
            "risk_score": final_score,
            "severity": severity,
            "sub_scores": sub_scores,
            "indicators": indicators if indicators else ["No suspicious indicators identified."]
        }

    def _classify_severity(self, score: float) -> str:
        if score >= settings.CRITICAL_RISK_THRESHOLD:
            return "CRITICAL"
        elif score >= settings.HIGH_RISK_THRESHOLD:
            return "HIGH"
        elif score >= settings.MEDIUM_RISK_THRESHOLD:
            return "MEDIUM"
        return "LOW"
