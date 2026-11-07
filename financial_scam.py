"""
UPI & Financial/KYC Scam Intelligence Module
"""

class FinancialScamDetector:
    def __init__(self):
        self.valid_handles = ["@okaxis", "@icici", "@ybl", "@paytm", "@sbi", "@upi", "@ibl"]
        self.fraud_keywords = ["support", "refund", "kyc", "customer-care", "claim", "verify"]

    def analyze_upi(self, upi_handle: str) -> dict:
        handle_lower = upi_handle.lower().strip()

        has_valid_psp = any(handle_lower.endswith(h) for h in self.valid_handles)
        contains_fraud_kw = any(kw in handle_lower for kw in self.fraud_keywords)

        unverified = not has_valid_psp or contains_fraud_kw

        return {
            "upi_handle": upi_handle,
            "unverified_upi_handle": unverified,
            "kyc_phishing_pattern": contains_fraud_kw,
            "financial_risk_level": "CRITICAL" if unverified else "CLEAN"
        }
