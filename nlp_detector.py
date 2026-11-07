"""
AI-Powered NLP Email & SMS Scam Detection Service
"""

import re

class NLPScamDetector:
    def __init__(self):
        self.urgency_keywords = [
            "urgent", "immediately", "suspended", "locked", "unauthorized",
            "24 hours", "action required", "legal action", "terminate", "alert"
        ]
        self.pretexting_patterns = [
            r"account.*suspended",
            r"verify.*identity",
            r"security.*breach",
            r"unusual.*activity",
            r"kyc.*update"
        ]

    def analyze_text(self, text: str) -> dict:
        text_lower = text.lower()

        urgency_hits = sum(1 for kw in self.urgency_keywords if kw in text_lower)
        pretexting_matched = any(re.search(pat, text_lower) for pat in self.pretexting_patterns)

        high_urgency = urgency_hits >= 2 or pretexting_matched

        return {
            "high_urgency_sentiment": high_urgency,
            "pretexting_detected": pretexting_matched,
            "urgency_score": min(100.0, urgency_hits * 30.0),
            "contains_suspicious_url": bool(re.search(r"https?://[^s]+", text))
        }
