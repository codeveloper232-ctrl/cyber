"""
Digital Impersonation & Brand Spoofing Detection Engine
"""

class ImpersonationDetector:
    def __init__(self):
        self.protected_brands = ["Paypal", "Google", "Amazon", "Apple", "Microsoft", "State Bank", "HDFC Bank"]

    def analyze_header_and_brand(self, sender: str, content: str) -> dict:
        sender_lower = sender.lower()
        content_lower = content.lower()

        spoofed_brand = None
        for brand in self.protected_brands:
            if brand.lower() in content_lower and brand.lower() not in sender_lower:
                spoofed_brand = brand
                break

        header_mismatch = False
        if "bank" in content_lower and not any(kw in sender_lower for kw in ["bank.com", "official"]):
            header_mismatch = True

        return {
            "spoofed_brand": spoofed_brand,
            "brand_spoofing_score": 85.0 if spoofed_brand else 0.0,
            "header_mismatch": header_mismatch
        }
