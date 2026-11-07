"""
Advanced URL & Domain Structural Intelligence Analyzer
"""

import urllib.parse
import re

class URLAnalyzer:
    def __init__(self):
        self.popular_brands = ["paypal", "google", "amazon", "apple", "microsoft", "chase", "binance", "sbi", "hdfc"]
        self.suspicious_tlds = [".top", ".xyz", ".cc", ".work", ".tk", ".fit", ".icu", ".vip"]

    async def analyze_url(self, url: str) -> dict:
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        domain = (parsed.netloc or parsed.path).split(':')[0].lower()

        is_typosquatted = self._check_typosquatting(domain)
        has_suspicious_tld = any(domain.endswith(tld) for tld in self.suspicious_tlds)
        redirect_hops = self._simulate_redirect_chain(url)
        domain_age = self._estimate_domain_age(domain)

        return {
            "domain": domain,
            "redirect_hops": redirect_hops,
            "is_typosquatted": is_typosquatted,
            "suspicious_tld": has_suspicious_tld,
            "domain_age_days": domain_age,
            "obfuscated_javascript": "eval(" in url or "unescape(" in url
        }

    def _check_typosquatting(self, domain: str) -> bool:
        for brand in self.popular_brands:
            if brand in domain and f"{brand}.com" not in domain and f"{brand}.in" not in domain:
                return True
            if self._levenshtein_distance(brand, domain.split('.')[0]) <= 2 and brand != domain.split('.')[0]:
                return True
        return False

    def _simulate_redirect_chain(self, url: str) -> int:
        if "redirect" in url or "gate" in url or "hop" in url or "link" in url:
            return 3
        return 1

    def _estimate_domain_age(self, domain: str) -> int:
        keywords = ["verify", "secure", "update", "login", "bank", "portal", "support", "kyc"]
        if any(kw in domain for kw in keywords):
            return 14 # Suspicious brand-new domain
        return 520

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
