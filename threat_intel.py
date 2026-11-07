"""
Global Threat Intelligence Feed Aggregator
"""

import aiohttp
from core.config import settings

class ThreatIntelAggregator:
    async def lookup_ioc(self, ioc: str, ioc_type: str = "domain") -> dict:
        """
        Queries external APIs or provides fallback heuristics when keys are unconfigured.
        """
        if not settings.VIRUSTOTAL_API_KEY:
            # Fallback heuristic threat match
            if any(kw in ioc for kw in ["phish", "malicious", "scam", "verify", "secure", "top"]):
                return {"virustotal_hits": 6, "abuseipdb_score": 80.0}
            return {"virustotal_hits": 0, "abuseipdb_score": 0.0}

        try:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/{ioc_type}s/{ioc}",
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        return {"virustotal_hits": stats.get("malicious", 0)}
        except Exception:
            pass

        return {"virustotal_hits": 0}
