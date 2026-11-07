"""
Automated Incident Reporting API Router
"""

from fastapi import APIRouter, Response
import json

router = APIRouter(tags=["Incident Reports"])

@router.get("/reports/incident/{incident_id}/json")
async def export_json_report(incident_id: int):
    return {
        "report_id": f"CYBERGUARD-INC-{incident_id:06d}",
        "timestamp": "2026-11-07T16:00:00Z",
        "threat_level": "CRITICAL",
        "target": "http://login.secure-bank-verify.top/auth",
        "assigned_score": 92.4,
        "xai_attributions": [
            "Domain registered less than 30 days ago.",
            "Typosquatted domain mimicking financial institution.",
            "Multi-hop HTTP redirect chain detected (3 hops)."
        ]
    }
