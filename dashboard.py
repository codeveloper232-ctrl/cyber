"""
SOC Analytics & Threat Dashboard Router
"""

from fastapi import APIRouter

router = APIRouter(tags=["Dashboard Metrics"])

@router.get("/dashboard/metrics")
async def get_dashboard_metrics():
    return {
        "total_scans_today": 14285,
        "threats_blocked": 1842,
        "critical_incidents": 124,
        "vector_distribution": {
            "URL_PHISHING": 42,
            "QUISHING_QR": 18,
            "EMAIL_SMS_SCAM": 25,
            "UPI_FRAUD": 15
        },
        "system_status": "OPTIMAL"
    }
