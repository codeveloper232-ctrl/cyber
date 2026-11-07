"""
CYBERGUARD X - Next-Generation AI Threat Intelligence Platform
Main FastAPI Application Entrypoint
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from core.config import settings
from database.connection import init_db
from routers import scan, telemetry, reports, dashboard

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("CYBERGUARD-X")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application Startup and Shutdown Lifespan Events."""
    logger.info("Initializing CYBERGUARD X Core Risk Engine & Database Pools...")
    await init_db()
    logger.info("Database schemas verified and threat detection feeds online.")
    yield
    logger.info("Shutting down CYBERGUARD X Threat Engine graceful cleanup...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Multi-Signal AI Threat Intelligence & Financial Fraud Prevention Engine",
    lifespan=lifespan
)

# CORS Policy Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Route Handlers Registration
app.include_router(scan.router, prefix="/api/v1")
app.include_router(telemetry.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")

@app.get("/health", tags=["System"])
async def system_health():
    return {
        "status": "OPERATIONAL",
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "active_modules": [
            "URL_STRUCTURAL_ANALYZER",
            "QUISHING_QR_DEFENSE",
            "NLP_URGENCY_SENTINEL",
            "BRAND_IMPERSONATION_GUARD",
            "UPI_KYC_SCAM_DETECTOR",
            "MULTI_SIGNAL_AI_RISK_ENGINE"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
