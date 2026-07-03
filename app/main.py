from dotenv import load_dotenv
load_dotenv()
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.api.webhook import router as webhook_router
from app.api.feedback import router as feedback_router
from app.api.github_app import router as github_app_router
from app.api.security import limiter
import os

app = FastAPI(
    title="AutoReviewer",
    description="Autonomous GitHub code review agent",
    version="0.1.0"
)

# CORS — allow frontend origins to call this API from the browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://revuops-web.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.include_router(feedback_router)
app.include_router(webhook_router)
app.include_router(github_app_router)

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "auto-reviewer"}