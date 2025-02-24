import os
import logging
import json
from datetime import datetime
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from prometheus_client import make_asgi_app

from .config import settings
from .database import create_tables, db
from .routes import auth, calls, credentials, knowledge_base, schedule, health, dashboard
from .middleware.auth import verify_token  # Your custom token verifier
from .utils.error_handler import error_handler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Voice Call AI API",
    description="API for Voice Call AI application with Ultravox integration",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(calls.router, prefix="/calls", tags=["Calls"], dependencies=[Depends(verify_token)])
app.include_router(credentials.router, prefix="/credentials", tags=["Credentials"], dependencies=[Depends(verify_token)])
app.include_router(knowledge_base.router, prefix="/knowledge", tags=["Knowledge Base"], dependencies=[Depends(verify_token)])
app.include_router(schedule.router, prefix="/schedule", tags=["Schedule"], dependencies=[Depends(verify_token)])
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"], dependencies=[Depends(verify_token)])

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return await error_handler.handle_error(request, exc)

@app.on_event("startup")
async def startup_event():
    try:
        create_tables()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Startup error: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    try:
        if db:
            await db.close()
        logger.info("Cleanup completed successfully")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "Voice Call AI API is running",
        "version": "1.0.0",
        "environment": os.getenv("ENV", "production"),
        "timestamp": datetime.utcnow().isoformat()
    }

# WebSocket endpoint (echo example)
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, token: str = Depends(verify_token)):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for user {user_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket.client_state.CONNECTED:
            await websocket.close(code=1000)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, log_level="info")
