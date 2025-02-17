from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from dotenv import load_dotenv
from sqlalchemy.orm import Session
import os
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from backend.database import get_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class Config:
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
    ULTRAVOX_API_KEY = os.getenv('ULTRAVOX_API_KEY')
    ULTRAVOX_API_URL = os.getenv('ULTRAVOX_API_URL')
    VERSION = "1.0.0"
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    ALLOWED_ORIGINS = [
        "https://ajingolik.fun",
        "http://localhost:3000",
        "http://localhost:8000",
    ]

# Initialize FastAPI app
app = FastAPI(
    title="Twilio-Ultravox Integration",
    description="API for managing outbound calls using Twilio and Ultravox",
    version=Config.VERSION
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Twilio client
try:
    twilio_client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN)
    logger.info("Twilio client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Twilio client: {str(e)}")
    raise

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"Message: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": Config.VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/login")
async def login(request: Request):
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")

        if username == "hamza" and password == "BAYAbaya-11":
            return JSONResponse(
                content={"success": True, "message": "Login successful"},
                status_code=200
            )
        return JSONResponse(
            content={"success": False, "message": "Invalid credentials"},
            status_code=401
        )
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/outbound-call")
async def make_outbound_call(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        phone_number = data.get("phone_number")
        
        if not phone_number:
            raise HTTPException(status_code=400, detail="Phone number is required")

        call = twilio_client.calls.create(
            to=phone_number,
            from_=Config.TWILIO_PHONE_NUMBER,
            url=f"{request.base_url}twiml"
        )
        
        # Broadcast call status to all connected clients
        await manager.broadcast(json.dumps({
            "type": "call_initiated",
            "data": {
                "call_sid": call.sid,
                "phone_number": phone_number
            }
        }))
        
        return {"success": True, "call_sid": call.sid}
    except Exception as e:
        logger.error(f"Error making outbound call: {str(e)}")
        return {"success": False, "error": str(e)}

@app.get("/twiml")
async def get_twiml():
    twiml_response = """<?xml version="1.0" encoding="UTF-8"?>
        <Response>
            <Say>Hello, this is a test call from your Twilio Ultravox integration.</Say>
            <Pause length="1"/>
            <Say>Thank you for your time. Goodbye!</Say>
        </Response>"""
    
    return Response(
        content=twiml_response,
        media_type="text/xml"
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv('PORT', 8000))
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=Config.DEBUG
    )
