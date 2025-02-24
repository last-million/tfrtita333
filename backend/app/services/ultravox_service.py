# backend/app/services/ultravox_service.py

import os
import asyncio
import json
import logging
import audioop
import base64
from datetime import datetime
import websockets
import requests
from typing import Dict, Optional, List, Any
from ..config import settings
from ..database import db

logger = logging.getLogger(__name__)

class UltravoxService:
    def __init__(self):
        self.api_key = settings.ULTRAVOX_API_KEY
        self.base_url = "https://api.ultravox.ai/api/calls"
        self.model = "ultravox-70B"
        self.sample_rate = 8000
        self.buffer_size = 60
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }

    async def create_call_session(
        self, 
        system_prompt: str, 
        first_message: str, 
        voice: str = "Tanya-English",
        call_history: str = ""
    ) -> Dict:
        """Create a new Ultravox call session"""
        try:
            payload = {
                "systemPrompt": f"{system_prompt}\n\nPrevious Call History:\n{call_history}",
                "model": self.model,
                "voice": voice,
                "temperature": 0.1,
                "initialMessages": [
                    {
                        "role": "MESSAGE_ROLE_USER",
                        "text": first_message
                    }
                ],
                "medium": {
                    "serverWebSocket": {
                        "inputSampleRate": self.sample_rate,
                        "outputSampleRate": self.sample_rate,
                        "clientBufferSizeMs": self.buffer_size
                    }
                },
                "selectedTools": self._get_default_tools()
            }

            response = requests.post(
                self.base_url,
                headers=self.headers,
                json=payload
            )
            
            if not response.ok:
                logger.error(f"Ultravox create call error: {response.status_code} {response.text}")
                raise Exception(f"Failed to create Ultravox call: {response.text}")

            data = response.json()
            return {
                "join_url": data.get("joinUrl"),
                "session_id": data.get("sessionId")
            }

        except Exception as e:
            logger.error(f"Error creating Ultravox call: {str(e)}")
            raise

    async def process_media_stream(
        self,
        websocket: websockets.WebSocketClientProtocol,
        call_sid: str,
        session_id: str
    ):
        """Handle media streaming between Twilio and Ultravox"""
        ultravox_ws = None
        transcription = []
        call_duration = 0
        start_time = datetime.now()

        try:
            # Connect to Ultravox WebSocket
            session = await self.create_call_session(
                system_prompt="You are an AI assistant helping with customer inquiries.",
                first_message="Hello! How can I help you today?"
            )
            
            ultravox_ws = await websockets.connect(session['join_url'])
            logger.info(f"Connected to Ultravox WebSocket for call {call_sid}")

            async def handle_ultravox_messages():
                try:
                    async for message in ultravox_ws:
                        if isinstance(message, bytes):
                            # Handle audio data from Ultravox
                            mu_law_audio = audioop.lin2ulaw(message, 2)
                            payload = {
                                "event": "media",
                                "streamSid": session_id,
                                "media": {
                                    "payload": base64.b64encode(mu_law_audio).decode('ascii')
                                }
                            }
                            try:
                                await websocket.send(json.dumps(payload))
                                logger.debug(f"Sent audio data to Twilio for call {call_sid}")
                            except Exception as e:
                                logger.error(f"Error sending audio to Twilio: {e}")
                                break # Exit the loop if sending fails
                        else:
                            # Handle text messages from Ultravox
                            msg_data = json.loads(message)
                            msg_type = msg_data.get("type")

                            if msg_type == "transcript":
                                await self._handle_transcript(msg_data, transcription)
                            elif msg_type == "client_tool_invocation":
                                await self._handle_tool_invocation(
                                    ultravox_ws, 
                                    msg_data, 
                                    call_sid
                                )

                except Exception as e:
                    logger.error(f"Error in Ultravox message handler: {str(e)}")

            # Start Ultravox message handler
            ultravox_task = asyncio.create_task(handle_ultravox_messages())

            # Handle Twilio WebSocket messages
            try:
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        if data.get("event") == "media":
                            # Convert Twilio µ-law to PCM
                            audio_data = base64.b64decode(data["media"]["payload"])
                            pcm_data = audioop.ulaw2lin(audio_data, 2)
                            
                            # Send to Ultravox
                            if ultravox_ws and ultravox_ws.open:
                                await ultravox_ws.send(pcm_data)
                                logger.debug(f"Sent audio data to Ultravox for call {call_sid}")
                    except json.JSONDecodeError:
                        logger.error("Invalid JSON from Twilio WebSocket")
                    except Exception as e:
                        logger.error(f"Error processing Twilio message: {str(e)}")

            except Exception as e:
                logger.error(f"Error in Twilio WebSocket handler: {str(e)}")
            finally:
                if not ultravox_task.done():
                    ultravox_task.cancel()

        except Exception as e:
            logger.error(f"Error in media stream processing: {str(e)}")
        finally:
            if ultravox_ws:
                await ultravox_ws.close()
            
            # Update call records
            end_time = datetime.now()
            call_duration = (end_time - start_time).seconds
            await self._update_call_record(
                call_sid,
                call_duration,
                transcription
            )

    async def _handle_transcript(self, msg_data: Dict, transcription: List):
        """Handle transcript messages from Ultravox"""
        role = msg_data.get("role")
        text = msg_data.get("text")
        if role and text:
            transcription.append({
                "role": role,
                "text": text,
                "timestamp": datetime.now().isoformat()
            })

    async def _handle_tool_invocation(
        self,
        ws: websockets.WebSocketClientProtocol,
        msg_data: Dict,
        call_sid: str
    ):
        """Handle tool invocation requests from Ultravox"""
        tool_name = msg_data.get("toolName")
        invocation_id = msg_data.get("invocationId")
        parameters = msg_data.get("parameters", {})

        try:
            if tool_name == "schedule_meeting":
                result = await self._handle_schedule_meeting(parameters)
            elif tool_name == "send_email":
                result = await self._handle_send_email(parameters)
            elif tool_name == "hangup":
                result = await self._handle_hangup(call_sid)
            else:
                result = "Unsupported tool"

            response = {
                "type": "client_tool_result",
                "invocationId": invocation_id,
                "result": result
            }
            await ws.send(json.dumps(response))

        except Exception as e:
            logger.error(f"Error handling tool {tool_name}: {str(e)}")
            error_response = {
                "type": "client_tool_result",
                "invocationId": invocation_id,
                "error": str(e)
            }
            await ws.send(json.dumps(error_response))

    def _get_default_tools(self) -> List[Dict]:
        """Get default tools configuration"""
        return [
            {
                "temporaryTool": {
                    "modelToolName": "schedule_meeting",
                    "description": "Schedule a meeting",
                    "dynamicParameters": [
                        {
                            "name": "datetime",
                            "type": "string",
                            "description": "Meeting date and time"
                        },
                        {
                            "name": "duration",
                            "type": "integer",
                            "description": "Meeting duration in minutes"
                        },
                        {
                            "name": "attendees",
                            "type": "array",
                            "description": "List of attendee email addresses"
                        }
                    ]
                }
            },
            {
                "temporaryTool": {
                    "modelToolName": "send_email",
                    "description": "Send follow-up email",
                    "dynamicParameters": [
                        {
                            "name": "to",
                            "type": "string",
                            "description": "Recipient email address"
                        },
                        {
                            "name": "subject",
                            "type": "string",
                            "description": "Email body"
                        }
                    ]
                }
            },
            {
                "temporaryTool": {
                    "modelToolName": "hangup",
                    "description": "End the call",
                    "dynamicParameters": []
                }
            }
        ]

    async def _update_call_record(
        self,
        call_sid: str,
        duration: int,
        transcription: List[Dict]
    ):
        """Update call record with final details"""
        try:
            query = """
                UPDATE calls
                SET duration = %s,
                    transcription = %s,
                    end_time = %s,
                    ultravox_cost = %s
                WHERE call_sid = %s
            """
            values = (
                duration,
                json.dumps(transcription),
                datetime.now(),
                self._calculate_cost(duration),
                call_sid
            )
            await db.execute(query, values)
        except Exception as e:
            logger.error(f"Error updating call record: {str(e)}")

    def _calculate_cost(self, duration: int) -> float:
        """Calculate Ultravox cost based on call duration"""
        # Example cost calculation: $0.05 per minute
        return round((duration / 60) * 0.05, 2)

ultravox_service = UltravoxService()
