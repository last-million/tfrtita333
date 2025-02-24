# backend/app/routes/dashboard.py

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict
import logging
from ..database import db
from ..middleware.auth import verify_token

router = APIRouter()

logger = logging.getLogger(__name__)

@router.get("/stats")
async def get_dashboard_stats():
    """
    Retrieve dashboard statistics
    """
    try:
        # Total calls
        total_calls_query = "SELECT COUNT(*) FROM calls"
        total_calls_result = await db.execute(total_calls_query)
        total_calls = total_calls_result[0][0] if total_calls_result else 0

        # Active services
        active_services_query = "SELECT COUNT(*) FROM service_credentials WHERE is_connected = TRUE"
        active_services_result = await db.execute(active_services_query)
        active_services = active_services_result[0][0] if active_services_result else 0

        # Knowledge base documents
        knowledge_base_query = "SELECT COUNT(*) FROM knowledge_base_documents"
        knowledge_base_result = await db.execute(knowledge_base_query)
        knowledge_base_documents = knowledge_base_result[0][0] if knowledge_base_result else 0

        # AI Accuracy (This is a placeholder, you'll need to implement actual logic)
        ai_response_accuracy = "85%"

        return {
            "totalCalls": total_calls,
            "activeServices": active_services,
            "knowledgeBaseDocuments": knowledge_base_documents,
            "aiResponseAccuracy": ai_response_accuracy
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
