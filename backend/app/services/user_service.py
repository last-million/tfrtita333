from passlib.context import CryptContext
from ..database import db
import logging

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def get_user_from_db(username: str) -> dict:
    try:
        query = "SELECT id, username, password_hash FROM users WHERE username = %s"
        result = await db.execute(query, (username,))
        return result[0] if result else None
    except Exception as e:
        logger.error(f"Error getting user from database: {e}")
        return None

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
