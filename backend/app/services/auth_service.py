from fastapi import HTTPException, status
from passlib.context import CryptContext
from ..database import db
from ..security.password import verify_password

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def authenticate_user(username: str, password: str):
    query = "SELECT id, username, password_hash FROM users WHERE username = %s"
    result = await db.execute(query, (username,))
    
    if not result or len(result) == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = result[0]
    if not verify_password(password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user
