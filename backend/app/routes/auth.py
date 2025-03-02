from fastapi import APIRouter, HTTPException, status, Depends, Body
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import List, Optional
from ..database import db
from ..config import settings
from ..security.password import hash_password, verify_password

router = APIRouter()

# Load JWT configuration from settings
SECRET_KEY = settings.jwt_secret
ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    is_admin: bool

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    
class UserUpdate(BaseModel):
    password: Optional[str] = None
    is_active: Optional[bool] = None

class UserResponse(UserBase):
    id: int
    is_admin: bool
    is_active: bool
    created_at: datetime

def create_access_token(data: dict, expires_delta: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(request_data: LoginRequest):
    try:
        # Fetch user from database
        query = "SELECT id, username, password_hash, is_admin, is_active FROM users WHERE username = %s"
        users = await db.execute(query, (request_data.username,))
        
        if not users:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = users[0]
        
        # Check if user is active
        if not user.get('is_active', True):  # Default to True if field doesn't exist
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Verify password
        if not verify_password(request_data.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Generate token with user info
        token_data = {
            "sub": request_data.username,
            "user_id": user["id"],
            "is_admin": bool(user.get("is_admin", False))
        }
        
        access_token = create_access_token(token_data)
        
        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "username": user["username"],
            "is_admin": bool(user.get("is_admin", False))
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during authentication: {str(e)}",
        )

@router.post("/refresh")
async def refresh_token(current_user: dict = Depends(lambda: {"sub": "temp"})):
    # Generate a new token with the same claims
    access_token = create_access_token({"sub": current_user["sub"]})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
async def get_current_user(current_user: dict = Depends(lambda: {"sub": "temp"})):
    try:
        # Fetch user details from database
        query = "SELECT id, username, is_admin, is_active, created_at FROM users WHERE username = %s"
        users = await db.execute(query, (current_user["sub"],))
        
        if not users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
            
        return users[0]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error fetching user information: {str(e)}",
        )

# Admin-only routes for user management
@router.get("/users", response_model=List[UserResponse])
async def get_users(current_user: dict = Depends(lambda: {"is_admin": False})):
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access user management",
        )
        
    try:
        query = "SELECT id, username, is_admin, is_active, created_at FROM users ORDER BY id"
        users = await db.execute(query)
        return users
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error fetching users: {str(e)}",
        )

@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate, 
    current_user: dict = Depends(lambda: {"is_admin": False})
):
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create users",
        )
        
    try:
        # Check if username exists
        check_query = "SELECT id FROM users WHERE username = %s"
        existing_user = await db.execute(check_query, (user_data.username,))
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists",
            )
            
        # Hash password
        hashed_password = hash_password(user_data.password)
        
        # Insert new user
        insert_query = """
            INSERT INTO users (username, password_hash, is_admin, is_active) 
            VALUES (%s, %s, FALSE, TRUE)
        """
        await db.execute(
            insert_query, 
            (user_data.username, hashed_password)
        )
        
        # Get the new user
        get_query = """
            SELECT id, username, is_admin, is_active, created_at 
            FROM users WHERE username = %s
        """
        new_user = await db.execute(get_query, (user_data.username,))
        
        return new_user[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating user: {str(e)}",
        )

@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: dict = Depends(lambda: {"is_admin": False})
):
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update users",
        )
        
    try:
        # Check if user exists
        check_query = "SELECT id FROM users WHERE id = %s"
        existing_user = await db.execute(check_query, (user_id,))
        
        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
            
        # Construct update parts
        updates = []
        params = []
        
        if user_data.password is not None:
            updates.append("password_hash = %s")
            params.append(hash_password(user_data.password))
            
        if user_data.is_active is not None:
            updates.append("is_active = %s")
            params.append(user_data.is_active)
            
        if not updates:
            # No fields to update
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid fields to update",
            )
            
        # Update user
        update_query = f"""
            UPDATE users 
            SET {', '.join(updates)}
            WHERE id = %s
        """
        params.append(user_id)
        await db.execute(update_query, tuple(params))
        
        # Get updated user
        get_query = """
            SELECT id, username, is_admin, is_active, created_at 
            FROM users WHERE id = %s
        """
        updated_user = await db.execute(get_query, (user_id,))
        
        return updated_user[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating user: {str(e)}",
        )

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    current_user: dict = Depends(lambda: {"is_admin": False, "user_id": -1})
):
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete users",
        )
        
    # Prevent deleting yourself
    if current_user.get("user_id") == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
        
    try:
        # Check if user exists
        check_query = "SELECT id FROM users WHERE id = %s"
        existing_user = await db.execute(check_query, (user_id,))
        
        if not existing_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
            
        # Delete user
        delete_query = "DELETE FROM users WHERE id = %s"
        await db.execute(delete_query, (user_id,))
        
        return None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting user: {str(e)}",
        )
