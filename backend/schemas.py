from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"

class UserBase(BaseModel):
    email: EmailStr
    name: str
    role: UserRole = UserRole.USER

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    active: bool
    created_at: datetime
    
    class Config:
        orm_mode = True

class CallStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

class CallCreate(BaseModel):
    phone_number: str
    initial_message: str

class Call(BaseModel):
    id: int
    phone_number: str
    status: CallStatus
    duration: int
    recording_url: Optional[str]
    transcript: Optional[str]
    created_at: datetime
    
    class Config:
        orm_mode = True

class BulkCallCreate(BaseModel):
    phone_numbers: List[str]
    initial_message: str

class BulkCallCampaign(BaseModel):
    id: int
    name: str
    initial_message: str
    total_calls: int
    completed_calls: int
    success_rate: float
    created_at: datetime
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[UserRole] = None
