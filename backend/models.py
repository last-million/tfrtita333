from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()

class UserRole(enum.Enum):
    ADMIN = "admin"
    USER = "user"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class CallStatus(enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

class Call(Base):
    __tablename__ = "calls"
    
    id = Column(Integer, primary_key=True)
    phone_number = Column(String(50), nullable=False)
    status = Column(Enum(CallStatus), default=CallStatus.PENDING)
    duration = Column(Integer, default=0)  # in seconds
    recording_url = Column(String(500))
    transcript = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'))
    
    user = relationship("User", back_populates="calls")

class BulkCallCampaign(Base):
    __tablename__ = "bulk_call_campaigns"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    initial_message = Column(Text, nullable=False)
    total_calls = Column(Integer, default=0)
    completed_calls = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'))
    
    user = relationship("User", back_populates="campaigns")
    calls = relationship("Call", back_populates="campaign")

User.calls = relationship("Call", back_populates="user")
User.campaigns = relationship("BulkCallCampaign", back_populates="user")
Call.campaign = relationship("BulkCallCampaign", back_populates="calls")
