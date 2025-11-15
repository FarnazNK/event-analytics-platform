"""
Database models using SQLAlchemy ORM.

Security Features:
- Parameterized queries (SQL injection prevention)
- Password hashing (never store plain passwords)
- Audit timestamps
- Soft delete support
- Index optimization

Model Design:
- Users: Authentication and authorization
- Events: Application events
- AuditLogs: Security audit trail
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text,
    Index, ForeignKey, JSON, Float
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()


class TimestampMixin:
    """
    Mixin for created_at and updated_at timestamps.
    
    All models should inherit this for audit trail.
    """
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )


class SoftDeleteMixin:
    """
    Mixin for soft delete functionality.
    
    Instead of deleting records, mark them as deleted.
    Useful for audit trail and data recovery.
    """
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)
    is_deleted = Column(Boolean, default=False, nullable=False, index=True)


class User(Base, TimestampMixin, SoftDeleteMixin):
    """
    User model for authentication and authorization.
    
    Security Notes:
    - Password is hashed using bcrypt (never plain text)
    - Email must be unique and validated
    - Username must be unique
    - Account can be disabled
    - Failed login attempts tracked
    - Last login timestamp recorded
    
    Indexes:
    - email (unique, for login lookups)
    - username (unique, for uniqueness checks)
    - is_active (for filtering active users)
    """
    
    __tablename__ = "users"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Authentication
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)  # Bcrypt hash
    
    # Profile
    full_name = Column(String(255), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_superuser = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Security tracking
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)  # IPv6 compatible
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    events = relationship("Event", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_user_email_active', 'email', 'is_active'),
        Index('idx_user_username_active', 'username', 'is_active'),
    )
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"


class Event(Base, TimestampMixin, SoftDeleteMixin):
    """
    Event model for tracking application events.
    
    Features:
    - Flexible JSON data field
    - User association
    - Event type categorization
    - Metadata storage
    - Performance metrics
    
    Indexes:
    - event_type (for filtering by type)
    - user_id (for user's events)
    - created_at (for time-based queries)
    """
    
    __tablename__ = "events"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Event details
    event_type = Column(String(100), nullable=False, index=True)
    event_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Event data (flexible JSON storage)
    data = Column(JSON, nullable=True)
    metadata = Column(JSON, nullable=True)
    
    # Categorization
    category = Column(String(100), nullable=True, index=True)
    severity = Column(String(20), nullable=True, index=True)  # info, warning, error, critical
    
    # Performance metrics
    duration_ms = Column(Float, nullable=True)
    
    # User association
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    user = relationship("User", back_populates="events")
    
    # Source information
    source_ip = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_event_type_created', 'event_type', 'created_at'),
        Index('idx_event_user_created', 'user_id', 'created_at'),
        Index('idx_event_category_severity', 'category', 'severity'),
    )
    
    def __repr__(self) -> str:
        return f"<Event(id={self.id}, type={self.event_type}, name={self.event_name})>"


class AuditLog(Base, TimestampMixin):
    """
    Audit log model for security and compliance tracking.
    
    Purpose:
    - Track all security-relevant actions
    - Compliance requirements (GDPR, HIPAA, etc.)
    - Forensic analysis
    - Anomaly detection
    
    Security Notes:
    - Cannot be deleted (no soft delete)
    - Immutable after creation
    - Comprehensive action tracking
    - IP and user agent logging
    
    Indexes:
    - action (for filtering by action type)
    - user_id (for user's audit trail)
    - created_at (for time-based queries)
    - ip_address (for IP-based analysis)
    """
    
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Action details
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(100), nullable=True)
    
    # User information
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    user = relationship("User", back_populates="audit_logs")
    
    # Request details
    ip_address = Column(String(45), nullable=True, index=True)
    user_agent = Column(String(500), nullable=True)
    
    # Action data
    old_values = Column(JSON, nullable=True)
    new_values = Column(JSON, nullable=True)
    
    # Status
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)
    
    # Additional context
    metadata = Column(JSON, nullable=True)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_audit_action_created', 'action', 'created_at'),
        Index('idx_audit_user_created', 'user_id', 'created_at'),
        Index('idx_audit_ip_created', 'ip_address', 'created_at'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, user_id={self.user_id})>"


class RefreshToken(Base, TimestampMixin):
    """
    Refresh token model for JWT token management.
    
    Features:
    - Token storage for validation
    - Expiration tracking
    - Revocation support
    - User association
    
    Security Notes:
    - Tokens can be revoked
    - Expiration enforced
    - One-time use (rotate on refresh)
    - IP tracking for anomaly detection
    """
    
    __tablename__ = "refresh_tokens"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Token details
    token = Column(String(500), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # Expiration
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Status
    is_revoked = Column(Boolean, default=False, nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    
    # Security tracking
    issued_ip = Column(String(45), nullable=True)
    last_used_ip = Column(String(45), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_refresh_token_user', 'user_id', 'is_revoked'),
        Index('idx_refresh_token_expires', 'expires_at', 'is_revoked'),
    )
    
    def __repr__(self) -> str:
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, revoked={self.is_revoked})>"


# Export all models
__all__ = [
    "Base",
    "User",
    "Event",
    "AuditLog",
    "RefreshToken",
    "TimestampMixin",
    "SoftDeleteMixin"
]
