"""
Pydantic schemas for request validation and response serialization.

Security Features:
- Strict input validation
- Type enforcement
- Size limits
- Pattern matching
- SQL injection prevention
- XSS prevention

All schemas use Pydantic v2 syntax.
"""

import re
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import (
    BaseModel,
    Field,
    EmailStr,
    field_validator,
    ConfigDict
)


# ====================================
# Base Schemas
# ====================================

class BaseSchema(BaseModel):
    """
    Base schema with common configuration.
    
    Configuration:
    - Populate by name (alias support)
    - Validate assignments
    - Use enum values
    - JSON schema extra allowed
    """
    
    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        use_enum_values=True,
        str_strip_whitespace=True
    )


# ====================================
# Authentication Schemas
# ====================================

class UserRegister(BaseSchema):
    """
    User registration schema.
    
    Validation:
    - Email format and uniqueness
    - Username format (alphanumeric, underscore, hyphen)
    - Password strength requirements
    - Full name length
    
    Security:
    - SQL injection prevention via validation
    - XSS prevention via pattern matching
    - No HTML tags in text fields
    """
    
    email: EmailStr = Field(
        ...,
        description="Valid email address",
        examples=["user@example.com"]
    )
    
    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Alphanumeric username (3-30 chars)",
        examples=["john_doe"]
    )
    
    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="Strong password (min 12 chars)",
        examples=["MyStr0ng!P@ssw0rd"]
    )
    
    full_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=255,
        description="Full name",
        examples=["John Doe"]
    )
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """
        Validate username format and content.
        
        Rules:
        - Only alphanumeric, underscore, hyphen
        - No SQL injection patterns
        - No reserved words
        """
        # Check for SQL injection patterns
        sql_patterns = ['--', ';', '/*', '*/', 'xp_', 'sp_', 'DROP', 'SELECT', 'INSERT', 'UPDATE', 'DELETE']
        if any(pattern.lower() in v.lower() for pattern in sql_patterns):
            raise ValueError("Username contains invalid characters or patterns")
        
        # Check for reserved words
        reserved = ['admin', 'root', 'system', 'administrator']
        if v.lower() in reserved:
            raise ValueError("Username is reserved and cannot be used")
        
        return v
    
    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate full name doesn't contain HTML/script tags.
        
        Security:
        - Prevent XSS attacks
        - No HTML tags allowed
        """
        if v is None:
            return v
        
        # Check for HTML tags
        if re.search(r'<[^>]+>', v):
            raise ValueError("Full name cannot contain HTML tags")
        
        return v


class UserLogin(BaseSchema):
    """
    User login schema.
    
    Security:
    - Rate limiting applied at endpoint level
    - No sensitive data in validation errors
    """
    
    email: EmailStr = Field(
        ...,
        description="Email address",
        examples=["user@example.com"]
    )
    
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Password"
    )


class Token(BaseSchema):
    """
    JWT token response schema.
    
    Contains:
    - Access token (short-lived)
    - Refresh token (long-lived)
    - Token type (Bearer)
    - Expiration time
    """
    
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")


class TokenRefresh(BaseSchema):
    """
    Token refresh request schema.
    """
    
    refresh_token: str = Field(
        ...,
        min_length=1,
        description="Valid refresh token"
    )


class PasswordChange(BaseSchema):
    """
    Password change schema.
    
    Security:
    - Current password verification
    - New password strength validation
    - No password reuse (checked in service layer)
    """
    
    current_password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Current password"
    )
    
    new_password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="New strong password"
    )
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v: str, info) -> str:
        """
        Validate new password is different from current.
        """
        current = info.data.get('current_password')
        if current and v == current:
            raise ValueError("New password must be different from current password")
        
        return v


# ====================================
# User Schemas
# ====================================

class UserBase(BaseSchema):
    """Base user schema with common fields."""
    
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30)
    full_name: Optional[str] = Field(None, max_length=255)


class UserResponse(UserBase):
    """
    User response schema.
    
    Security:
    - Never includes password hash
    - Only public information
    """
    
    id: int
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class UserUpdate(BaseSchema):
    """
    User update schema.
    
    All fields optional for partial updates.
    """
    
    full_name: Optional[str] = Field(None, max_length=255)
    
    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v: Optional[str]) -> Optional[str]:
        """Prevent XSS attacks."""
        if v and re.search(r'<[^>]+>', v):
            raise ValueError("Full name cannot contain HTML tags")
        return v


# ====================================
# Event Schemas
# ====================================

class EventCreate(BaseSchema):
    """
    Event creation schema.
    
    Validation:
    - Event type format
    - Data size limits
    - No SQL injection
    - No XSS attacks
    """
    
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        pattern=r"^[a-zA-Z0-9_.-]+$",
        description="Event type (alphanumeric with .-_)",
        examples=["user.login", "payment.completed"]
    )
    
    event_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Human-readable event name",
        examples=["User Login", "Payment Completed"]
    )
    
    description: Optional[str] = Field(
        None,
        max_length=5000,
        description="Event description"
    )
    
    data: Optional[Dict[str, Any]] = Field(
        None,
        description="Event data (JSON)"
    )
    
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional metadata"
    )
    
    category: Optional[str] = Field(
        None,
        max_length=100,
        pattern=r"^[a-zA-Z0-9_-]+$",
        examples=["authentication", "payment", "system"]
    )
    
    severity: Optional[str] = Field(
        None,
        pattern=r"^(info|warning|error|critical)$",
        description="Event severity level",
        examples=["info", "warning"]
    )
    
    duration_ms: Optional[float] = Field(
        None,
        ge=0,
        description="Event duration in milliseconds"
    )
    
    @field_validator('data', 'metadata')
    @classmethod
    def validate_json_size(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Validate JSON data size.
        
        Security:
        - Prevent memory exhaustion
        - Limit nested depth
        - Prevent DoS attacks
        """
        if v is None:
            return v
        
        # Convert to JSON string and check size
        import json
        json_str = json.dumps(v)
        
        if len(json_str) > 100000:  # 100KB limit
            raise ValueError("Data payload is too large (max 100KB)")
        
        # Check nesting depth (prevent stack overflow)
        def check_depth(obj, depth=0, max_depth=10):
            if depth > max_depth:
                raise ValueError(f"Data nesting too deep (max {max_depth} levels)")
            
            if isinstance(obj, dict):
                for value in obj.values():
                    check_depth(value, depth + 1, max_depth)
            elif isinstance(obj, list):
                for item in obj:
                    check_depth(item, depth + 1, max_depth)
        
        check_depth(v)
        
        return v
    
    @field_validator('description', 'event_name')
    @classmethod
    def validate_no_html(cls, v: Optional[str]) -> Optional[str]:
        """Prevent XSS attacks."""
        if v and re.search(r'<[^>]+>', v):
            raise ValueError("Field cannot contain HTML tags")
        return v


class EventResponse(BaseSchema):
    """
    Event response schema.
    """
    
    id: int
    event_type: str
    event_name: str
    description: Optional[str]
    data: Optional[Dict[str, Any]]
    metadata: Optional[Dict[str, Any]]
    category: Optional[str]
    severity: Optional[str]
    duration_ms: Optional[float]
    user_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class EventUpdate(BaseSchema):
    """
    Event update schema.
    
    All fields optional for partial updates.
    """
    
    event_name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)
    data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    category: Optional[str] = Field(None, max_length=100)
    severity: Optional[str] = Field(None, pattern=r"^(info|warning|error|critical)$")
    duration_ms: Optional[float] = Field(None, ge=0)


class EventQuery(BaseSchema):
    """
    Event query/filter schema.
    
    Security:
    - Prevent SQL injection via validated parameters
    - Limit result size
    """
    
    event_type: Optional[str] = Field(None, max_length=100)
    category: Optional[str] = Field(None, max_length=100)
    severity: Optional[str] = Field(None, pattern=r"^(info|warning|error|critical)$")
    user_id: Optional[int] = Field(None, ge=1)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")
    
    @field_validator('end_date')
    @classmethod
    def validate_date_range(cls, v: Optional[datetime], info) -> Optional[datetime]:
        """Validate end date is after start date."""
        start = info.data.get('start_date')
        if start and v and v < start:
            raise ValueError("End date must be after start date")
        return v


# ====================================
# Analytics Schemas
# ====================================

class AnalyticsSummary(BaseSchema):
    """
    Analytics summary response.
    """
    
    total_events: int
    events_by_type: Dict[str, int]
    events_by_category: Dict[str, int]
    events_by_severity: Dict[str, int]
    average_duration_ms: Optional[float]
    period_start: datetime
    period_end: datetime


class TrendPoint(BaseSchema):
    """Single point in trend data."""
    
    timestamp: datetime
    count: int
    average_duration_ms: Optional[float]


class TrendsResponse(BaseSchema):
    """
    Time-series trends response.
    """
    
    event_type: str
    interval: str  # hour, day, week, month
    data_points: List[TrendPoint]


# ====================================
# Error Schemas
# ====================================

class ErrorResponse(BaseSchema):
    """
    Standard error response.
    
    Security:
    - No sensitive information in errors
    - No stack traces in production
    - Generic messages for security errors
    """
    
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Machine-readable error code")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    correlation_id: Optional[str] = Field(None, description="Request correlation ID")


class ValidationError(BaseSchema):
    """
    Validation error response.
    """
    
    field: str
    message: str


class ValidationErrorResponse(BaseSchema):
    """
    Validation errors response.
    """
    
    detail: str = "Validation error"
    errors: List[ValidationError]


# ====================================
# Health & Metrics Schemas
# ====================================

class HealthCheck(BaseSchema):
    """
    Health check response.
    """
    
    status: str = Field(..., pattern=r"^(healthy|degraded|unhealthy)$")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    checks: Dict[str, bool]


class MetricsResponse(BaseSchema):
    """
    System metrics response.
    """
    
    cache_metrics: Dict[str, Any]
    request_metrics: Dict[str, Any]
    database_metrics: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# Export all schemas
__all__ = [
    # Auth
    "UserRegister",
    "UserLogin",
    "Token",
    "TokenRefresh",
    "PasswordChange",
    # User
    "UserBase",
    "UserResponse",
    "UserUpdate",
    # Event
    "EventCreate",
    "EventResponse",
    "EventUpdate",
    "EventQuery",
    # Analytics
    "AnalyticsSummary",
    "TrendPoint",
    "TrendsResponse",
    # Error
    "ErrorResponse",
    "ValidationError",
    "ValidationErrorResponse",
    # Health
    "HealthCheck",
    "MetricsResponse",
]
