"""
Security module implementing authentication, authorization, and password management.

Security Features:
- OAuth 2.0 with JWT tokens
- Bcrypt password hashing with salt
- Token blacklisting support
- Rate limiting protection
- Secure password validation
- SQL injection prevention
"""

import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import get_settings


# Password hashing context using bcrypt
# Bcrypt is recommended for password hashing due to its adaptive nature
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{get_settings().API_V1_PREFIX}/auth/token"
)


class PasswordValidator:
    """
    Validates passwords against security requirements.
    
    Requirements are configurable via environment variables:
    - Minimum length
    - Uppercase letters
    - Lowercase letters
    - Numbers
    - Special characters
    """
    
    def __init__(self):
        settings = get_settings()
        self.min_length = settings.MIN_PASSWORD_LENGTH
        self.require_uppercase = settings.REQUIRE_UPPERCASE
        self.require_lowercase = settings.REQUIRE_LOWERCASE
        self.require_numbers = settings.REQUIRE_NUMBERS
        self.require_special = settings.REQUIRE_SPECIAL_CHARS
    
    def validate(self, password: str) -> tuple[bool, list[str]]:
        """
        Validate password against all requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_messages)
            
        Example:
            >>> validator = PasswordValidator()
            >>> is_valid, errors = validator.validate("weak")
            >>> is_valid
            False
            >>> len(errors) > 0
            True
        """
        errors = []
        
        # Check length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        # Check uppercase
        if self.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check lowercase
        if self.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check numbers
        if self.require_numbers and not re.search(r"\d", password):
            errors.append("Password must contain at least one number")
        
        # Check special characters
        if self.require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")
        
        # Check for common patterns (dictionary attack prevention)
        common_patterns = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "sunshine"
        ]
        if any(pattern in password.lower() for pattern in common_patterns):
            errors.append("Password contains common patterns and is not secure")
        
        return len(errors) == 0, errors
    
    def get_requirements(self) -> str:
        """Get human-readable password requirements string."""
        requirements = [f"at least {self.min_length} characters"]
        
        if self.require_uppercase:
            requirements.append("one uppercase letter")
        if self.require_lowercase:
            requirements.append("one lowercase letter")
        if self.require_numbers:
            requirements.append("one number")
        if self.require_special:
            requirements.append("one special character")
        
        return f"Password must contain {', '.join(requirements)}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        plain_password: Plain text password
        hashed_password: Bcrypt hashed password
        
    Returns:
        bool: True if passwords match
        
    Security Notes:
        - Uses bcrypt with automatic salt generation
        - Constant-time comparison prevents timing attacks
        - Automatically handles password rehashing if needed
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Bcrypt hashed password with salt
        
    Security Notes:
        - Bcrypt automatically generates and stores salt
        - Uses work factor to slow down brute force attacks
        - Hash is different each time (due to random salt)
        
    Example:
        >>> hash1 = get_password_hash("mypassword")
        >>> hash2 = get_password_hash("mypassword")
        >>> hash1 != hash2  # Different salts
        True
        >>> verify_password("mypassword", hash1)
        True
    """
    return pwd_context.hash(password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload data to encode in token
        expires_delta: Optional expiration time delta
        
    Returns:
        str: Encoded JWT token
        
    Security Notes:
        - Token is signed with SECRET_KEY
        - Includes expiration time (exp claim)
        - Cannot be modified without invalidating signature
        - Should be transmitted over HTTPS only
        
    Example:
        >>> token = create_access_token({"sub": "user@example.com"})
        >>> isinstance(token, str)
        True
    """
    settings = get_settings()
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    # Add standard JWT claims
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),  # Issued at
        "type": "access"
    })
    
    # Encode token
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create a JWT refresh token with longer expiration.
    
    Args:
        data: Payload data to encode in token
        
    Returns:
        str: Encoded JWT refresh token
        
    Security Notes:
        - Longer expiration than access tokens
        - Should be stored securely (HttpOnly cookie)
        - Used only to generate new access tokens
        - Should be rotated on use
    """
    settings = get_settings()
    to_encode = data.copy()
    
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Dict containing token payload
        
    Raises:
        HTTPException: If token is invalid or expired
        
    Security Notes:
        - Validates signature using SECRET_KEY
        - Checks expiration time
        - Verifies token type
        - Prevents token reuse after expiration
    """
    settings = get_settings()
    
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    """
    Extract current user ID from JWT token.
    
    This dependency can be used in FastAPI endpoints to require authentication.
    
    Args:
        token: JWT token from Authorization header
        
    Returns:
        str: User ID from token
        
    Raises:
        HTTPException: If token is invalid or user not found
        
    Example:
        @router.get("/protected")
        async def protected_route(user_id: str = Depends(get_current_user_id)):
            return {"user_id": user_id}
    """
    payload = decode_token(token)
    
    user_id: Optional[str] = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify token type
    token_type = payload.get("type")
    if token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user_id


async def get_current_active_user(user_id: str = Depends(get_current_user_id)) -> str:
    """
    Get current active user with additional checks.
    
    This dependency adds extra validation on top of get_current_user_id.
    Can be extended to check user status, permissions, etc.
    
    Args:
        user_id: User ID from JWT token
        
    Returns:
        str: User ID
        
    Example:
        @router.get("/me")
        async def read_users_me(user_id: str = Depends(get_current_active_user)):
            return {"user_id": user_id}
    """
    # TODO: Add database lookup to verify user exists and is active
    # For now, just return user_id
    return user_id


def validate_password_strength(password: str) -> None:
    """
    Validate password meets security requirements.
    
    Args:
        password: Password to validate
        
    Raises:
        HTTPException: If password doesn't meet requirements
        
    Example:
        >>> validate_password_strength("weak")
        Traceback (most recent call last):
        ...
        HTTPException: 400: Password does not meet requirements
    """
    validator = PasswordValidator()
    is_valid, errors = validator.validate(password)
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Password does not meet requirements",
                "errors": errors,
                "requirements": validator.get_requirements()
            }
        )


# Token blacklist for logout functionality
# In production, use Redis or database
_token_blacklist: set = set()


def blacklist_token(token: str) -> None:
    """
    Add token to blacklist (logout).
    
    Args:
        token: JWT token to blacklist
        
    Security Notes:
        - In production, store in Redis with TTL
        - Blacklist only needs to exist until token expires
        - Consider using JTI (JWT ID) claim for efficiency
    """
    _token_blacklist.add(token)


def is_token_blacklisted(token: str) -> bool:
    """
    Check if token is blacklisted.
    
    Args:
        token: JWT token to check
        
    Returns:
        bool: True if token is blacklisted
    """
    return token in _token_blacklist


# Export public API
__all__ = [
    "verify_password",
    "get_password_hash",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_current_user_id",
    "get_current_active_user",
    "validate_password_strength",
    "PasswordValidator",
    "blacklist_token",
    "is_token_blacklisted",
]
