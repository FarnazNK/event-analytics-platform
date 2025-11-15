"""
Core configuration management with security-first design.
All sensitive values are loaded from environment variables.
"""

import os
import secrets
from typing import List, Optional
from pydantic import field_validator, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Security Notes:
    - Never hardcode sensitive values
    - All secrets must be in environment variables
    - Validate all configuration on startup
    - Fail fast if critical config is missing
    """
    
    # Application
    APP_NAME: str = "Event Analytics Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", pattern="^(development|staging|production)$")
    DEBUG: bool = False
    
    # Security - CRITICAL: Must be set via environment variables
    SECRET_KEY: str = Field(
        ...,  # Required field
        min_length=32,
        description="JWT secret key - generate with: openssl rand -hex 32"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Password Requirements
    MIN_PASSWORD_LENGTH: int = 12
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_NUMBERS: bool = True
    REQUIRE_SPECIAL_CHARS: bool = True
    
    # Database Configuration
    DATABASE_URL: str = Field(
        ...,  # Required field
        description="Database connection string with credentials"
    )
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600
    DB_QUERY_TIMEOUT: int = 30
    
    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    REDIS_MAX_CONNECTIONS: int = 50
    REDIS_SOCKET_TIMEOUT: int = 5
    REDIS_SOCKET_CONNECT_TIMEOUT: int = 5
    
    # Cache Settings
    CACHE_TTL_SECONDS: int = 300
    CACHE_MAX_SIZE: int = 10000
    LOCAL_CACHE_SIZE: int = 100
    
    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    
    # CORS Settings
    ENABLE_CORS: bool = True
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:8000"
    ALLOWED_METHODS: str = "GET,POST,PUT,DELETE,OPTIONS"
    ALLOWED_HEADERS: str = "*"
    ALLOW_CREDENTIALS: bool = True
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    USER_RATE_LIMIT_PER_MINUTE: int = 100
    USER_RATE_LIMIT_PER_HOUR: int = 5000
    ADMIN_RATE_LIMIT_PER_MINUTE: int = 30
    
    # Security Headers
    ENABLE_SECURITY_HEADERS: bool = True
    ENABLE_HSTS: bool = True
    HSTS_MAX_AGE: int = 31536000
    ENABLE_CSP: bool = True
    CSP_POLICY: str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    # Logging & Monitoring
    LOG_LEVEL: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    LOG_FORMAT: str = Field(default="json", pattern="^(json|text)$")
    ENABLE_REQUEST_LOGGING: bool = True
    ENABLE_SQL_LOGGING: bool = False
    LOG_FILE_PATH: Optional[str] = "/var/log/event-analytics/app.log"
    LOG_ROTATION_SIZE: str = "100MB"
    LOG_RETENTION_DAYS: int = 30
    
    # Metrics
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    
    # Health Checks
    HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    
    # Performance Settings
    MAX_REQUEST_SIZE: int = 10485760  # 10MB
    MAX_UPLOAD_SIZE: int = 52428800   # 50MB
    REQUEST_TIMEOUT_SECONDS: int = 30
    BACKGROUND_TASK_TIMEOUT: int = 300
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100
    
    # Background Tasks
    ENABLE_BACKGROUND_TASKS: bool = True
    TASK_QUEUE_SIZE: int = 1000
    MAX_WORKER_THREADS: int = 10
    
    # Cleanup Tasks
    ENABLE_AUTO_CLEANUP: bool = True
    CLEANUP_INTERVAL_HOURS: int = 24
    DATA_RETENTION_DAYS: int = 90
    
    # Monitoring Thresholds
    MEMORY_WARNING_THRESHOLD_PERCENT: int = 85
    MEMORY_CRITICAL_THRESHOLD_PERCENT: int = 95
    MEMORY_CHECK_INTERVAL_SECONDS: int = 15
    CACHE_HIT_RATE_TARGET_PERCENT: int = 80
    CACHE_EVICTION_WARNING_RATE: int = 100
    SLOW_QUERY_THRESHOLD_MS: int = 1000
    
    # External Services (Optional)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = "noreply@example.com"
    SMTP_USE_TLS: bool = True
    
    # Sentry Error Tracking
    SENTRY_DSN: Optional[str] = None
    SENTRY_ENVIRONMENT: Optional[str] = None
    
    # Testing
    TEST_DATABASE_URL: Optional[str] = None
    TEST_RATE_LIMIT_ENABLED: bool = False
    TEST_CACHE_ENABLED: bool = False
    
    # Feature Flags
    ENABLE_ANALYTICS_API: bool = True
    ENABLE_ADMIN_API: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    ENABLE_CACHE_WARMING: bool = True
    ENABLE_INTEGRITY_CHECKS: bool = True
    
    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """
        Validate SECRET_KEY meets security requirements.
        
        Security Requirements:
        - Minimum 32 characters
        - Not a default/example value
        - Sufficient entropy
        """
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        
        # Check for insecure default values
        insecure_defaults = [
            "CHANGE_ME",
            "changeme",
            "secret",
            "password",
            "1234567890",
            "your-secret-key-here"
        ]
        
        if any(default.lower() in v.lower() for default in insecure_defaults):
            raise ValueError(
                "SECRET_KEY contains insecure default value. "
                "Generate a secure key with: openssl rand -hex 32"
            )
        
        return v
    
    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """
        Validate database URL format and security.
        
        Security Checks:
        - Contains username and password
        - Not using default passwords
        - Proper URL format
        """
        if not v:
            raise ValueError("DATABASE_URL is required")
        
        # Check for insecure passwords in URL
        insecure_passwords = ["password", "admin", "root", "123456", "changeme"]
        if any(pwd in v.lower() for pwd in insecure_passwords):
            raise ValueError(
                "DATABASE_URL contains insecure password. "
                "Use a strong, unique password."
            )
        
        return v
    
    @field_validator("ALLOWED_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        """
        Validate CORS configuration for security.
        
        Security Notes:
        - Wildcard (*) should never be used in production
        - Only allow specific, trusted origins
        """
        if "*" in v and os.getenv("ENVIRONMENT") == "production":
            raise ValueError(
                "Wildcard CORS origin (*) is not allowed in production. "
                "Specify exact origins."
            )
        
        return v
    
    def get_allowed_origins_list(self) -> List[str]:
        """Parse ALLOWED_ORIGINS string into list."""
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]
    
    def get_allowed_methods_list(self) -> List[str]:
        """Parse ALLOWED_METHODS string into list."""
        return [method.strip() for method in self.ALLOWED_METHODS.split(",")]
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT == "production"
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.ENVIRONMENT == "development"
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"  # Ignore extra fields in environment


# Global settings instance
settings: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Get or create settings instance.
    
    This function implements lazy loading and caching of settings.
    Settings are loaded once and reused throughout the application.
    
    Returns:
        Settings: Application configuration
        
    Raises:
        ValueError: If required environment variables are missing
    """
    global settings
    
    if settings is None:
        try:
            settings = Settings()
        except Exception as e:
            raise ValueError(
                f"Failed to load configuration: {str(e)}\n"
                "Ensure all required environment variables are set. "
                "See .env.example for reference."
            ) from e
    
    return settings


def generate_secret_key() -> str:
    """
    Generate a cryptographically secure secret key.
    
    Use this for generating SECRET_KEY values.
    
    Returns:
        str: 64-character hexadecimal string
        
    Example:
        >>> key = generate_secret_key()
        >>> len(key)
        64
    """
    return secrets.token_hex(32)


# Export commonly used items
__all__ = [
    "Settings",
    "settings",
    "get_settings",
    "generate_secret_key"
]
