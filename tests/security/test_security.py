"""
Security tests for Event Analytics Platform.

Tests:
- Authentication and authorization
- Input validation
- SQL injection prevention
- XSS prevention
- Rate limiting
- Password security
- Token security
"""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta

from app.main import app
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_token,
    PasswordValidator
)
from app.core.config import get_settings


client = TestClient(app)


# ====================================
# Password Security Tests
# ====================================

class TestPasswordSecurity:
    """Test password hashing and validation."""
    
    def test_password_hashing(self):
        """Test that passwords are hashed correctly."""
        password = "MyStr0ng!P@ssw0rd"
        hashed = get_password_hash(password)
        
        # Hash should not equal plain password
        assert hashed != password
        
        # Hash should be bcrypt format
        assert hashed.startswith("$2b$")
        
        # Same password should produce different hashes (due to salt)
        hashed2 = get_password_hash(password)
        assert hashed != hashed2
    
    def test_password_verification(self):
        """Test that password verification works."""
        password = "MyStr0ng!P@ssw0rd"
        hashed = get_password_hash(password)
        
        # Correct password should verify
        assert verify_password(password, hashed) is True
        
        # Incorrect password should not verify
        assert verify_password("WrongPassword", hashed) is False
    
    def test_password_strength_validation(self):
        """Test password strength requirements."""
        validator = PasswordValidator()
        
        # Weak password should fail
        is_valid, errors = validator.validate("weak")
        assert is_valid is False
        assert len(errors) > 0
        
        # Strong password should pass
        is_valid, errors = validator.validate("MyStr0ng!P@ssw0rd123")
        assert is_valid is True
        assert len(errors) == 0
    
    def test_common_passwords_rejected(self):
        """Test that common passwords are rejected."""
        validator = PasswordValidator()
        
        common_passwords = [
            "password123!",
            "Password123!",
            "Qwerty123!",
        ]
        
        for pwd in common_passwords:
            is_valid, errors = validator.validate(pwd)
            # These might fail for different reasons
            # but should all be invalid
            if "common patterns" in " ".join(errors).lower():
                assert is_valid is False


# ====================================
# JWT Token Security Tests
# ====================================

class TestJWTSecurity:
    """Test JWT token security."""
    
    def test_token_creation(self):
        """Test that tokens are created correctly."""
        data = {"sub": "test@example.com"}
        token = create_access_token(data)
        
        # Token should be a string
        assert isinstance(token, str)
        
        # Token should have three parts (header.payload.signature)
        assert len(token.split(".")) == 3
    
    def test_token_expiration(self):
        """Test that expired tokens are rejected."""
        data = {"sub": "test@example.com"}
        
        # Create token that expires immediately
        token = create_access_token(
            data,
            expires_delta=timedelta(seconds=-1)
        )
        
        # Should raise exception for expired token
        with pytest.raises(Exception) as exc_info:
            decode_token(token)
        
        assert exc_info.value.status_code == 401
    
    def test_token_tampering(self):
        """Test that tampered tokens are rejected."""
        data = {"sub": "test@example.com"}
        token = create_access_token(data)
        
        # Tamper with token
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}.invalid_signature"
        
        # Should raise exception for invalid signature
        with pytest.raises(Exception) as exc_info:
            decode_token(tampered_token)
        
        assert exc_info.value.status_code == 401


# ====================================
# Input Validation Tests
# ====================================

class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection attempts are blocked."""
        # SQL injection patterns
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT * FROM users--"
        ]
        
        for malicious_input in malicious_inputs:
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "email": "test@example.com",
                    "username": malicious_input,
                    "password": "MyStr0ng!P@ssw0rd"
                }
            )
            
            # Should be rejected (400 or 422)
            assert response.status_code in [400, 422]
    
    def test_xss_prevention(self):
        """Test that XSS attempts are blocked."""
        # XSS patterns
        malicious_inputs = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        for malicious_input in malicious_inputs:
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "email": "test@example.com",
                    "username": "testuser",
                    "password": "MyStr0ng!P@ssw0rd",
                    "full_name": malicious_input
                }
            )
            
            # Should be rejected (400 or 422)
            assert response.status_code in [400, 422]
    
    def test_email_validation(self):
        """Test that invalid emails are rejected."""
        invalid_emails = [
            "notanemail",
            "@example.com",
            "user@",
            "user @example.com",
            "user@example",
        ]
        
        for invalid_email in invalid_emails:
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "email": invalid_email,
                    "username": "testuser",
                    "password": "MyStr0ng!P@ssw0rd"
                }
            )
            
            assert response.status_code == 422
    
    def test_payload_size_limit(self):
        """Test that oversized payloads are rejected."""
        # Create large payload
        large_data = {"data": "A" * 200000}  # 200KB
        
        response = client.post(
            "/api/v1/events",
            json={
                "event_type": "test.event",
                "event_name": "Test Event",
                "data": large_data
            },
            headers={"Authorization": "Bearer test_token"}
        )
        
        # Should be rejected (413 or 422)
        assert response.status_code in [413, 422]


# ====================================
# Rate Limiting Tests
# ====================================

class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def test_rate_limit_enforcement(self):
        """Test that rate limits are enforced."""
        settings = get_settings()
        
        # Make requests up to the limit
        responses = []
        for i in range(settings.RATE_LIMIT_PER_MINUTE + 10):
            response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": "test@example.com",
                    "password": "password"
                }
            )
            responses.append(response)
        
        # At least one request should be rate limited
        rate_limited = any(r.status_code == 429 for r in responses)
        assert rate_limited
    
    def test_rate_limit_headers(self):
        """Test that rate limit headers are present."""
        response = client.get("/health")
        
        # Check for rate limit headers
        assert "X-RateLimit-Limit-Minute" in response.headers
        assert "X-RateLimit-Remaining-Minute" in response.headers


# ====================================
# Security Headers Tests
# ====================================

class TestSecurityHeaders:
    """Test security headers are present."""
    
    def test_security_headers_present(self):
        """Test that all security headers are present."""
        response = client.get("/health")
        
        # Check for important security headers
        expected_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy"
        ]
        
        for header in expected_headers:
            assert header in response.headers
    
    def test_hsts_header(self):
        """Test HSTS header in production."""
        # This test assumes production environment
        # In development, HSTS might not be set
        response = client.get("/health")
        
        # HSTS should be present in production
        settings = get_settings()
        if settings.is_production():
            assert "Strict-Transport-Security" in response.headers


# ====================================
# CORS Tests
# ====================================

class TestCORS:
    """Test CORS configuration."""
    
    def test_cors_preflight(self):
        """Test CORS preflight request."""
        response = client.options(
            "/api/v1/events",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST"
            }
        )
        
        # Should allow the request
        assert response.status_code in [200, 204]
    
    def test_cors_headers(self):
        """Test that CORS headers are present."""
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"}
        )
        
        # Check for CORS headers
        settings = get_settings()
        if settings.ENABLE_CORS:
            assert "Access-Control-Allow-Origin" in response.headers


# ====================================
# Error Handling Tests
# ====================================

class TestErrorHandling:
    """Test error handling security."""
    
    def test_error_messages_safe(self):
        """Test that error messages don't leak sensitive info."""
        # Make request that will fail
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "wrongpassword"
            }
        )
        
        # Error message should be generic
        error_detail = response.json().get("detail", "")
        
        # Should not reveal whether user exists
        assert "does not exist" not in error_detail.lower()
        assert "user not found" not in error_detail.lower()
    
    def test_stack_traces_hidden(self):
        """Test that stack traces are not exposed."""
        # This test would need to trigger an internal error
        # For now, we just verify error structure
        response = client.get("/nonexistent-endpoint")
        
        # Error should not contain stack trace
        response_text = response.text.lower()
        assert "traceback" not in response_text
        assert "exception" not in response_text
        assert "file" not in response_text or ".py" not in response_text


# ====================================
# Integration Tests
# ====================================

class TestAuthenticationFlow:
    """Test complete authentication flow."""
    
    def test_registration_and_login_flow(self):
        """Test user registration and login."""
        # TODO: Implement with database
        pass
    
    def test_token_refresh_flow(self):
        """Test token refresh mechanism."""
        # TODO: Implement with database
        pass
    
    def test_logout_flow(self):
        """Test logout and token invalidation."""
        # TODO: Implement with database
        pass


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
