# Security Policy

## 🔒 Security Overview

This project implements enterprise-grade security practices suitable for production environments. **All sensitive data must be properly configured before deployment.**

## ⚠️ Critical Security Requirements

### Before Production Deployment

1. **Generate New Secrets**
   ```bash
   # Generate SECRET_KEY (minimum 32 characters)
   openssl rand -hex 32
   
   # Generate strong passwords for all services
   openssl rand -base64 32
   ```

2. **Environment Configuration**
   - Never use `.env.example` values in production
   - Change ALL default passwords
   - Set proper `ALLOWED_ORIGINS` (no wildcards)
   - Configure `DATABASE_URL` with strong credentials
   - Set `ENVIRONMENT=production`

3. **Network Security**
   - Enable HTTPS/TLS (HSTS enabled automatically)
   - Configure firewall rules
   - Use private networks for databases
   - Restrict metrics endpoint to internal network

4. **Access Control**
   - Implement principle of least privilege
   - Regular credential rotation
   - Multi-factor authentication (MFA) for admin accounts
   - Strong password policies enforced

## 🛡️ Security Features Implemented

### Authentication & Authorization

#### OAuth 2.0 with JWT
- **Token-based authentication** using industry-standard JWT
- **Access tokens**: Short-lived (30 minutes by default)
- **Refresh tokens**: Long-lived (7 days by default)
- **Token rotation**: Refresh tokens are one-time use
- **Token blacklisting**: Logout invalidates tokens

#### Password Security
- **Bcrypt hashing**: Passwords hashed with salt (never stored in plain text)
- **Password requirements**:
  - Minimum 12 characters
  - Uppercase and lowercase letters
  - Numbers and special characters
  - Common pattern detection
- **Failed login tracking**: Account lockout after repeated failures
- **Password history**: Prevents password reuse

### Input Validation & Sanitization

#### Pydantic Schemas
- **Strict type validation**: All inputs validated against schemas
- **Size limits**: Maximum payload sizes enforced
- **Pattern matching**: Regular expressions for format validation
- **XSS prevention**: HTML tag detection and rejection
- **SQL injection prevention**: Parameterized queries only

#### Examples
```python
# Email validation
email: EmailStr = Field(...)

# Username validation (alphanumeric only)
username: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$")

# JSON size limit (prevent memory exhaustion)
data: Dict = Field(..., max_length=100000)
```

### Rate Limiting

#### Multi-tier Rate Limiting
- **Per-minute limits**: Prevent burst attacks
- **Per-hour limits**: Prevent sustained abuse
- **Per-endpoint limits**: Different limits for different resources
- **Per-user limits**: Authenticated users get higher limits

#### Implementation
```python
# Default limits
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# User limits (more generous)
USER_RATE_LIMIT_PER_MINUTE=100
USER_RATE_LIMIT_PER_HOUR=5000

# Admin limits (stricter)
ADMIN_RATE_LIMIT_PER_MINUTE=30
```

### Security Headers

All responses include security headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### CORS Configuration

```python
# Development
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# Production (specific domains only, no wildcards)
ALLOWED_ORIGINS=https://app.example.com,https://www.example.com
```

### Audit Logging

#### What is Logged
- **Authentication events**: Login, logout, failed attempts
- **Authorization events**: Permission checks, access denials
- **Data modifications**: Create, update, delete operations
- **Admin actions**: All administrative operations
- **Security events**: Rate limit hits, validation failures

#### Log Security
- **Immutable**: Audit logs cannot be deleted
- **No sensitive data**: Passwords and tokens never logged
- **Correlation IDs**: Track requests across services
- **IP address tracking**: Source IP for all actions
- **Timestamp precision**: Microsecond accuracy

### Database Security

#### SQL Injection Prevention
- **SQLAlchemy ORM**: Parameterized queries only
- **Input validation**: All inputs validated before queries
- **Connection security**: TLS/SSL for database connections
- **Principle of least privilege**: Minimal database permissions

#### Examples (Safe)
```python
# ✅ SAFE: Using SQLAlchemy ORM
user = db.query(User).filter(User.email == email).first()

# ✅ SAFE: Parameterized query
result = db.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)
```

#### Examples (Unsafe - Never Do This)
```python
# ❌ NEVER: String concatenation
query = f"SELECT * FROM users WHERE email = '{email}'"  # SQL injection risk!

# ❌ NEVER: Unvalidated input
db.execute(f"DELETE FROM users WHERE id = {user_input}")  # Dangerous!
```

### Sensitive Data Protection

#### Secrets Management
- **Environment variables**: All secrets via environment
- **No hardcoded secrets**: Source code is clean
- **.gitignore**: Prevents accidental commits
- **Secrets rotation**: Regular rotation required

#### Data Encryption
- **Passwords**: Bcrypt with salt
- **Tokens**: Signed with HMAC-SHA256
- **Database**: Encryption at rest (configure in DB)
- **Network**: TLS/SSL for all connections

### Dependency Security

#### Security Scanning
```bash
# Check for known vulnerabilities
safety check

# Run security linting
bandit -r app/

# Update dependencies regularly
pip list --outdated
```

#### Dependency Pinning
All dependencies pinned to specific versions in `requirements.txt` to prevent supply chain attacks.

## 🔍 Security Testing

### Automated Tests

```bash
# Run all tests including security tests
pytest tests/

# Run only security tests
pytest tests/security/

# Generate coverage report
pytest --cov=app --cov-report=html
```

### Manual Security Testing

#### Authentication Testing
```bash
# Test rate limiting
for i in {1..100}; do curl -X POST http://localhost:8000/api/v1/auth/login; done

# Test invalid tokens
curl -H "Authorization: Bearer invalid_token" http://localhost:8000/api/v1/events

# Test password requirements
curl -X POST http://localhost:8000/api/v1/auth/register \
  -d '{"email":"test@example.com","username":"test","password":"weak"}'
```

#### Input Validation Testing
```bash
# Test SQL injection
curl -X POST http://localhost:8000/api/v1/events \
  -d '{"event_type":"user.login'; DROP TABLE users; --"}'

# Test XSS
curl -X POST http://localhost:8000/api/v1/events \
  -d '{"event_name":"<script>alert(\"XSS\")</script>"}'

# Test payload size limits
curl -X POST http://localhost:8000/api/v1/events \
  -d '{"data":"'$(python -c 'print("A"*1000000)')'"}'
```

## 🚨 Reporting Security Vulnerabilities

### Responsible Disclosure

If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** create a public GitHub issue
2. **DO** email security concerns to: security@example.com
3. **DO** provide detailed information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix timeline**: Based on severity
- **Credit**: Public acknowledgment (if desired)

### Severity Levels

- **Critical**: Immediate fix required (RCE, authentication bypass)
- **High**: Fix within 7 days (privilege escalation, data exposure)
- **Medium**: Fix within 30 days (DoS, information disclosure)
- **Low**: Fix as time permits (minor issues, best practices)

## ✅ Security Checklist

### Development

- [ ] All inputs validated with Pydantic schemas
- [ ] No SQL injection vulnerabilities (use ORM)
- [ ] No XSS vulnerabilities (validate and escape)
- [ ] No hardcoded secrets
- [ ] Proper error handling (no stack traces in production)
- [ ] Audit logging for sensitive operations
- [ ] Unit tests for security features
- [ ] Security linting with Bandit

### Pre-Production

- [ ] Generated new SECRET_KEY
- [ ] Changed all default passwords
- [ ] Configured DATABASE_URL
- [ ] Set proper ALLOWED_ORIGINS
- [ ] Enabled HTTPS/TLS
- [ ] Configured firewall rules
- [ ] Set up monitoring and alerting
- [ ] Reviewed and tested all endpoints
- [ ] Performed security scanning
- [ ] Load testing completed

### Production

- [ ] HTTPS/TLS enabled
- [ ] Security headers enabled
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Monitoring active
- [ ] Backup strategy in place
- [ ] Incident response plan documented
- [ ] Regular security updates scheduled
- [ ] Access control configured
- [ ] Secrets properly rotated

## 📚 Security Resources

### Standards & Best Practices
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

### FastAPI Security
- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

### Python Security
- [Python Security](https://python.readthedocs.io/en/latest/library/security_warnings.html)
- [Bandit Security Linter](https://bandit.readthedocs.io/)
- [Safety Vulnerability Scanner](https://pyup.io/safety/)

## 📝 Version History

- **v1.0.0** (2025-11-14): Initial security implementation
  - OAuth 2.0 authentication
  - Rate limiting
  - Input validation
  - Security headers
  - Audit logging

---

**Remember**: Security is an ongoing process, not a one-time implementation. Regular reviews, updates, and testing are essential.
