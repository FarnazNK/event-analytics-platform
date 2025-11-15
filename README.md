# Event Analytics Platform

A production-ready, secure real-time event processing and analytics platform built with FastAPI. This project demonstrates enterprise-grade software engineering practices including comprehensive monitoring, multi-tier caching, and security-first design.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)
[![Security: OWASP](https://img.shields.io/badge/security-OWASP-brightgreen.svg)](https://owasp.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 Key Features

### Security & Compliance
- **OAuth 2.0 with JWT** - Secure authentication and authorization
- **Rate Limiting** - Per-endpoint and per-user protection
- **Input Validation** - Pydantic models with strict validation
- **SQL Injection Prevention** - Parameterized queries with SQLAlchemy
- **CORS Configuration** - Configurable cross-origin policies
- **Security Headers** - HSTS, CSP, X-Frame-Options
- **Secrets Management** - Environment-based configuration
- **Audit Logging** - Complete security event tracking

### Performance & Monitoring
- **Multi-tier Caching** - Redis with LRU eviction (80%+ hit rates)
- **Comprehensive Metrics** - 15+ performance indicators
- **Health Monitoring** - Automated checks and alerts
- **Resource Tracking** - Memory, CPU, and leak detection
- **Structured Logging** - Correlation IDs and context

### Architecture
- **Microservices Ready** - Clean separation of concerns
- **RESTful APIs** - OpenAPI/Swagger documentation
- **Async/Await** - High-concurrency support
- **Database Agnostic** - PostgreSQL/MySQL support
- **Event Streaming** - Real-time data processing

## 🔒 Security Notice

**This is an open-source project following security best practices:**

- ✅ No hardcoded credentials or secrets
- ✅ All sensitive data via environment variables
- ✅ Input validation on all endpoints
- ✅ SQL injection prevention
- ✅ Rate limiting and throttling
- ✅ Secure password hashing (bcrypt)
- ✅ HTTPS enforcement in production
- ✅ Security headers enabled
- ✅ Dependency vulnerability scanning

**⚠️ Before deploying to production:**
1. Change all default secrets in `.env`
2. Enable HTTPS/TLS
3. Configure proper CORS origins
4. Set up rate limiting thresholds
5. Enable audit logging
6. Configure firewall rules

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+ or MySQL 8+
- Redis 7+
- Docker & Docker Compose (optional)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/event-analytics-platform.git
cd event-analytics-platform
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
# ⚠️ IMPORTANT: Generate new SECRET_KEY and change all passwords!
```

5. **Initialize database**
```bash
python scripts/init_db.py
```

6. **Run the application**
```bash
uvicorn app.main:app --reload
```

7. **Access the API**
- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Metrics: http://localhost:8000/metrics

### Docker Deployment

```bash
docker-compose up -d
```

## 📊 Architecture Overview

```
event-analytics-platform/
├── app/
│   ├── api/
│   │   ├── endpoints/      # API route handlers
│   │   └── middleware/     # Security, logging, metrics
│   ├── core/
│   │   ├── config.py       # Environment configuration
│   │   ├── security.py     # Auth, hashing, tokens
│   │   └── cache.py        # Multi-tier caching
│   ├── models/             # Database models
│   ├── schemas/            # Pydantic validation
│   ├── services/           # Business logic
│   └── utils/              # Monitoring, logging
├── tests/
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── performance/        # Load tests
├── monitoring/             # Prometheus, Grafana
├── docker/                 # Dockerfiles
└── scripts/                # Utility scripts
```

## 🔐 Security Features

### Authentication & Authorization
```python
# OAuth 2.0 with JWT tokens
POST /api/v1/auth/token
POST /api/v1/auth/register
GET  /api/v1/auth/me
```

### Rate Limiting
- **Per-endpoint**: 60 requests/minute
- **Per-user**: 1000 requests/hour
- **Configurable** via environment variables

### Input Validation
```python
class EventCreate(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    data: Dict[str, Any] = Field(..., max_length=10000)
    timestamp: Optional[datetime] = None
    
    @validator('data')
    def validate_data(cls, v):
        # Custom validation logic
        if len(str(v)) > 10000:
            raise ValueError("Data payload too large")
        return v
```

### Security Headers
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `X-XSS-Protection`

## 📈 Performance Features

### Multi-tier Caching
```python
# Three-tier cache architecture
- L1: Local memory (LRU, 100 items)
- L2: Redis (TTL-based, 10000 items)
- L3: Database with query optimization
```

### Monitoring Metrics
- Cache hit/miss rates
- Request latency (p50, p95, p99)
- Memory utilization
- Database query performance
- Error rates by endpoint
- Active connections
- Queue depths

### Health Checks
```bash
GET /health          # Basic health
GET /health/ready    # Readiness probe
GET /health/live     # Liveness probe
GET /metrics         # Prometheus metrics
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test categories
pytest tests/unit
pytest tests/integration
pytest tests/performance

# Run security tests
pytest tests/security
```

## 📊 API Documentation

### Events API
```bash
POST   /api/v1/events              # Create event
GET    /api/v1/events              # List events (paginated)
GET    /api/v1/events/{id}         # Get event by ID
PUT    /api/v1/events/{id}         # Update event
DELETE /api/v1/events/{id}         # Delete event
```

### Analytics API
```bash
GET    /api/v1/analytics/summary   # Event statistics
GET    /api/v1/analytics/trends    # Time-series data
POST   /api/v1/analytics/query     # Custom queries
```

### Admin API
```bash
GET    /api/v1/admin/metrics       # System metrics
GET    /api/v1/admin/cache-stats   # Cache performance
POST   /api/v1/admin/cache-clear   # Clear cache
GET    /api/v1/admin/audit-logs    # Security audit logs
```

## 🔧 Configuration

Key environment variables:

```env
# Security (⚠️ CHANGE IN PRODUCTION!)
SECRET_KEY=your-secret-key-here-min-32-chars
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_URL=postgresql://user:password@localhost/dbname

# Redis
REDIS_URL=redis://localhost:6379/0

# API Settings
API_V1_PREFIX=/api/v1
ENABLE_CORS=true
ALLOWED_ORIGINS=http://localhost:3000

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# Monitoring
ENABLE_METRICS=true
LOG_LEVEL=INFO
```

## 🚀 Deployment

### Production Checklist
- [ ] Generate strong SECRET_KEY: `openssl rand -hex 32`
- [ ] Change all default passwords
- [ ] Configure DATABASE_URL with strong password
- [ ] Set ALLOWED_ORIGINS to your domain
- [ ] Enable HTTPS/TLS
- [ ] Set up SSL certificates
- [ ] Configure firewall rules
- [ ] Enable audit logging
- [ ] Set up monitoring alerts
- [ ] Configure backup strategy
- [ ] Review rate limit settings
- [ ] Enable security headers
- [ ] Set LOG_LEVEL to WARNING or ERROR

### Docker Production
```bash
docker-compose -f docker-compose.prod.yml up -d
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Run security checks
5. Submit pull request

## 📝 License

MIT License - see [LICENSE](LICENSE) file

## 🛡️ Security Policy

Found a security vulnerability? Please email security@example.com or create a private security advisory on GitHub.

**Do not** create public issues for security vulnerabilities.

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)

## 👨‍💻 Author

**Farnaz Nasehi**
- LinkedIn: [linkedin.com/in/farnaz-nasehi](https://linkedin.com/in/farnaz-nasehi)
- GitHub: [github.com/fnasehi](https://github.com/fnasehi)
- Email: fnasehikalajahi@gmail.com

---

**Built with ❤️ and security in mind**
