# 🚀 Quick Start Guide

Get started with the Event Analytics Platform in 5 minutes!

## Prerequisites

- Python 3.11+
- PostgreSQL or MySQL
- Redis
- Git

## Installation Steps

### 1. Clone or Download

If this is already downloaded, skip to step 2.

```bash
git clone <your-repo-url>
cd event-analytics-platform
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv

# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Generate a secure SECRET_KEY
openssl rand -hex 32

# Edit .env and set:
# - SECRET_KEY=<generated-key>
# - DATABASE_URL=postgresql://user:password@localhost/dbname
# - REDIS_URL=redis://localhost:6379/0
```

### 5. Start Services (Option A: Docker)

```bash
# Start all services with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f api
```

### 5. Start Services (Option B: Local)

```bash
# Make sure PostgreSQL and Redis are running

# Initialize database
python scripts/init_db.py

# Start the application
uvicorn app.main:app --reload
```

### 6. Access the Application

- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Metrics**: http://localhost:8000/metrics

## Using Make Commands

This project includes a Makefile for common tasks:

```bash
# View all available commands
make help

# Complete setup
make setup

# Run tests
make test

# Run with coverage
make test-cov

# Security checks
make security

# Format code
make format

# Run linters
make lint

# Start dev server
make run

# Docker commands
make docker-up
make docker-down
make docker-logs
```

## Quick Test

```bash
# Check health
curl http://localhost:8000/health

# View API documentation
# Open http://localhost:8000/docs in your browser
```

## Next Steps

1. **Review Security**: Read [SECURITY.md](SECURITY.md)
2. **Configuration**: Update `.env` for your environment
3. **Development**: Read [CONTRIBUTING.md](CONTRIBUTING.md)
4. **API Documentation**: Explore `/docs` endpoint
5. **Run Tests**: `make test-cov`

## Common Issues

### Database Connection Error

```bash
# Make sure PostgreSQL is running
brew services start postgresql  # macOS
sudo service postgresql start   # Linux

# Check connection string in .env
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
```

### Redis Connection Error

```bash
# Make sure Redis is running
brew services start redis  # macOS
sudo service redis start   # Linux

# Check connection string in .env
REDIS_URL=redis://localhost:6379/0
```

### Module Not Found Error

```bash
# Make sure virtual environment is activated
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

## Project Structure

```
event-analytics-platform/
├── app/                    # Application code
│   ├── api/               # API endpoints and middleware
│   ├── core/              # Core functionality (config, security, cache)
│   ├── models/            # Database models
│   ├── schemas/           # Pydantic schemas
│   ├── services/          # Business logic
│   └── main.py           # FastAPI application
├── tests/                 # Test suite
├── docker/                # Docker configuration
├── monitoring/            # Prometheus/Grafana config
├── scripts/               # Utility scripts
├── .env.example          # Example environment variables
├── requirements.txt       # Python dependencies
├── docker-compose.yml    # Docker Compose configuration
├── Makefile              # Development commands
└── README.md             # Full documentation
```

## Security Checklist

Before deploying to production:

- [ ] Generate new SECRET_KEY
- [ ] Change all default passwords
- [ ] Configure DATABASE_URL with strong password
- [ ] Set proper ALLOWED_ORIGINS
- [ ] Enable HTTPS/TLS
- [ ] Review SECURITY.md
- [ ] Run security tests: `make security`
- [ ] Set ENVIRONMENT=production

## Getting Help

- **Documentation**: See README.md
- **Security**: See SECURITY.md
- **Contributing**: See CONTRIBUTING.md
- **Issues**: Create a GitHub issue
- **Questions**: Open a GitHub discussion

## Technologies Used

- **FastAPI**: Modern web framework
- **PostgreSQL**: Relational database
- **Redis**: Caching layer
- **SQLAlchemy**: ORM
- **Pydantic**: Data validation
- **JWT**: Authentication
- **Docker**: Containerization
- **Pytest**: Testing
- **Prometheus**: Monitoring

---

**Happy coding! 🎉**

For detailed documentation, see [README.md](README.md)
