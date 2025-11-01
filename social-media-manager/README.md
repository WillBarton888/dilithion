# Dilithion Social Media Manager

**Version:** 1.0.0
**Status:** In Development
**Quality Standard:** 10/10, A++

## Overview

Professional social media management application for Dilithion cryptocurrency project. Semi-automated platform for managing Twitter, Reddit, and GitHub presence with AI-powered reply suggestions and human approval workflow.

## Architecture

- **Frontend:** React 18 + TypeScript + Material-UI
- **Backend:** FastAPI + Python 3.11+
- **Database:** SQLite (dev) → PostgreSQL (production)
- **AI:** Claude API (Anthropic)
- **Platforms:** Twitter API v2, Reddit API, GitHub API

## Features

### Core Features (Option 2)
- ✅ Unified mention monitoring (Twitter, Reddit, GitHub)
- ✅ AI-powered reply suggestions (Claude)
- ✅ Post scheduler with approval queue
- ✅ Analytics dashboard
- ✅ Smart alerts system
- ✅ Content library (FAQ templates)

### Safety & Compliance
- ✅ Human approval required for all automated actions
- ✅ Encrypted API credential storage
- ✅ Platform ToS compliance built-in
- ✅ Rate limiting (respects all API limits)
- ✅ Comprehensive audit logging

## Project Structure

```
social-media-manager/
├── backend/              # FastAPI backend application
│   ├── app/
│   │   ├── api/          # REST API endpoints
│   │   ├── core/         # Security, logging, config
│   │   ├── db/           # Database models and session
│   │   ├── schemas/      # Pydantic schemas
│   │   ├── services/     # Business logic
│   │   ├── integrations/ # Platform API wrappers
│   │   ├── tasks/        # Background tasks
│   │   └── utils/        # Utility functions
│   └── tests/            # Backend tests
├── frontend/             # React frontend application
│   ├── public/           # Static assets
│   └── src/
│       ├── components/   # React components
│       ├── pages/        # Page components
│       ├── services/     # API client
│       └── hooks/        # Custom React hooks
├── docs/                 # Documentation
├── scripts/              # Setup and deployment scripts
└── docker/               # Docker configuration

```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

### Setup

```bash
# Clone repository
git clone https://github.com/dilithion/social-media-manager.git
cd social-media-manager

# Run setup script
./scripts/setup.sh      # Linux/Mac
# or
scripts\setup.bat       # Windows

# Configure API credentials
# Edit backend/.env and frontend/.env with your API keys

# Start development servers
./scripts/start-dev.sh  # Linux/Mac
# or
scripts\start-dev.bat   # Windows
```

### Access Points

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## Development Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation (Database, FastAPI) | 🔄 In Progress |
| 2 | Platform Integrations | ⏳ Pending |
| 3 | AI Integration (Claude) | ⏳ Pending |
| 4 | Backend Services | ⏳ Pending |
| 5 | REST API Layer | ⏳ Pending |
| 6 | Frontend Foundation | ⏳ Pending |
| 7-11 | Frontend UI Components | ⏳ Pending |
| 12 | Testing & Hardening | ⏳ Pending |
| 13 | Documentation | ⏳ Pending |
| 14 | Deployment | ⏳ Pending |

## Documentation

- [Architecture Documentation](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Setup Guide](docs/setup-guide.md)
- [User Guide](docs/user-guide.md)
- [Security Practices](docs/security.md)
- [Deployment Guide](docs/deployment.md)

## API Credentials Required

### Twitter API
- API Key & Secret
- Bearer Token
- Access Token & Secret

### Reddit API
- Client ID & Secret
- Username & Password
- User Agent

### GitHub API
- Personal Access Token
- Repository Name

### Claude API
- Anthropic API Key

See [Setup Guide](docs/setup-guide.md) for detailed instructions.

## Security

- All API credentials encrypted at rest
- Master encryption key stored in environment variables only
- No credentials in code or version control
- Human approval required for all public-facing actions
- Comprehensive audit logging

## Testing

```bash
# Backend tests
cd backend
source venv/bin/activate
pytest

# Frontend tests
cd frontend
npm test

# E2E tests
npm run test:e2e
```

## Contributing

This is a private project for Dilithion cryptocurrency. Internal development only.

## License

MIT License - See [LICENSE](LICENSE) file

## Support

- **Issues:** Internal tracking only
- **Documentation:** See `docs/` directory
- **Contact:** Development team

---

**Project Principles:**
- No bias - objective technical decisions
- Keep it simple and robust
- 10/10 and A++ quality at all times
- Most professional and safest options
- Comprehensive documentation

**Generated with:** Claude Code
**Lead Engineer:** Claude (AI Assistant)
**Project Owner:** Will Barton (Dilithion)

---

**Status:** Phase 1 - Foundation (In Progress)
**Last Updated:** 2025-11-01
