# Security Practices

## Credential Management

### Encryption
- All API credentials encrypted at rest using Fernet (symmetric encryption)
- Master encryption key stored in environment variable only
- Never store master key in database or version control

### Generating Keys

**Master Encryption Key:**
```python
python -c "from app.core.security import generate_encryption_key; print(generate_encryption_key())"
```

**Backend API Key:**
```python
python -c "from app.core.security import generate_api_key; print(generate_api_key())"
```

**Secret Key:**
```bash
openssl rand -hex 32
```

### Environment Security

1. Never commit `.env` files to version control
2. Use `.env.example` as template
3. Rotate keys regularly
4. Use different keys for dev/staging/production

## Authentication

### API Key Authentication
- All API requests require `X-API-Key` header
- Constant-time comparison prevents timing attacks
- Invalid attempts logged for monitoring

### Usage Example:
```python
import requests

headers = {"X-API-Key": "your-api-key-here"}
response = requests.get("http://localhost:8000/api/v1/mentions", headers=headers)
```

## Best Practices

1. **Key Rotation:** Rotate API keys quarterly
2. **Access Control:** Limit API key distribution
3. **Monitoring:** Review authentication logs regularly
4. **Backups:** Backup encryption keys securely (offline)
5. **Platform Credentials:** Never hardcode in source code

## Platform API Security

### Twitter
- Use environment variables only
- Enable 2FA on Twitter developer account
- Monitor API usage for anomalies

### Reddit
- Use separate account for bot activity
- Store credentials encrypted
- Respect rate limits strictly

### GitHub
- Use Personal Access Token with minimal scopes
- Set expiration dates on tokens
- Revoke tokens when not in use

### Claude
- Store API key encrypted
- Monitor token usage
- Set usage alerts in Anthropic console

## Compliance

### Data Protection
- Encrypt credentials at rest
- Use HTTPS for all API calls
- Log access but not credentials
- Clear logs contain no sensitive data

### Platform ToS
- Human approval for all posts
- Respect rate limits
- No automated mass actions
- Clear bot identification

## Incident Response

### Credential Compromise
1. Immediately revoke compromised credentials
2. Generate new credentials
3. Update environment variables
4. Review access logs
5. Monitor for unauthorized activity

### Reporting
- Security issues: Report to project lead
- Platform API issues: Follow platform procedures
- Data breaches: Follow incident response plan
