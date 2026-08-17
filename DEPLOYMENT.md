# Production Deployment Guide for PrivGuard

## Prerequisites

- Linux server (Ubuntu 22.04 LTS recommended)
- Docker and Docker Compose installed
- Domain name pointing to your server
- SSL certificate (Let's Encrypt recommended)
- API keys for chosen LLM providers

## Quick Start

### Option 1: Docker Deployment (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/privguard-prototype.git
   cd privguard-prototype
   ```

2. **Create production environment file**
   ```bash
   cp .env.production.example .env
   # Edit .env with your actual configuration
   nano .env
   ```

3. **Build and run with production Dockerfile**
   ```bash
   docker build -f Dockerfile.production -t privguard:latest .
   docker run -d \
     --name privguard \
     --restart unless-stopped \
     -p 8000:8000 \
     --env-file .env \
     privguard:latest
   ```

4. **Verify deployment**
   ```bash
   curl http://localhost:8000/api/health
   ```

### Option 2: Direct Python Deployment

1. **Install Python 3.11+**
   ```bash
   sudo apt update
   sudo apt install python3.11 python3.11-venv python3-pip
   ```

2. **Set up virtual environment**
   ```bash
   python3.11 -m venv /opt/privguard/venv
   source /opt/privguard/venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r backend/requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.production.example .env
   # Edit .env with your configuration
   ```

5. **Run with Gunicorn (production WSGI server)**
   ```bash
   pip install gunicorn
   gunicorn backend.app:app \
     --workers 4 \
     --worker-class uvicorn.workers.UvicornWorker \
     --bind 0.0.0.0:8000 \
     --timeout 120 \
     --access-logfile - \
     --error-logfile -
   ```

## Production Checklist

### Security

- [ ] Rotate all API keys
- [ ] Set `ENV=production` in environment
- [ ] Configure CORS for your domain only
- [ ] Enable HTTPS with TLS 1.2+
- [ ] Set up rate limiting (default: 60 req/min)
- [ ] Disable `/docs` and `/redoc` endpoints
- [ ] Use secrets manager for credentials
- [ ] Regular security updates

### Monitoring

- [ ] Set up health check monitoring
- [ ] Configure error tracking (Sentry)
- [ ] Set up log aggregation
- [ ] Monitor API usage and costs
- [ ] Configure alerts for high error rates

### Performance

- [ ] Enable response caching where appropriate
- [ ] Configure CDN for static assets
- [ ] Optimize database queries (if added)
- [ ] Load test before going live
- [ ] Monitor response times

### Backup & Recovery

- [ ] Document rollback procedures
- [ ] Test backup restoration
- [ ] Configure automated backups (if using DB)
- [ ] Define RTO/RPO objectives

## Nginx Reverse Proxy Setup

1. **Install Nginx**
   ```bash
   sudo apt install nginx
   ```

2. **Copy configuration**
   ```bash
   sudo cp nginx.conf.example /etc/nginx/sites-available/privguard
   sudo ln -s /etc/nginx/sites-available/privguard /etc/nginx/sites-enabled/
   ```

3. **Update domain names in config**
   ```bash
   sudo nano /etc/nginx/sites-available/privguard
   # Replace yourdomain.com with your actual domain
   ```

4. **Set up SSL with Let's Encrypt**
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
   ```

5. **Test and reload Nginx**
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## Environment Variables Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENV` | Environment (development/production) | development | No |
| `LLM_PROVIDER` | LLM provider (mock, gemini, chatgpt, etc.) | mock | No |
| `LLM_TIMEOUT_SECONDS` | Request timeout | 60 | No |
| `GEMINI_API_KEY` | Google Gemini API key | - | If using Gemini |
| `OPENAI_API_KEY` | OpenAI API key | - | If using ChatGPT |
| `ANTHROPIC_API_KEY` | Anthropic API key | - | If using Claude |
| `ALLOWED_ORIGINS` | CORS allowed origins (comma-separated) | localhost | Yes |
| `RATE_LIMIT_PER_MINUTE` | Rate limit per IP | 60 | No |
| `RATE_LIMIT_BURST` | Burst size for rate limiting | 10 | No |
| `LOG_LEVEL` | Logging level | INFO | No |

## Health Checks

The application provides a health endpoint:

```bash
curl https://yourdomain.com/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "provider_mode": "gemini",
  "version": "0.1.0"
}
```

## Monitoring & Alerts

### Recommended Metrics

- Response time (p50, p95, p99)
- Error rate (%)
- Requests per minute
- Rate limit hits
- LLM provider errors
- Privacy sanitization stats

### Log Management

Logs are written to stdout/stderr. For production:

```bash
# Using journald
sudo journalctl -u privguard -f

# Or redirect to file
gunicorn ... --access-logfile /var/log/privguard/access.log --error-logfile /var/log/privguard/error.log
```

## Troubleshooting

### Common Issues

**Issue**: 403 Forbidden from Google API
- **Solution**: Check API key is valid and has correct permissions
- **Solution**: Verify OAuth scopes include generative-language API

**Issue**: Rate limit exceeded
- **Solution**: Increase `RATE_LIMIT_PER_MINUTE` in .env
- **Solution**: Implement distributed rate limiting with Redis

**Issue**: CORS errors
- **Solution**: Add your domain to `ALLOWED_ORIGINS` in .env
- **Solution**: Ensure HTTPS is properly configured

**Issue**: High memory usage
- **Solution**: Reduce number of workers
- **Solution**: Monitor for memory leaks
- **Solution**: Add memory limits in Docker

### Getting Help

- Check logs: `docker logs privguard` or `journalctl -u privguard`
- Review production readiness checklist: `PRODUCTION_READINESS.md`
- Open an issue on GitHub with error details

## Updating

1. **Pull latest changes**
   ```bash
   git pull origin main
   ```

2. **Rebuild Docker image**
   ```bash
   docker build -f Dockerfile.production -t privguard:latest .
   docker stop privguard
   docker rm privguard
   docker run -d --name privguard --restart unless-stopped -p 8000:8000 --env-file .env privguard:latest
   ```

3. **Or restart Python service**
   ```bash
   sudo systemctl restart privguard
   ```

## Rollback Procedure

If something goes wrong after an update:

1. **Stop current version**
   ```bash
   docker stop privguard
   docker rm privguard
   ```

2. **Run previous version**
   ```bash
   docker run -d --name privguard --restart unless-stopped -p 8000:8000 --env-file .env privguard:previous-tag
   ```

3. **Verify functionality**
   ```bash
   curl https://yourdomain.com/api/health
   ```

## Security Best Practices

1. **Never commit secrets** - Use `.gitignore` and secrets managers
2. **Regular updates** - Keep dependencies updated for security patches
3. **Least privilege** - Run as non-root user (already configured)
4. **Network security** - Use firewalls and VPCs
5. **Audit logging** - Log all access attempts
6. **Input validation** - Already implemented, but review regularly
7. **HTTPS everywhere** - Never use HTTP in production
8. **Security headers** - Configured in both app and nginx

## Cost Optimization

- Monitor LLM API usage and set budgets
- Use caching for repeated prompts
- Implement request deduplication
- Choose cost-effective models for different use cases
- Set up billing alerts with cloud providers

---

**Last Updated**: 2026-06-25  
**Version**: 0.1.0  
**Maintainer**: PrivGuard Team
