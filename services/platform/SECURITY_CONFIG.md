# PRAHO Platform Security Configuration

This document outlines critical security configurations required for production deployment of the PRAHO platform.

## 🔒 Price Sealing Security

### PRICE_SEALING_SECRET Configuration

Each portal deployment **MUST** have its own unique `PRICE_SEALING_SECRET` environment variable to prevent cross-portal token attacks.

#### Generate a new secret:

```bash
# Generate a secure 64-character secret
python manage.py generate_price_sealing_secret

# Or generate with custom length (minimum 32)
python manage.py generate_price_sealing_secret --length 128
```

#### Set the environment variable:

```bash
# In your .env file
PRICE_SEALING_SECRET=your_generated_secret_here

# Or export directly
export PRICE_SEALING_SECRET=your_generated_secret_here
```

### Security Notes:

- ⚠️ **Each portal instance MUST have a unique secret**
- 🚫 **Never commit secrets to version control**
- 🔄 **Rotate secrets periodically**
- 💾 **Use secure secret storage (AWS Secrets Manager, HashiCorp Vault, etc.)**
- 📏 **Minimum length: 32 characters, recommended: 64+**

## 🛡️ Multi-Tenancy Security

When deploying multiple portal instances:

1. Each portal gets its own `PRICE_SEALING_SECRET`
2. Tokens from Portal A cannot be used in Portal B
3. IP address binding prevents token theft
4. 60-second token expiry prevents replay attacks

## 🚨 Security Warnings

If you see this warning in logs:
```
🚨 [Security] Using Django SECRET_KEY for price sealing. Configure PRICE_SEALING_SECRET environment variable for production.
```

**Action Required**: Generate and configure a dedicated `PRICE_SEALING_SECRET` immediately.

## 📋 Production Security Checklist

- [ ] `PRICE_SEALING_SECRET` configured and unique per portal
- [ ] Secret is at least 32 characters long
- [ ] Secret is stored securely (not in code)
- [ ] Django `SECRET_KEY` is separate and secure
- [ ] SSL/TLS enabled for all API endpoints
- [ ] Rate limiting configured
- [ ] Session security middleware active
- [ ] CSP headers configured
- [ ] Regular security audits scheduled

## 🔧 Development vs Production

### Development:
- Can use Django `SECRET_KEY` (with warnings)
- Shorter token expiry acceptable

### Production:
- **MUST** use dedicated `PRICE_SEALING_SECRET`
- Implement proper secret rotation
- Monitor security logs
- Use secure secret storage
