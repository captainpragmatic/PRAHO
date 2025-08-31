# HTTPS Security Deployment Checklist for PragmaticHost

## 🔒 **HTTPS Security Implementation Guide**

This checklist ensures proper HTTPS security hardening deployment for the PRAHO Platform on PragmaticHost infrastructure.

---

## **Pre-Deployment Preparation**

### ✅ **1. Load Balancer/Proxy Configuration**
- [ ] **SSL Certificate Installed**: Verify SSL certificate is properly installed on load balancer
- [ ] **X-Forwarded-Proto Header**: Confirm load balancer sets `X-Forwarded-Proto: https` for HTTPS requests
- [ ] **Health Check Endpoints**: Ensure health checks work over HTTPS
- [ ] **HTTP to HTTPS Redirect**: Test that HTTP requests redirect to HTTPS at load balancer level

**Commands to verify:**
```bash
# Test X-Forwarded-Proto header
curl -H "X-Forwarded-Proto: https" https://app.pragmatichost.com/health/

# Test SSL certificate
openssl s_client -connect app.pragmatichost.com:443 -servername app.pragmatichost.com
```

### ✅ **2. DNS Configuration**
- [ ] **A Record**: `app.pragmatichost.com` points to load balancer IP
- [ ] **SSL Certificate Validity**: Certificate covers `app.pragmatichost.com`
- [ ] **Wildcard Support**: If using subdomains, verify wildcard certificate

### ✅ **3. Backup Current Configuration**
```bash
# Backup current settings
cp config/settings/prod.py config/settings/prod.py.backup.$(date +%Y%m%d)

# Backup environment variables
env | grep -E "(DJANGO|SECRET|DATABASE|REDIS)" > .env.backup.$(date +%Y%m%d)
```

---

## **Environment-Specific Deployment**

### 🚀 **Production Deployment** (app.pragmatichost.com)

#### **Phase 1: Initial HTTPS Configuration**
- [ ] **Deploy HTTPS Settings**: Deploy production settings with HTTPS hardening
- [ ] **Verify ALLOWED_HOSTS**: Ensure `ALLOWED_HOSTS = ["app.pragmatichost.com"]`
- [ ] **Set CSRF_TRUSTED_ORIGINS**: `CSRF_TRUSTED_ORIGINS = ["https://app.pragmatichost.com"]`

#### **Phase 2: SSL Redirect Testing**
- [ ] **Test Without SSL Redirect**: First deploy with `SECURE_SSL_REDIRECT = False`
- [ ] **Verify HTTPS Works**: Test all major application flows over HTTPS
- [ ] **Check Security Headers**: Verify security headers are present

**Test Commands:**
```bash
# Test HTTPS functionality
curl -I https://app.pragmatichost.com/auth/login/

# Check security headers
curl -I https://app.pragmatichost.com/ | grep -E "(X-Content-Type|X-Frame|X-XSS|Strict-Transport)"

# Test Django system checks
python manage.py check --settings=config.settings.prod --deploy
```

#### **Phase 3: Enable SSL Redirect**
- [ ] **Enable SSL Redirect**: Set `SECURE_SSL_REDIRECT = True`
- [ ] **Test HTTP Redirects**: Verify HTTP requests redirect to HTTPS
- [ ] **Verify No Redirect Loops**: Ensure proper `X-Forwarded-Proto` handling

**Test Commands:**
```bash
# Test HTTP to HTTPS redirect
curl -I http://app.pragmatichost.com/ | grep -i location

# Verify no redirect loops
curl -L -I http://app.pragmatichost.com/auth/login/
```

#### **Phase 4: HSTS Rollout**
- [ ] **Short HSTS First**: Start with `SECURE_HSTS_SECONDS = 300` (5 minutes)
- [ ] **Monitor for 24 Hours**: Verify no issues with short HSTS
- [ ] **Increase to Production**: Set `SECURE_HSTS_SECONDS = 31536000` (1 year)

**HSTS Verification:**
```bash
# Check HSTS header
curl -I https://app.pragmatichost.com/ | grep -i strict-transport-security

# Test HSTS policy in browser
# Visit https://app.pragmatichost.com and check Network tab
```

### 🧪 **Staging Deployment** (staging.pragmatichost.com)

#### **Staging Configuration Validation**
- [ ] **Deploy Staging Settings**: Use staging-specific HTTPS configuration
- [ ] **Shorter HSTS**: `SECURE_HSTS_SECONDS = 3600` (1 hour)
- [ ] **No Subdomain HSTS**: `SECURE_HSTS_INCLUDE_SUBDOMAINS = False`
- [ ] **Test SSL Configuration**: Full application testing over HTTPS

### 🔧 **Development Environment**

#### **Local Development Verification**
- [ ] **HTTP Configuration**: Ensure development uses HTTP properly
- [ ] **No SSL Redirect**: Verify `SECURE_SSL_REDIRECT = False`
- [ ] **Insecure Cookies**: Confirm `SESSION_COOKIE_SECURE = False`

---

## **Security Validation**

### ✅ **1. Django System Checks**
```bash
# Run all security checks
python manage.py check --settings=config.settings.prod --deploy

# Check specific HTTPS security
python manage.py check --tag security --settings=config.settings.prod
```

### ✅ **2. Security Headers Validation**
```bash
# Check all security headers
curl -I https://app.pragmatichost.com/ | grep -E "(Content-Security-Policy|X-Content-Type|X-Frame|X-XSS|Referrer-Policy|Strict-Transport)"

# Verify CSP allows trusted CDNs
curl -I https://app.pragmatichost.com/ | grep "Content-Security-Policy" | grep -E "(unpkg.com|cdn.tailwindcss.com)"
```

### ✅ **3. Cookie Security Testing**
```bash
# Check session cookie security
curl -c cookies.txt https://app.pragmatichost.com/auth/login/
grep -E "(Secure|HttpOnly|SameSite)" cookies.txt
```

### ✅ **4. Run Test Suite**
```bash
# Run HTTPS security tests
python manage.py test tests.common.test_https_security --settings=config.settings.prod

# Run all security tests
python manage.py test --pattern="*security*" --settings=config.settings.prod
```

---

## **Monitoring & Verification**

### ✅ **1. Application Functionality Testing**

#### **Critical User Flows**
- [ ] **User Login/Logout**: Test authentication flows over HTTPS
- [ ] **Customer Dashboard**: Verify dashboard loads properly
- [ ] **Billing Operations**: Test invoice generation and payment flows
- [ ] **Staff Interface**: Verify staff can access admin functions
- [ ] **API Endpoints**: Test API functionality with HTTPS

#### **Browser Compatibility**
- [ ] **Chrome**: Test latest Chrome browser
- [ ] **Firefox**: Test latest Firefox browser  
- [ ] **Safari**: Test Safari (if supporting macOS users)
- [ ] **Mobile**: Test mobile browsers

### ✅ **2. Performance Monitoring**
- [ ] **Response Times**: Monitor for HTTPS performance impact
- [ ] **SSL Handshake Time**: Verify reasonable SSL negotiation times
- [ ] **CDN Compatibility**: Ensure CDN works with new security headers

### ✅ **3. Log Monitoring**
```bash
# Monitor application logs for HTTPS issues
tail -f /var/log/pragmatichost/app.log | grep -i -E "(ssl|https|redirect|security)"

# Check for SSL-related errors
grep -i "ssl" /var/log/pragmatichost/app.log | tail -20
```

---

## **Rollback Plan**

### 🔄 **Emergency Rollback Procedure**

If critical issues are discovered:

#### **1. Immediate Rollback**
```bash
# Disable SSL redirect immediately
export SECURE_SSL_REDIRECT=False
systemctl restart pragmatichost-app

# Or deploy previous settings file
cp config/settings/prod.py.backup config/settings/prod.py
systemctl restart pragmatichost-app
```

#### **2. HSTS Rollback**
```bash
# Reduce HSTS to minimum (if enabled)
export SECURE_HSTS_SECONDS=0
systemctl restart pragmatichost-app
```

**Note**: HSTS cannot be immediately disabled for users who already received the header. Plan HSTS rollout carefully.

#### **3. DNS/Load Balancer Rollback**
- [ ] Revert load balancer SSL configuration
- [ ] Temporarily allow HTTP traffic if needed
- [ ] Coordinate with infrastructure team

---

## **Post-Deployment Verification**

### ✅ **24-Hour Monitoring Checklist**

#### **Day 1: Initial Monitoring**
- [ ] **Error Logs**: No SSL-related errors in application logs
- [ ] **User Reports**: No user complaints about accessibility
- [ ] **Performance**: Response times within acceptable range
- [ ] **Security Scan**: Run security scan to verify headers

#### **Week 1: Stability Monitoring**
- [ ] **SSL Certificate**: Verify certificate auto-renewal works
- [ ] **HSTS Policy**: Confirm HSTS working in browsers
- [ ] **Search Engines**: Monitor for HTTPS indexing by search engines
- [ ] **CDN Integration**: Verify CDN properly handles security headers

### ✅ **Security Scanning**
```bash
# Use external security scanning tools
# Example: Mozilla Observatory
curl -X POST https://http-observatory.security.mozilla.org/api/v1/analyze?host=app.pragmatichost.com

# SSL Labs test
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=app.pragmatichost.com
```

---

## **Documentation & Communication**

### ✅ **Team Communication**
- [ ] **Notify Support Team**: Brief support staff on HTTPS changes
- [ ] **Update Documentation**: Update any HTTP references to HTTPS
- [ ] **API Documentation**: Update API documentation with HTTPS URLs
- [ ] **Monitoring Alerts**: Update monitoring to expect HTTPS

### ✅ **Customer Communication** (if needed)
- [ ] **Service Notice**: If maintenance window required
- [ ] **URL Updates**: Communicate any bookmark updates needed
- [ ] **Integration Updates**: Notify customers with API integrations

---

## **Long-Term Security Maintenance**

### ✅ **Ongoing Security Tasks**

#### **Monthly**
- [ ] **SSL Certificate Monitoring**: Verify certificates haven't expired
- [ ] **Security Headers Review**: Audit security header effectiveness
- [ ] **HSTS Policy Review**: Confirm HSTS policy appropriate

#### **Quarterly**
- [ ] **Security Scanning**: Run comprehensive security scans
- [ ] **Django Security Updates**: Review Django security releases
- [ ] **TLS Configuration Review**: Update TLS settings as needed

#### **Annually**
- [ ] **HTTPS Configuration Audit**: Full review of HTTPS implementation
- [ ] **Certificate Strategy Review**: Evaluate certificate provider/strategy
- [ ] **Security Policy Updates**: Update security policies as needed

---

## **Environment Variables Reference**

### **Production HTTPS Settings**
```bash
# Required for HTTPS security
export SECURE_SSL_REDIRECT=True
export SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https")
export SESSION_COOKIE_SECURE=True
export CSRF_COOKIE_SECURE=True
export SECURE_HSTS_SECONDS=31536000
export SECURE_HSTS_INCLUDE_SUBDOMAINS=True
export SECURE_HSTS_PRELOAD=False

# Domain configuration
export ALLOWED_HOSTS="app.pragmatichost.com"
export CSRF_TRUSTED_ORIGINS="https://app.pragmatichost.com"
```

### **Staging HTTPS Settings**
```bash
# Staging-specific HTTPS config
export SECURE_SSL_REDIRECT=True
export SECURE_HSTS_SECONDS=3600  # Shorter duration
export SECURE_HSTS_INCLUDE_SUBDOMAINS=False  # More flexible
export ALLOWED_HOSTS="staging.pragmatichost.com"
export CSRF_TRUSTED_ORIGINS="https://staging.pragmatichost.com"
```

---

## **Emergency Contacts**

- **DevOps Team**: Contact for load balancer/SSL issues
- **Infrastructure Team**: DNS and certificate issues  
- **Security Team**: Security policy questions
- **Development Team**: Application-specific HTTPS issues

---

## **Success Criteria**

✅ **Deployment is successful when:**

1. **All HTTP traffic redirects to HTTPS** without loops
2. **All security headers present** and properly configured
3. **Django system checks pass** without security warnings
4. **Application functionality intact** over HTTPS
5. **SSL Labs rating A or A+** (external validation)
6. **No increase in error rates** after deployment
7. **HSTS policy active** and working in browsers
8. **CDN and security headers compatible**

---

**📋 Checklist Completed By**: _________________ **Date**: _________________

**🔍 Reviewed By**: _________________ **Date**: _________________

**✅ Approved for Production**: _________________ **Date**: _________________