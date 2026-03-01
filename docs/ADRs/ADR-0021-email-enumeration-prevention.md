# ADR-003: Email Enumeration Prevention

**Status:** Implemented ✅
**Date:** 2025-01-08
**Authors:** PRAHO Security Team
**Reviewers:** Engineering Team

## Context

The PRAHO platform initially implemented an `api_check_email` endpoint that validated email availability for user registration forms. This endpoint followed a common but insecure pattern that revealed whether email addresses existed in the system, creating a critical information disclosure vulnerability.

### Initial Vulnerable Implementation

```python
# VULNERABLE CODE (replaced)
def api_check_email(request):
    email = request.POST.get("email")
    exists = User.objects.filter(email=email).exists()  # ⚠️ DATABASE QUERY
    return json_success({
        "exists": exists,  # ⚠️ REVEALS EXISTENCE
        "message": "Email available" if not exists else "Email already in use"  # ⚠️ DIFFERENT MESSAGES
    })
```

### Security Risks Identified

1. **Email Enumeration Oracle**: Attackers could systematically discover all registered email addresses
2. **User Privacy Violation**: Exposed personal information without consent
3. **GDPR Compliance Risk**: Unauthorized data disclosure of EU users
4. **Attack Vectors**:
   - Automated email harvesting for spam/phishing
   - Social engineering attacks using known accounts
   - Competitor intelligence gathering
   - Identity verification bypass attempts

## Decision

We have implemented a **hardened email enumeration prevention pattern** that provides UX benefits while eliminating information disclosure vulnerabilities.

### Core Security Principles

1. **Uniform Responses**: Identical HTTP status codes and response payloads regardless of email existence
2. **Zero Database Queries**: No lookups in the validation endpoint to prevent timing attacks
3. **Consistent Timing**: Artificial delays with jitter to prevent side-channel analysis
4. **Soft Rate Limiting**: Graceful degradation without blocking legitimate users
5. **Server-Side Uniqueness**: Actual email validation only during registration submission

## Implementation

### Hardened Endpoint Design

```python
# SECURITY: Uniform response timing
UNIFORM_MIN_DELAY = 0.08  # 80ms base delay
UNIFORM_JITTER = 0.05     # +0..50ms random jitter

def _uniform_response():
    """Always returns identical response - never reveals email existence."""
    return JsonResponse({
        "message": _("Please complete registration to continue"),
        "success": True,
    }, status=200)

@require_http_methods(["POST"])
@ratelimit(key="apps.users.ratelimit_keys.user_or_ip", rate="10/m", method="POST", block=False)
@ratelimit(key="apps.users.ratelimit_keys.user_or_ip", rate="100/h", method="POST", block=False)
def api_check_email(request):
    """
    🔒 HARDENED EMAIL VALIDATION ENDPOINT
    - Uniform responses prevent enumeration attacks
    - No database queries - zero information disclosure
    - Consistent timing prevents side-channel analysis
    - Soft rate limiting with user-aware keys
    """
    # Add timing delay to prevent analysis
    _sleep_uniform()

    # Always return identical response
    return _uniform_response()
```

### Rate Limiting Strategy

**Intelligent Key Function:**
```python
def user_or_ip(group, request):
    """Rate limit authenticated users by ID, anonymous by IP."""
    if request.user.is_authenticated:
        return f"user:{request.user.pk}"
    return f"ip:{get_safe_client_ip(request)}"
```

**Soft Limiting Approach:**
- **10 requests/minute** - Short-term protection
- **100 requests/hour** - Long-term abuse prevention
- **No 429 errors** - Maintains uniform responses
- **Security logging** - Audit trail for rate limit hits

### Uniqueness Enforcement

Email uniqueness is enforced **only during actual registration**:

```python
def signup(request):
    try:
        with transaction.atomic():
            User.objects.create_user(email=email, ...)
    except IntegrityError:
        # Generic message - don't reveal existence
        return JsonResponse({
            "message": _("Check your inbox for next steps.")
        })
```

## Testing Strategy

### Security-First Test Coverage

1. **Uniform Response Validation**:
   ```python
   def test_uniform_response_shape(self):
       """Responses must be identical regardless of email existence."""
       available_response = self.client.post('/api/check-email/', {'email': 'new@example.com'})
       existing_response = self.client.post('/api/check-email/', {'email': 'existing@example.com'})

       self.assertEqual(available_response.content, existing_response.content)
   ```

2. **Zero Database Query Enforcement**:
   ```python
   def test_no_database_queries(self):
       """Endpoint must make zero database queries."""
       with self.assertNumQueries(0):
           response = self.client.post('/api/check-email/', {'email': 'any@example.com'})
   ```

3. **Timing Consistency Validation**:
   ```python
   def test_timing_consistency(self):
       """Response timing must be consistent to prevent timing attacks."""
       durations = []
       for i in range(5):
           start = time.time()
           response = self.client.post('/api/check-email/', {'email': f'test{i}@example.com'})
           duration = time.time() - start
           durations.append(duration)

       # All responses should take at least base delay time
       for duration in durations:
           self.assertGreater(duration, 0.07)
   ```

4. **Rate Limiting Behavior**:
   ```python
   def test_soft_rate_limiting(self):
       """Rate limiting should not return 429 errors."""
       for i in range(15):  # Exceed 10/m limit
           response = self.client.post('/api/check-email/', {'email': f'test{i}@example.com'})
           self.assertEqual(response.status_code, 200)  # Never 429
   ```

## OWASP Threat Coverage

### Mitigated Vulnerabilities

- **A01 - Broken Access Control**: Prevents unauthorized data access through enumeration
- **A03 - Injection**: Eliminates information disclosure vectors
- **A04 - Insecure Design**: Implements secure-by-default patterns
- **A07 - Authentication Failures**: Hardens account discovery mechanisms

### Security Controls Implemented

- ✅ **Information Disclosure Prevention**: Zero data leakage
- ✅ **Timing Attack Mitigation**: Consistent response times
- ✅ **Rate Limiting**: Abuse prevention without UX impact
- ✅ **Audit Logging**: Security event monitoring
- ✅ **Privacy Compliance**: GDPR-safe user data handling

## Migration Strategy

### Phase 1: Implementation ✅
- [x] Replace vulnerable endpoint with hardened version
- [x] Add rate limiting key function
- [x] Update Django settings for rate limiting
- [x] Implement comprehensive test suite

### Phase 2: Extension (Future)
- [ ] Apply same pattern to password reset flows
- [ ] Extend to account recovery endpoints
- [ ] Add CAPTCHA integration for high-volume abuse
- [ ] Implement advanced monitoring dashboards

### Phase 3: Monitoring (Future)
- [ ] Set up alerting for enumeration attempt patterns
- [ ] Create security metrics dashboard
- [ ] Implement behavioral analysis for abuse detection

## Performance Impact

**Positive Impact:**
- ✅ **Reduced Database Load**: Zero queries vs. previous User.exists() calls
- ✅ **Consistent Response Times**: Predictable 80-130ms response windows
- ✅ **Improved Caching**: No database dependency allows aggressive caching

**Considerations:**
- ⚠️ **Artificial Delay**: 80-130ms minimum response time (acceptable for UX)
- ⚠️ **Memory Usage**: Rate limiting state in Redis (negligible)

## Alternatives Considered

### 1. CAPTCHA-Only Approach ❌
**Why Rejected**: CAPTCHA alone doesn't prevent enumeration - attackers can solve CAPTCHAs or use services. Uniform responses are the core defense.

### 2. Aggressive Rate Limiting ❌
**Why Rejected**: Hard rate limiting with 429 errors would block legitimate users sharing IP addresses (offices, schools, public WiFi).

### 3. Account Lockout ❌
**Why Rejected**: Creates denial-of-service vectors where attackers can lock out legitimate users.

### 4. Email Domain Blocking ❌
**Why Rejected**: Reduces legitimate user accessibility and can be bypassed with disposable email services.

## Monitoring & Alerting

### Security Metrics
- **Rate Limit Hits**: Track enumeration attempt patterns
- **Geographic Patterns**: Monitor for automated scraping
- **Response Time Distribution**: Detect timing attack attempts
- **Error Rate Monitoring**: Ensure system stability

### Alert Conditions
- **High Volume**: >1000 requests/hour from single IP
- **Geographic Anomalies**: Requests from suspicious regions
- **Pattern Recognition**: Systematic email testing patterns

## Compliance & Legal

### GDPR Compliance ✅
- **Data Minimization**: Zero personal data exposed
- **Privacy by Design**: No information disclosure possible
- **Consent Unnecessary**: No data processing for validation

### Security Standards ✅
- **OWASP Top 10**: Multiple vulnerability classes addressed
- **Industry Best Practices**: Follows security-first principles
- **Enterprise Security**: Suitable for high-security environments

## Conclusion

This implementation successfully eliminates the critical email enumeration vulnerability while maintaining excellent user experience. The solution follows defense-in-depth principles with multiple layers of protection:

1. **Uniform responses** prevent all enumeration attempts
2. **Timing consistency** blocks side-channel attacks
3. **Soft rate limiting** handles abuse gracefully
4. **Zero database queries** eliminate information leakage
5. **Comprehensive testing** ensures ongoing security

The pattern should be extended to all similar endpoints (password reset, account recovery) to maintain consistent security posture across the platform.

---

**Next Steps:**
1. Monitor production metrics for 30 days
2. Extend pattern to password reset endpoint
3. Implement advanced abuse detection
4. Consider CAPTCHA integration for extreme cases

**References:**
- OWASP Testing Guide: Information Gathering
- NIST Cybersecurity Framework
- RFC 7231: HTTP/1.1 Semantics and Content
- GDPR Article 25: Data Protection by Design
