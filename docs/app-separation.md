# PRAHO Platform App Separation Architecture

## Overview

This document outlines the architecture for separating PRAHO into distinct applications for enhanced security, following the principle of complete isolation between customer-facing and administrative systems.

## Architecture Decision: Two-App Strategy

After analyzing multiple deployment options, the **Two-App Strategy** has been selected for PRAHO Platform due to the security-critical nature of hosting provider operations and Romanian business compliance requirements.

### Two-App Architecture

```
praho-admin/          # Staff-only Django app
├── VPN-only deployment
├── Full database access with all models
├── Virtualmin integration
├── Financial reporting
├── API endpoints for customer app
├── Romanian validators (CUI, VAT)
├── Audit logging system
└── High-security hardening

praho-customer/       # Customer-facing Django app  
├── Public internet exposure
├── Zero database access (API-only)
├── Customer self-service UI
├── API client for admin communication
├── Duplicated validators (for form validation)
├── High-availability focus
└── DDoS protection
```

### Why Two Apps, Not Three?

**No shared library (praho-core) needed.** Build and maintain only two codebases: `praho-admin` and `praho-customer`. Do not introduce a third shared library unless duplication becomes a proven pain point. This approach:

- ✅ **Maximizes development velocity** - No package management overhead
- ✅ **Minimizes complexity** - Two repos instead of three
- ✅ **Aligns with best practices** from large-scale SaaS platforms (Spotify, Netflix, Uber)
- ✅ **Accepts deliberate duplication** of ~500 lines of shared code (validators, constants)

## 📊 Current State Analysis

### ✅ What We Already Have (Can Keep in praho-admin)

1. **Full Django Application Stack** - All 11 apps with complete models, ready for admin operations
2. **Database Models** - Complete schema that would remain in admin for full DB access
3. **Romanian Business Logic** - CUI validation, VAT calculations, e-Factura ready
4. **Audit System** - Comprehensive audit trails already in place
5. **User Authentication** - Email-based auth with 2FA support
6. **Admin Interfaces** - Full Django admin customization
7. **Service Layer Pattern** - Already using `services.py`, `repos.py` pattern (ADR-0012)
8. **Virtualmin Integration** - Already implemented in provisioning app

### 🚫 What We Need to Add/Build

#### 1. **API Layer for Customer App** (2-3 weeks)
```python
# Need to create apps/api/ with endpoints like:
/api/customers/{id}/invoices/
/api/customers/{id}/services/
/api/customers/{id}/domains/
/api/customers/{id}/tickets/
```

#### 2. **Inter-Service Authentication Middleware** (3-4 days)
```python
# New middleware for validating customer app requests
class CustomerAppOnlyMiddleware:
    def __call__(self, request):
        if request.path.startswith('/api/'):
            # Validate X-Service-Auth header
            # Check source IP is from customer app
```

#### 3. **Rate Limiting Infrastructure** (2-3 days)
- Add django-ratelimit or similar
- Configure per-endpoint limits
- Add monitoring/alerting for anomalies

#### 4. **API Serializers** (1 week)
- Create Django REST Framework serializers for all models
- Ensure proper field filtering (no sensitive data exposure)
- Version the API from day one

### 🔄 What to Migrate to praho-customer

#### Phase 1: Customer-Facing Views (2 weeks)
**Move these view patterns:**
- Customer self-service dashboards
- Invoice viewing (read-only)
- Ticket creation/viewing
- Domain management UI
- Service status pages

**Keep in admin:**
- All Django admin views
- Staff dashboards
- Financial reports
- System settings
- Server management

#### Phase 2: Templates & Static Files (1 week)
**Move to customer:**
- Customer portal templates
- Public-facing CSS/JS
- Marketing pages

**Keep in admin:**
- Admin templates
- Staff dashboard UI
- Internal tools UI

#### Phase 3: Duplicate Small Shared Code (2-3 days)
**Copy to customer (deliberate duplication):**
```python
# ~500 lines total to duplicate:
praho-admin/apps/common/validators.py → praho-customer/apps/validators.py
praho-admin/apps/common/constants.py → praho-customer/apps/constants.py
praho-admin/apps/common/formatters.py → praho-customer/apps/formatters.py
```

### 🗑️ What to Remove/Refactor

1. **Direct Customer Access Patterns** (1 week)
   - Remove any public-facing URLs from admin
   - Remove customer login flows (move to customer app)
   - Remove self-registration logic

2. **Session Sharing Logic** (2-3 days)
   - Remove any cross-user session management
   - Each app handles its own sessions

### 🏗️ Architecture Changes Needed

#### 1. **Network Security Configuration** (3-4 days)
```python
# settings/production.py changes:
ALLOWED_HOSTS = ['10.0.1.5', 'admin.internal.domain']
TRUSTED_CUSTOMER_IPS = ['10.0.1.10']
INTER_SERVICE_SECRET = env('INTER_SERVICE_SECRET')
```

#### 2. **Logging & Monitoring Enhancement** (3-4 days)
- Add structured logging for all API calls
- Implement audit trail for inter-service communication
- Add Prometheus metrics for API performance

#### 3. **API Client Service in Customer App** (1 week)
```python
# praho-customer/services/admin_api.py
class AdminAPIClient:
    """Single point of integration with admin app"""
    BASE_URL = "http://10.0.1.5:8000/api"
    
    def get_customer_invoices(self, customer_id):
        # All admin communication through this service
```

## 🔒 Security Analysis

### Security Strengths of Separate Apps

- ✅ **True Isolation**: Zero shared code paths between admin and customer
- ✅ **Independent Security Posture**: Different dependencies, update cycles, hardening
- ✅ **Blast Radius Control**: Customer portal breach cannot touch admin systems
- ✅ **Different Threat Models**: Can optimize security per app's risk profile
- ✅ **Supply Chain Isolation**: Different requirements.txt files

### Real-World Threat Mitigation

#### Supply Chain Attack (SolarWinds-style)
- **Separate Apps**: Could isolate to customer app, admin remains secure
- **Single App**: Compromised package affects both admin and customer instantly

#### Zero-Day in Django/Framework  
- **Separate Apps**: Different Django versions possible, staggered exposure
- **Single App**: Both systems vulnerable simultaneously

#### Logic Bug in Customer Portal
- **Separate Apps**: Customer app literally cannot access admin functions - impossible by design
- **Single App**: Complex conditional logic creates potential privilege escalation paths

## 🏗️ Technical Architecture

### Database Security Architecture - API Gateway Pattern

```
Internet
    ↓
praho-customer/  (public-facing)
    ↓ (HTTPS API calls)
praho-admin/     (VPN-protected)  
    ↓ (direct database access)
PostgreSQL Database
```

**Flow:**
1. Customer logs into `app.pragmatichost.com`
2. Customer app makes API calls to `admin.pragmatichost.com/api/`
3. Admin app validates customer identity and permissions
4. Admin app queries database and returns filtered results

### Network Security Implementation

#### Server-to-Server API Communication
API requests happen **server-side** from customer Django app to admin Django app:

```
User Browser → Customer App Server → Admin API Server → Database
(public)       (public IP)           (private IP)
```

#### Network Topology
```
Internet Users
    ↓
[Load Balancer - Public IP]
    ↓
Customer App (DMZ)
  - Public: 185.x.x.x
  - Private: 10.0.1.10
    ↓
[FIREWALL - Only allows 10.0.1.10]
    ↓
Admin App (Private Network)
  - Private: 10.0.1.5
  - NO public IP
    ↓
PostgreSQL (Private)
  - Private: 10.0.1.2
```

### Inter-Service Authentication

#### Option 1: Shared Secret (Simple)
```python
# Both apps share a secret key
API_SECRET = "long-random-string-stored-in-env"

# Customer app sends it
headers = {"X-Service-Auth": API_SECRET}

# Admin app validates it
if request.headers.get('X-Service-Auth') != settings.API_SECRET:
    return HttpResponseForbidden()
```

#### Option 2: JWT Tokens (Recommended)
```python
# Customer app generates JWT
token = jwt.encode({
    'customer_id': customer_id,
    'exp': datetime.now() + timedelta(minutes=5)
}, SECRET_KEY)

# Admin app validates JWT
try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    customer_id = payload['customer_id']
except jwt.ExpiredSignatureError:
    return HttpResponse('Token expired', status=401)
```
## 📅 Implementation Timeline

### Phase 1: Foundation (Week 1-2)
- [ ] Set up API framework in current praho-admin
- [ ] Implement basic authentication middleware
- [ ] Create first read-only API endpoints
- [ ] Add comprehensive logging

### Phase 2: API Development (Week 3-4)
- [ ] Build customer data API endpoints
- [ ] Add serializers and pagination
- [ ] Implement rate limiting
- [ ] Add comprehensive API tests

### Phase 3: Customer App Creation (Week 5-6)
- [ ] Initialize `praho-customer` Django app
- [ ] Copy validators/constants (~500 lines)
- [ ] Implement API client service layer
- [ ] Move customer templates

### Phase 4: Security Hardening (Week 7)
- [ ] Configure network isolation
- [ ] Add JWT token authentication
- [ ] Implement API versioning
- [ ] Security audit & penetration testing

### Phase 5: Deployment (Week 8)
- [ ] Set up separate CI/CD pipelines
- [ ] Configure VPN for admin access
- [ ] Deploy customer app to DMZ
- [ ] Monitor and optimize

## 🚨 Critical Decisions Needed

1. **API Framework**: Django REST Framework vs Django Ninja vs FastAPI sidecar
2. **Authentication**: JWT vs OAuth2 vs Shared Secret
3. **Deployment**: Kubernetes vs Docker Compose vs traditional VMs
4. **Database Access**: Keep single DB or read replicas for customer app?

## 💰 Resource Requirements

- **Team**: 2-3 senior developers for 8 weeks
- **Infrastructure**: Additional servers for customer app
- **Tools**: API gateway (Kong/Traefik), monitoring (Grafana/Prometheus)
- **Security**: Penetration testing budget (~$5-10k)

## ⚠️ Risk Factors

1. **Data Consistency**: Need careful transaction handling across API boundary
2. **Performance**: API calls add latency vs direct DB access
3. **Migration**: Zero-downtime migration strategy needed
4. **Duplication Drift**: Validators in both apps could diverge (mitigate with tests)

## 🎯 Quick Wins (Do First)

1. **Start with read-only APIs** - Lower risk, immediate value
2. **Use existing service layer** - Your ADR-0012 pattern makes this easier
3. **Keep single database initially** - Simplify data consistency
4. **Leverage Django REST Framework** - Mature, well-documented
5. **Duplicate validators fearlessly** - It's only ~500 lines, not worth complexity

## 📝 Recommended Next Steps

1. **Week 1**: Create proof-of-concept API for invoices
2. **Week 2**: Build minimal praho-customer with invoice viewing
3. **Week 3**: Add authentication and test in staging
4. **Week 4**: Plan full migration based on POC learnings

## 🎉 The Good News

Your current architecture with the service layer pattern (ADR-0012) and modular app structure makes this separation very feasible. The main effort will be in creating the API layer and ensuring proper security boundaries. By avoiding a third shared codebase, you'll ship faster and maintain simpler.

**Total Estimated Timeline: 7-8 weeks** with a team of 2-3 senior developers (saved 1-2 weeks by skipping praho-core complexity).
## 🏢 Deployment Architecture

### Subdomain Structure

#### VPN-Protected (Staff Only)
```
admin.pragmatichost.com
├── Django Admin
├── Staff Dashboard  
├── System Settings
├── Server Management (Virtualmin)
├── Audit Logs
├── Financial Reports
└── Customer Management Tools
```

#### Public-Facing (Customer Access)
```
app.pragmatichost.com
├── Customer Login/Dashboard
├── Invoice Viewing
├── Service Status
├── Domain Management  
├── Ticket Creation
└── Account Settings
```

## 📋 Update Recommendation for copilot-instructions.md

Add this section:
```markdown
## Architecture Decision: Two-App Strategy (No Shared Library)
- praho-admin: Full Django app with database access and API endpoints
- praho-customer: Lightweight Django app with API client only  
- Shared code: Deliberately duplicated (~500 lines) until proven need
- Models: Always live in admin, never shared
- API contracts: Defined via serializers in admin, consumed by customer
- Validators: Duplicated between apps (acceptable for ~500 lines)
```

## Conclusion

For PRAHO Platform, a Romanian hosting provider handling CUI data, VAT information, and server infrastructure, the security benefits of complete application separation significantly outweigh the maintenance overhead. 

The admin system managing Virtualmin servers and customer financial data should never share code paths with the public-facing customer portal. This architecture provides true security isolation while maintaining shared business logic through deliberate duplication of small shared code (validators, constants) between the two apps. Models and business logic always live in `praho-admin` and are never shared.

**Implementation recommendation**: Build and maintain only two codebases: `praho-admin` and `praho-customer`. Do not introduce a third shared library unless duplication becomes a proven pain point. This approach maximizes development velocity, minimizes complexity, and aligns with best practices from large-scale SaaS platforms. Extract shared code only if and when the cost of duplication exceeds the cost of coordination.