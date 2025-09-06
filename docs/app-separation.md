# PRAHO Platform App Separation Architecture

## Overview

This document outlines the architecture for separating PRAHO into distinct applications for enhanced security, following the principle of complete isolation between customer-facing and administrative systems.

## Architecture Decision: Two-App Strategy

After analyzing multiple deployment options, the **Two-App Strategy** has been selected for PRAHO Platform due to the security-critical nature of hosting provider operations and Romanian business compliance requirements.

### Monorepo Service Architecture

```
PRAHO/                          # Beautiful monorepo root
├── services/
│   ├── platform/               # Staff-only Django service (admin/backend)
│   │   ├── apps/               # All business logic apps
│   │   ├── config/             # Django settings
│   │   ├── manage.py           # Django management
│   │   ├── requirements/       # Platform-specific deps
│   │   └── VPN-only deployment with full database access
│   │
│   └── portal/                 # Customer-facing Django service (client area)
│       ├── apps/               # Customer-facing apps only
│       ├── config/             # Django settings
│       ├── manage.py           # Django management  
│       ├── requirements/       # Portal-specific deps (no DB drivers)
│       └── Public internet exposure, API-only
│
├── Makefile                    # Unified build commands
├── docker-compose.yml          # Multi-service orchestration
├── .github/workflows/          # Shared CI/CD pipelines
├── docs/                       # Shared documentation
└── tests/integration/          # Cross-service integration tests
```

### Why Beautiful Monorepo with Two Services?

**No separate repositories or shared library needed.** Build and maintain a single beautiful monorepo with two complete Django services under `services/` folder. This approach:

- ✅ **Maximizes development velocity** - Single repo, unified tooling, shared CI/CD
- ✅ **Minimizes complexity** - One repo with clear service boundaries
- ✅ **Enables atomic changes** - Cross-service changes in single commit/PR
- ✅ **Aligns with modern practices** - Google, Facebook, Uber use monorepos
- ✅ **Accepts deliberate duplication** of ~500 lines of shared code (validators, constants)
- ✅ **Shared development tooling** - One Makefile, one Docker setup, unified linting

## 📊 Current State Analysis

### ✅ What We Already Have (Can Keep in Platform)

1. **Full Django Application Stack** - All 11 apps with complete models, ready for admin operations
2. **Database Models** - Complete schema that would remain in admin for full DB access
3. **Romanian Business Logic** - CUI validation, VAT calculations, e-Factura ready
4. **Audit System** - Comprehensive audit trails already in place
5. **User Authentication** - Email-based auth with 2FA support
6. **Admin Interfaces** - Full Django admin customization
7. **Service Layer Pattern** - Already using `services.py`, `repos.py` pattern (ADR-0012)
8. **Virtualmin Integration** - Already implemented in provisioning app

## 🏗️ **Monorepo Architecture Benefits**

### ✅ **What This Monorepo Structure Gives Us**

1. **🔄 Atomic Changes** - Update API contract and consumer in single PR/commit
2. **🛠️ Unified Tooling** - One Makefile, shared linting, common Docker setup
3. **📊 Shared CI/CD** - Single pipeline can test both services together  
4. **📚 Centralized Documentation** - All docs in one place, cross-references work
5. **🔍 Global Search** - Find all usage of a function across both services instantly
6. **🧪 Integration Testing** - Easy to write tests that span both services
7. **📦 Dependency Management** - Clear view of all dependencies across services
8. **🔒 Security Scanning** - Unified vulnerability scanning across entire codebase

### 🎯 **Best of Both Worlds**

This approach gives us:
- ✅ **Service Isolation** - Services can't directly import each other (different Python paths)
- ✅ **Development Velocity** - No separate repo coordination needed
- ✅ **Deployment Flexibility** - Can deploy services independently 
- ✅ **Clear Boundaries** - Physical separation under `services/` folder
- ✅ **Operational Simplicity** - One repo to clone, one place for issues/PRs

### 🚫 What We Need to Add/Build

#### 1. **API Layer for Portal Service** (2-3 weeks)
**Decision: Django REST Framework with clean `/api/` URLs**
```python
# Create services/platform/apps/api/ with endpoints like:
/api/customers/                    # Customer management
/api/customers/{id}/               # Customer details
/api/billing/invoices/             # Invoice listing
/api/billing/invoices/{id}/        # Invoice details
/api/tickets/                      # Support tickets
/api/tickets/{id}/                 # Ticket details
/api/provisioning/services/        # Hosting services
/api/domains/                      # Domain management
```

**Structure:**
```python
services/platform/apps/
├── api/                           # Main API app
│   ├── urls.py                   # Clean URL routing
│   ├── customers/                # Customer API views
│   ├── billing/                  # Billing API views
│   ├── tickets/                  # Tickets API views
│   ├── provisioning/             # Services API views
│   ├── domains/                  # Domains API views
│   ├── serializers/              # DRF serializers
│   ├── permissions/              # API permissions
│   └── middleware/               # API-specific middleware
```

#### 2. **Inter-Service Authentication Middleware** (3-4 days)
```python
# New middleware for validating portal service requests
class PortalServiceOnlyMiddleware:
    def __call__(self, request):
        if request.path.startswith('/api/'):
            # Validate X-Service-Auth header
            # Check source IP is from portal service
```

#### 3. **Rate Limiting Infrastructure** (2-3 days)
- Add django-ratelimit or similar
- Configure per-endpoint limits
- Add monitoring/alerting for anomalies

#### 4. **API Serializers** (1 week)
- Create Django REST Framework serializers for all models
- Ensure proper field filtering (no sensitive data exposure)
- Start with clean `/api/` URLs (no versioning until needed)
- Implement proper permission classes for each endpoint

### 🔄 What to Migrate to Portal

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
**Copy to portal (deliberate duplication):**
```python
# ~500 lines total to duplicate:
services/platform/apps/common/validators.py → services/portal/apps/validators.py
services/platform/apps/common/constants.py → services/portal/apps/constants.py
services/platform/apps/common/formatters.py → services/portal/apps/formatters.py
```

### 🗑️ What to Remove/Refactor

1. **Direct Customer Access Patterns** (1 week)
   - Remove any public-facing URLs from admin
   - Remove customer login flows (move to portal app)
   - Remove self-registration logic

2. **Session Sharing Logic** (2-3 days)
   - Remove any cross-user session management
   - Each app handles its own sessions

### 🏗️ Architecture Changes Needed

#### 1. **Network Security Configuration** (3-4 days)
```python
# settings/production.py changes:
ALLOWED_HOSTS = ['10.0.1.5', 'platform.pragmatichost.com']
TRUSTED_PORTAL_IPS = ['10.0.1.10']
INTER_SERVICE_SECRET = env('INTER_SERVICE_SECRET')
```

#### 2. **Logging & Monitoring Enhancement** (3-4 days)
- Add structured logging for all API calls
- Implement audit trail for inter-service communication
- Add Prometheus metrics for API performance

#### 3. **API Client Service in Portal App** (1 week)
```python
# services/portal/apps/api_client/services.py
class PlatformAPIClient:
    """Single point of integration with platform service"""
    BASE_URL = "http://10.0.1.5:8700/api"
    
    def get_customer_invoices(self, customer_id):
        # All platform communication through this service
```

## 🔒 Security Analysis

### Security Strengths of Separate Services

- ✅ **True Isolation**: Zero shared code paths between platform and portal services
- ✅ **Independent Security Posture**: Different dependencies, update cycles, hardening
- ✅ **Blast Radius Control**: Portal service breach cannot touch platform systems
- ✅ **Different Threat Models**: Can optimize security per service's risk profile
- ✅ **Supply Chain Isolation**: Separate requirements.txt files per service
- ✅ **Monorepo Benefits**: Unified security tooling, shared vulnerability scanning

### Real-World Threat Mitigation

#### Supply Chain Attack (SolarWinds-style)
- **Separate Services**: Could isolate to portal service, platform remains secure
- **Single Service**: Compromised package affects both platform and portal instantly

#### Zero-Day in Django/Framework  
- **Separate Services**: Different Django versions possible, staggered exposure
- **Single Service**: Both systems vulnerable simultaneously

#### Logic Bug in Customer Portal
- **Separate Services**: Portal service literally cannot access platform functions - impossible by design
- **Single Service**: Complex conditional logic creates potential privilege escalation paths

## 🏗️ Technical Architecture

### Database Security Architecture - API Gateway Pattern

```
Internet
    ↓
services/portal/     (public-facing service)
    ↓ (HTTPS API calls)
services/platform/   (VPN-protected service)  
    ↓ (direct database access)
PostgreSQL Database
```

**Flow:**
1. Customer logs into `portal.pragmatichost.com`
2. Portal service makes API calls to `platform.pragmatichost.com/api/`
3. Platform service validates customer identity and permissions
4. Platform service queries database and returns filtered results

### Network Security Implementation

#### Server-to-Server API Communication
API requests happen **server-side** from portal Django service to platform Django service:

```
User Browser → Portal Service → Platform Service → Database
(public)       (public IP)     (private IP)
```

#### Network Topology
```
Internet Users
    ↓
[Load Balancer - Public IP]
    ↓
Portal Service (DMZ)
  - Public: 185.x.x.x
  - Private: 10.0.1.10
    ↓
[FIREWALL - Only allows 10.0.1.10]
    ↓
Platform Service (Private Network)
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

# Portal app sends it
headers = {"X-Service-Auth": API_SECRET}

# Platform app validates it
if request.headers.get('X-Service-Auth') != settings.API_SECRET:
    return HttpResponseForbidden()
```

#### Option 2: JWT Tokens (Recommended)
```python
# Portal app generates JWT
token = jwt.encode({
    'customer_id': customer_id,
    'exp': datetime.now() + timedelta(minutes=5)
}, SECRET_KEY)

# Platform app validates JWT
try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    customer_id = payload['customer_id']
except jwt.ExpiredSignatureError:
    return HttpResponse('Token expired', status=401)
```

## 🏛️ Portal Service Stateless Architecture

### 🎯 **CRITICAL PRINCIPLE: Portal Must Be Completely Stateless**

The Portal service is designed as a **pure UI service** that consumes Platform API data without storing any state locally. This ensures maximum security, scalability, and maintains clear separation of concerns.

#### ❌ What Portal Should NOT Have

- ❌ **No Real Database**: Portal uses dummy in-memory SQLite (lost on restart)
- ❌ **No Models**: Portal apps should not define any Django models  
- ❌ **No Migrations**: Database router prevents all migrations
- ❌ **No Sessions**: No session middleware or session storage
- ❌ **No User Authentication**: No `django.contrib.auth` or user models
- ❌ **No Messages Framework**: No `django.contrib.messages` (requires sessions)
- ❌ **No CSRF Protection**: Portal is read-only, no forms that modify data
- ❌ **No Redis**: No cache backend or external state storage
- ❌ **No Shared State**: No communication with Platform via Redis/cache

#### ✅ What Portal DOES Have

- ✅ **Templates & Views**: Customer-facing UI rendering
- ✅ **API Client**: HTTP communication with Platform service via token auth
- ✅ **Static Files**: CSS, JS, images for customer interface
- ✅ **Template Tags**: UI components and formatting helpers (stateless)
- ✅ **Context Processors**: Template data enhancement (API-driven)
- ✅ **Dummy Database**: In-memory SQLite (Django requirement, never used)

#### 🔧 Authentication Flow

1. **Customer Accesses Portal**: Direct URL to portal service
2. **Platform API Call**: Portal makes authenticated API call to Platform
3. **API Token/Key**: Portal uses shared API secret or service token
4. **Data Retrieval**: All customer data comes from Platform API responses
5. **Template Rendering**: Portal renders HTML with API data
6. **No Local State**: Portal never stores any customer information locally

#### 🔐 Security Benefits

- **No Session Leakage**: No way for customers to access each other's sessions
- **No Local Data**: Nothing stored locally to compromise
- **API-Only Authentication**: Platform handles all auth verification
- **Service Isolation**: Portal and Platform completely separated

#### 🎯 Portal Structure

```
services/portal/
├── apps/
│   ├── api_client/     # Platform API communication
│   ├── dashboard/      # Customer dashboard views
│   ├── billing/        # Billing display (via API)
│   ├── services/       # Service management UI
│   ├── tickets/        # Support ticket interface
│   ├── ui/             # Template tags and components
│   └── common/         # Shared utilities (no models!)
├── templates/          # Customer-facing templates
├── static/             # CSS, JS, images
└── config/             # Django settings (no auth/sessions)
```

## 📅 Implementation Timeline

### Phase 1: Foundation (Week 1-2)
- [ ] Set up Django REST Framework in platform service
- [ ] Create `services/platform/apps/api/` app structure
- [ ] Implement basic authentication middleware
- [ ] Create first read-only API endpoints (`/api/customers/`, `/api/billing/invoices/`)
- [ ] Add comprehensive logging and API documentation

### Phase 2: API Development (Week 3-4)
- [ ] Build comprehensive API endpoints (`/api/tickets/`, `/api/provisioning/services/`, `/api/domains/`)
- [ ] Add DRF serializers with proper field filtering
- [ ] Implement rate limiting and throttling
- [ ] Add comprehensive API tests and OpenAPI documentation

### Phase 3: Portal Service Creation (Week 5-6)
- [ ] Initialize `services/portal/` Django service
- [ ] Copy validators/constants (~500 lines)
- [ ] Implement API client service layer
- [ ] Move customer-facing templates and views

### Phase 4: Security Hardening (Week 7)
- [ ] Configure network isolation
- [ ] Add JWT token authentication
- [ ] Implement API documentation and monitoring
- [ ] Security audit & penetration testing

### Phase 5: Deployment (Week 8)
- [ ] Set up unified CI/CD pipeline for both services
- [ ] Configure VPN for platform service access
- [ ] Deploy portal service to DMZ
- [ ] Deploy platform service to private network
- [ ] Monitor and optimize both services

## ✅ Architecture Decisions Made

### 1. ✅ API Framework: Django REST Framework (DRF) - **DECIDED**

#### 🏆 Django REST Framework (DRF) - **RECOMMENDED**

**✅ Pros:**
- ✅ **Mature & Battle-tested** - 10+ years in production, used by Instagram, Mozilla, Red Hat
- ✅ **Seamless Django Integration** - Uses Django models, permissions, authentication out-of-the-box
- ✅ **Rich Ecosystem** - JWT, filtering, pagination, throttling, OpenAPI docs built-in
- ✅ **Team Knowledge** - Most Django developers already familiar with DRF patterns
- ✅ **Security Proven** - Extensive security audits, CVE handling, permission system
- ✅ **Serializer Power** - Handles complex nested relationships, validation, field control
- ✅ **Admin Integration** - Works naturally with Django admin for API management
- ✅ **PRAHO Alignment** - Perfect for Romanian business models (CUI, VAT serialization)

**❌ Cons:**
- ❌ **Performance Overhead** - ~20-30% slower than FastAPI for simple CRUD
- ❌ **Learning Curve** - Complex for beginners (ViewSets, Serializers, Permissions)
- ❌ **Verbose Configuration** - More boilerplate than newer alternatives
- ❌ **Legacy Patterns** - Some patterns feel dated compared to modern async frameworks

**🎯 Best For:** Complex business logic, existing Django teams, regulatory compliance needs

---

#### ⚡ Django Ninja - **MODERN ALTERNATIVE**

**✅ Pros:**
- ✅ **Modern Python** - Type hints, Pydantic models, automatic validation
- ✅ **Performance** - ~40% faster than DRF, closer to FastAPI speeds
- ✅ **Developer Experience** - Auto-generated OpenAPI docs, less boilerplate
- ✅ **Django Native** - Still uses Django ORM, auth, middleware naturally
- ✅ **Easy Migration** - Can run alongside DRF during gradual adoption
- ✅ **Type Safety** - Better IDE support, fewer runtime errors
- ✅ **Async Support** - Built-in async view support for high-performance endpoints

**❌ Cons:**
- ❌ **Newer Framework** - Less than 3 years old, smaller community
- ❌ **Limited Ecosystem** - Fewer third-party packages compared to DRF
- ❌ **Team Learning** - Requires learning Pydantic, new patterns
- ❌ **Less Documentation** - Fewer Stack Overflow answers, tutorials
- ❌ **Serialization Control** - Less fine-grained control than DRF serializers
- ❌ **Enterprise Adoption** - Fewer large-scale production references

**🎯 Best For:** New projects, performance-critical APIs, modern Python teams

---

#### 🚀 FastAPI Sidecar - **PERFORMANCE CHAMPION**

**✅ Pros:**
- ✅ **Maximum Performance** - 2-3x faster than Django solutions, async-first
- ✅ **Modern Architecture** - Type hints, async/await, dependency injection
- ✅ **Auto Documentation** - Excellent OpenAPI/Swagger integration
- ✅ **Independent Deployment** - Can scale API separately from Django apps
- ✅ **Microservice Ready** - Natural fit for service-oriented architecture
- ✅ **Type Safety** - Pydantic validation, excellent IDE support
- ✅ **Industry Momentum** - Rapidly growing adoption, modern best practices

**❌ Cons:**
- ❌ **Additional Complexity** - Separate service, different deployment pipeline
- ❌ **Data Layer Duplication** - Need to reimplement Django model logic
- ❌ **Authentication Complexity** - Must recreate Django auth, permissions
- ❌ **Two Frameworks** - Team must maintain Django + FastAPI expertise
- ❌ **Database Migrations** - Must sync schema changes across services
- ❌ **Romanian Business Logic** - Need to reimplement CUI validation, VAT calculations
- ❌ **Development Overhead** - More services to maintain, monitor, deploy

**🎯 Best For:** High-performance APIs, microservice architectures, greenfield projects

---

### 📊 Framework Comparison Matrix

| Criteria | Django REST Framework | Django Ninja | FastAPI Sidecar |
|----------|---------------------|--------------|-----------------|
| **Performance** | 🟡 Moderate | 🟢 Good | 🟢 Excellent |
| **Django Integration** | 🟢 Perfect | 🟢 Native | 🟡 Separate |
| **Learning Curve** | 🟡 Steep | 🟢 Gentle | 🔴 Complex |
| **Maturity** | 🟢 Battle-tested | 🟡 Growing | 🟢 Mature |
| **Team Knowledge** | 🟢 Existing | 🟡 New | 🔴 New Stack |
| **Maintenance** | 🟢 Single Stack | 🟢 Single Stack | 🟡 Multi-Stack |
| **Romanian Features** | 🟢 Ready | 🟢 Adaptable | 🟡 Rebuild |
| **Security** | 🟢 Proven | 🟡 Good | 🟡 DIY |

### 🎯 Recommendation for PRAHO Platform

**Django REST Framework is the recommended choice** for PRAHO because:

1. **Regulatory Compliance** - Proven handling of complex business models, VAT, audit trails
2. **Team Efficiency** - Existing Django knowledge transfers directly
3. **Romanian Features** - CUI validation, VAT serialization already implemented
4. **Security Maturity** - Essential for hosting provider handling sensitive data
5. **Maintenance** - Single technology stack reduces operational complexity

### 2. ✅ Authentication: Shared Secret → JWT Migration Path - **DECIDED**

**Phase 1**: Shared Secret (immediate implementation)
```python
# Simple, fast implementation for MVP
INTER_SERVICE_SECRET = env('INTER_SERVICE_SECRET')
headers = {"X-Service-Auth": INTER_SERVICE_SECRET}
```

**Phase 2**: JWT Migration (after portal service is stable)
```python
# Easy 1-day migration later
JWT_SECRET = env('JWT_SECRET') 
token = jwt.encode({'customer_id': customer_id, 'exp': datetime.now() + timedelta(minutes=5)}, JWT_SECRET)
```

**Migration Strategy**: Both auth methods work simultaneously during transition, then remove shared secret.

### 🚨 Outstanding Decisions

3. **Deployment**: Kubernetes vs Docker Compose vs traditional VMs
4. **Database Access**: Keep single DB or read replicas for portal app?

## 💰 Resource Requirements

- **Team**: 2-3 senior developers for 8 weeks
- **Infrastructure**: Additional servers for portal app
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

1. **Week 1**: Set up Django REST Framework in `services/platform/apps/api/`
2. **Week 2**: Create clean `/api/customers/` and `/api/billing/invoices/` endpoints
3. **Week 3**: Build minimal portal service with API client
4. **Week 4**: Add authentication and test in staging environment

## 🎉 The Good News

Your current architecture with the service layer pattern (ADR-0012) and modular app structure makes this separation very feasible. The main effort will be in creating the API layer and ensuring proper security boundaries. By avoiding a third shared codebase, you'll ship faster and maintain simpler.

**Total Estimated Timeline: 7-8 weeks** with a team of 2-3 senior developers (saved 1-2 weeks by skipping shared library complexity).
## 🏢 Deployment Architecture

### Subdomain Structure

#### VPN-Protected (Staff Only)
```
platform.pragmatichost.com
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
portal.pragmatichost.com
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
## Architecture Decision: Beautiful Monorepo with Two Services
- services/platform/: Full Django service with database access and DRF API endpoints
- services/portal/: Lightweight Django service with API client only  
- API Framework: Django REST Framework with clean /api/ URLs (no versioning initially)
- Shared code: Deliberately duplicated (~500 lines) until proven need
- Models: Always live in platform service, never shared
- API contracts: Defined via DRF serializers in platform, consumed by portal
- Validators: Duplicated between services (acceptable for ~500 lines)
- Repository: Single beautiful monorepo with clear service boundaries
```

## Conclusion

For PRAHO Platform, a Romanian hosting provider handling CUI data, VAT information, and server infrastructure, the security benefits of complete application separation significantly outweigh the maintenance overhead. 

The platform system managing Virtualmin servers and customer financial data should never share code paths with the public-facing customer portal. This architecture provides true security isolation while maintaining shared business logic through deliberate duplication of small shared code (validators, constants) between the two apps. Models and business logic always live in `platform` and are never shared.

**Implementation recommendation**: Build and maintain only two codebases: `platform` and `portal`. Do not introduce a third shared library unless duplication becomes a proven pain point. This approach maximizes development velocity, minimizes complexity, and aligns with best practices from large-scale SaaS platforms. Extract shared code only if and when the cost of duplication exceeds the cost of coordination.

---

## 🚀 **Portal Authentication Implementation Plan - Django Best Practices**

*Updated implementation plan based on senior tech lead review and Django best practices.*

### **Phase 1: Fix Django Configuration Foundation (Day 1 - Morning)**
1. **Update portal settings** with correct SESSION_ENGINE and missing apps/middleware
2. **Add proper cookie security settings** (SECURE, SAMESITE, HTTPONLY)
3. **Configure CSRF protection** for all forms
4. **Test basic Django session functionality**

### **Phase 2: Implement Proper LoginView (Day 1 - Afternoon)** 
1. **Replace custom cookie logic** with Django sessions (`request.session`)
2. **Add CSRF protection** to login form with `{% csrf_token %}`
3. **Implement "Remember Me"** using `request.session.set_expiry()`
4. **Add secure logout** with `request.session.flush()` for session key rotation

### **Phase 3: Secure Platform API Integration (Day 2 - Morning)**
1. **Implement HMAC request signing** in portal API client
2. **Add HMAC verification** to platform authenticate_customer endpoint  
3. **Add nonce tracking** to prevent replay attacks
4. **Return generic 401s** to prevent credential enumeration

### **Phase 4: Simple Authentication Middleware (Day 2 - Afternoon)**
1. **Create lightweight middleware** that checks `request.session.get('customer_id')`
2. **Remove manual authentication checks** from individual views
3. **Attach customer data** to request object for easy access
4. **Test session persistence** across requests

### **Key Architecture Fixes Applied:**

#### **✅ Fixed Configuration Issues:**
1. **Correct SESSION_ENGINE** - Using `django.contrib.sessions.backends.db`
2. **Added missing apps** - `sessions`, `messages` 
3. **Added missing middleware** - Session, CSRF, Auth, Messages
4. **Proper CSRF protection** - All forms include `{% csrf_token %}`

#### **✅ Security Improvements:**
1. **HMAC inter-service auth** - Platform verifies portal requests
2. **No custom cookie handling** - Using Django sessions exclusively  
3. **Session key rotation** - `request.session.flush()` on logout
4. **Generic 401 responses** - No credential enumeration
5. **Nonce tracking** - Prevents replay attacks

#### **✅ Removed Anti-Patterns:**
1. **No LocMemCache for sessions** - Using database sessions
2. **No IP/UA binding** - Avoided brittle user lockouts
3. **No custom session tokens** - Using Django's built-in system
4. **No race conditions** - Django sessions handle atomicity

**Outcome:** Production-ready Django-native authentication with proper CSRF protection, secure inter-service communication, and database sessions - no Redis required, no custom session management complexity.

---

## ⏺ ✅ HMAC-Only Architecture Complete - No JWT Bloat!

**Architecture Decision: HMAC-Signed Context Validation (Final Implementation)**

After implementing and evaluating both JWT and HMAC approaches for secure session validation between portal and platform services, we have **removed JWT complexity entirely** and implemented a clean HMAC-only solution.

### 🎯 **Final Implementation: HMAC-Signed Request Bodies**

#### **Security Architecture:**
- **Portal Service**: Signs customer context in request body using HMAC headers
- **Platform Service**: Validates HMAC signature and processes customer context
- **No JWT tokens**: Eliminated unnecessary complexity and dependencies
- **No customer IDs in URLs**: Prevents enumeration attacks (OWASP fix)

#### **Request Flow:**
```http
POST /api/users/session/validate/
Headers:
  X-Portal-Id: portal-001
  X-Nonce: <unique-nonce>
  X-Timestamp: <unix-timestamp>
  X-Body-Hash: <sha256-base64>
  X-Signature: <hmac-sha256>
  Content-Type: application/json

Body:
{
  "customer_id": "2",
  "state_version": 42,
  "timestamp": 1694022337
}
```

### 🔒 **Security Features Implemented:**

#### **Portal Service (Customer-Facing):**
- **Sophisticated middleware timing**: Jittered validation (10min + 0-2min jitter)
- **Single-flight locks**: Prevents thundering herd (one validation per customer)
- **Stale-while-revalidate**: Soft TTL (5min grace) + Hard TTL (15min max)
- **Fail-open strategy**: Allows access during platform outages
- **Session metadata tracking**: `validated_at`, `next_validate_at`, `state_version`

#### **Platform Service (Admin/API):**
- **Rate limiting**: 60 requests/min per portal (prevents brute force)
- **Nonce deduplication**: Prevents replay attacks
- **Uniform error responses**: No information leakage
- **Security headers**: Cache-Control, X-Content-Type-Options
- **Request freshness**: 5-minute timestamp window

### 📊 **HMAC vs JWT vs Shared Secret Comparison:**

| Feature | HMAC-Signed | JWT Tokens | Shared Secret |
|---------|-------------|------------|---------------|
| **Complexity** | ✅ Simple | ❌ High | ✅ Minimal |
| **Dependencies** | ✅ None | ❌ PyJWT | ✅ None |
| **Security** | ✅ Excellent | ✅ Good | ⚠️ Basic |
| **Performance** | ✅ Fast | ⚠️ Slower | ✅ Fastest |
| **Replay Protection** | ✅ Nonce | ✅ exp + jti | ❌ None |
| **Context Passing** | ✅ Request Body | ✅ Token Claims | ❌ Headers Only |
| **Scalability** | ✅ Stateless | ✅ Stateless | ⚠️ Shared State |
| **Debugging** | ✅ Clear | ❌ Opaque | ✅ Transparent |

### 🏗️ **Implementation Details:**

#### **Files Modified:**
1. **`/services/platform/apps/api/users/views.py`**
   - Added `validate_session_secure()` endpoint
   - Removed JWT-based validation logic
   - Implemented uniform error responses

2. **`/services/portal/apps/api_client/services.py`**
   - Updated `validate_session_secure()` to send context in request body
   - Maintained existing HMAC signature generation
   - Removed JWT token handling

3. **`/services/portal/apps/users/middleware.py`**
   - Enhanced with production-ready timing controls
   - Added jittered validation and single-flight locks
   - Implemented stale-while-revalidate pattern

4. **`requirements.txt` (both services)**
   - **Removed PyJWT dependency** - eliminated unnecessary complexity

### ✅ **Why HMAC-Only Wins:**

1. **Simplicity**: No token parsing, no expiration handling, no claims validation
2. **Security**: Same cryptographic strength as JWT without implementation pitfalls
3. **Performance**: Zero token processing overhead
4. **Maintainability**: Fewer dependencies, clearer request/response flow
5. **Debugging**: Request bodies are readable, signatures are verifiable

### 🎯 **OWASP Top 10 Compliance:**
- **A01 - Broken Access Control**: ✅ No customer IDs in URLs
- **A02 - Cryptographic Failures**: ✅ HMAC-SHA256 with proper nonce handling
- **A03 - Injection**: ✅ Request body validation and timestamp checks
- **A07 - ID & Auth Failures**: ✅ Rate limiting and uniform error responses
- **A09 - Security Logging**: ✅ Audit trails without PII exposure

### 🚀 **Production Features:**
- **Zero downtime**: Graceful degradation during platform maintenance
- **Horizontal scaling**: Stateless validation with cache-based coordination
- **Monitoring ready**: Structured logging with security event correlation
- **Enterprise grade**: Battle-tested patterns used by major SaaS platforms

**Final Verdict**: HMAC-signed request bodies provide the perfect balance of security, simplicity, and performance for inter-service authentication. JWT would have been over-engineering for this use case.