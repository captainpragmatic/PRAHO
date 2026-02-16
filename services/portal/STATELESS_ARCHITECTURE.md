# 🏛️ Portal Stateless Architecture

## 🚨 CRITICAL ARCHITECTURAL PRINCIPLE

**The Portal service MUST be completely stateless.**

## ❌ What Portal Should NOT Have

- ❌ **No Real Database**: Portal uses dummy in-memory SQLite (lost on restart)
- ❌ **No Models**: Portal apps should not define any Django models
- ❌ **No Migrations**: Database router prevents all migrations
- ❌ **No Sessions**: No session middleware or session storage
- ❌ **No User Authentication**: No `django.contrib.auth` or user models
- ❌ **No Messages Framework**: No `django.contrib.messages` (requires sessions)
- ❌ **No CSRF Protection**: Portal is read-only, no forms that modify data
- ❌ **No Redis**: No cache backend or external state storage
- ❌ **No Shared State**: No communication with Platform via Redis/cache
- ❌ **No Direct Data Storage**: All data comes from Platform API calls

## ✅ What Portal DOES Have

- ✅ **Templates & Views**: Customer-facing UI rendering
- ✅ **API Client**: Communication with Platform service via HTTP
- ✅ **Static Files**: CSS, JS, images for customer interface
- ✅ **Template Tags**: UI components and formatting helpers (stateless)
- ✅ **Context Processors**: Template data enhancement (API-driven)
- ✅ **Dummy Database**: In-memory SQLite (Django requirement, never used)

## 🔄 Data Flow Pattern

```
Customer Browser → Portal Service → Platform API → Platform Database
                      ↓
                 Templates + Views
                      ↓
                 Rendered HTML
```

## 🔧 Authentication Flow

1. **Customer Accesses Portal**: Direct URL to portal service
2. **Platform API Call**: Portal makes authenticated API call to Platform
3. **API Token/Key**: Portal uses shared API secret or service token
4. **Data Retrieval**: All customer data comes from Platform API responses
5. **Template Rendering**: Portal renders HTML with API data
6. **No Local State**: Portal never stores any customer information locally

## 📁 Portal Service Structure

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

## 🚫 Files That Should NOT Exist

- `portal.sqlite3` - No database file
- `apps/users/` - No user authentication app
- `*/migrations/` - No migration directories
- Any file importing `django.contrib.auth`
- Any file importing `django.db.models`

## 🔧 Technical Implementation Details

### Why Dummy Database?

Django **requires** a `DATABASES` setting to function, even if you never use it. Portal uses:

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",  # In-memory, disappears on restart
    }
}
```

- **In-Memory Only**: Database exists only in RAM, lost on restart
- **Never Written To**: Database router prevents all migrations and writes
- **Django Compliance**: Satisfies Django's configuration requirements
- **Zero Persistence**: No files created, no state preserved

### Why No Redis/Cache?

- **Security Risk**: Shared cache could leak data between services
- **Complexity**: Additional infrastructure dependency
- **Unnecessary**: Portal only displays data, doesn't store it
- **Stateless Goal**: Any cache would be local state (violates architecture)

## 🎯 Benefits of Stateless Design

1. **Scalability**: Portal instances can be load balanced easily
2. **Security**: No local data to compromise or leak between customers
3. **Consistency**: Single source of truth (Platform database)
4. **Deployment**: Portal can restart without data loss
5. **Development**: Clear separation of concerns
6. **Zero Migrations**: Portal never needs database schema changes
7. **Horizontal Scale**: Add portal instances without coordination

---

**Generated**: September 6, 2025
**Status**: ✅ IMPLEMENTED - Portal is now completely stateless
