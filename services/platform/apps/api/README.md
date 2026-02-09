# 🚀 PRAHO Platform API

## Overview

PRAHO Platform provides a centralized REST API for all business operations. The API follows the successful architectural patterns used by Sentry, Stripe, and other major Django applications.

## Architecture

- **Centralized Structure**: All API endpoints live under `apps/api/`
- **Domain Organization**: Endpoints grouped by business domain (customers, billing, tickets)
- **Clean URLs**: Direct paths without versioning (e.g., `/api/customers/`)
- **DRF-based**: Built on Django REST Framework with custom base classes

## Base URL

```
http://localhost:8001/api/
```

## Authentication

All API endpoints require authentication. Currently supported:
- **Session Authentication**: For web interface AJAX calls

## Rate Limiting

- **Standard APIs**: 60 requests/minute per user
- **Search APIs**: 120 requests/minute per user (higher limit for autocomplete)

## Endpoints

### Customer APIs

#### Customer Search
```
GET /api/customers/search/?q={query}
```

Search customers for dropdowns and autocomplete fields.

**Parameters:**
- `q` (string, required): Search query (minimum 2 characters)

**Response:**
```json
{
  "results": [
    {
      "id": 1,
      "text": "Company Name (user@example.com)",
      "primary_email": "user@example.com"
    }
  ]
}
```

#### Customer Services
```
GET /api/customers/{id}/services/
```

Get services for a specific customer (placeholder - returns empty list).

**Path Parameters:**
- `id` (integer): Customer ID

**Response:**
```json
[]
```

### Billing APIs

*Coming soon - Romanian VAT-compliant billing endpoints*

### Ticket APIs  

*Coming soon - Support ticket and SLA management endpoints*

## Error Responses

The API returns standard HTTP status codes with JSON error messages:

```json
{
  "error": "Error description"
}
```

Common status codes:
- `400`: Bad Request - Invalid parameters
- `401`: Unauthorized - Authentication required
- `403`: Forbidden - Access denied  
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error

## Development

### Adding New Endpoints

1. **Choose Domain**: Determine if endpoint belongs to customers, billing, or tickets
2. **Create Serializer**: Add to `apps/api/{domain}/serializers.py`
3. **Create ViewSet**: Add to `apps/api/{domain}/views.py` extending `BaseAPIViewSet`
4. **Add URL**: Register in `apps/api/{domain}/urls.py`

### Base Classes

All API endpoints should extend the base classes in `apps/api/core/`:

- `BaseAPIViewSet`: Full CRUD operations
- `ReadOnlyAPIViewSet`: Read-only operations (search, lists)

These provide consistent:
- Authentication & permissions
- Rate limiting  
- Pagination
- Error handling

### Example ViewSet

```python
from apps.api.core import BaseAPIViewSet
from apps.customers.models import Customer
from .serializers import CustomerSerializer

class CustomerViewSet(BaseAPIViewSet):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    
    def get_queryset(self):
        # Filter based on user access
        user = self.request.user
        return user.get_accessible_customers()
```

## Migration Status

✅ **Completed:**
- Customer search API (migrated from `apps.customers.customer_views.customer_search_api`)  
- Customer services API (migrated from `apps.customers.customer_views.customer_services_api`)
- Base API infrastructure
- URL routing and configuration

🔄 **In Progress:**
- Billing API endpoints
- Ticket API endpoints  
- API documentation generation

📋 **Planned:**
- Domain management APIs
- Provisioning APIs
- Audit log APIs
