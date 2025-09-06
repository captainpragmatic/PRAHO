# 🔐 PRAHO API Authentication Guide

## Authentication Methods

PRAHO Platform API supports multiple authentication methods for different use cases:

### 1. **Session Authentication** 🍪
- **Use case**: Web UI (HTMX calls from platform service)
- **Method**: Django session cookies
- **Setup**: Automatic for logged-in users

### 2. **Token Authentication** 🎫
- **Use case**: Portal service, mobile apps, CLI tools  
- **Method**: Authorization header with token
- **Setup**: Obtain token via API endpoint

## Getting API Tokens

### **Obtain Token**
```bash
POST /api/users/token/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "your-password"
}
```

**Response:**
```json
{
    "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
    "user_id": 123,
    "email": "user@example.com",
    "is_staff": false
}
```

### **Using Tokens**
Include the token in the Authorization header:

```bash
curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" \
     https://platform.praho.com/api/customers/search/?q=test
```

### **Verify Token**
```bash
GET /api/users/token/verify/
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

**Response:**
```json
{
    "user_id": 123,
    "email": "user@example.com", 
    "is_staff": false,
    "accessible_customers": [1, 2, 3],
    "full_name": "John Doe"
}
```

### **Revoke Token**
```bash
POST /api/users/token/revoke/
Content-Type: application/json

{
    "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"
}
```

## Rate Limiting 🚦

### **Rate Limits by Authentication**

| User Type | Limit | Usage |
|-----------|-------|--------|
| **Anonymous** | 100/hour | Public endpoints only |
| **Authenticated** | 1000/hour | General API usage |
| **Burst** | 60/min | Search/autocomplete |
| **Auth endpoints** | 5/min | Login/token requests |

### **Rate Limit Headers**
API responses include rate limit information:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1625097600
```

### **Rate Limit Exceeded**
```json
{
    "detail": "Request was throttled. Expected available in 3600 seconds."
}
```

## Portal Service Integration

For the **portal service** to call the platform API:

### **1. Initial Setup**
```javascript
// Portal service authentication
const response = await fetch('https://platform.praho.com/api/users/token/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        email: 'service-account@praho.com',
        password: 'secure-service-password'
    })
});

const { token } = await response.json();
```

### **2. API Calls**
```javascript
// Use token for all API calls
const customerData = await fetch('https://platform.praho.com/api/customers/search/?q=test', {
    headers: {
        'Authorization': `Token ${token}`,
        'Content-Type': 'application/json',
    }
});
```

### **3. Token Management**
```javascript
// Verify token is still valid
const verifyResponse = await fetch('https://platform.praho.com/api/users/token/verify/', {
    headers: {
        'Authorization': `Token ${token}`
    }
});

if (verifyResponse.status === 401) {
    // Token expired, get new one
    token = await getNewToken();
}
```

## Security Best Practices

### **For Portal Service**
1. **Service Account**: Create dedicated user for portal service
2. **Environment Variables**: Store tokens in environment, never in code
3. **Token Rotation**: Periodically revoke and regenerate tokens
4. **HTTPS Only**: Never send tokens over HTTP

### **For Users**
1. **Secure Storage**: Store tokens securely (encrypted storage)
2. **Limited Scope**: Use tokens only for intended purposes  
3. **Revoke Unused**: Revoke tokens when no longer needed
4. **Monitor Usage**: Check for suspicious API activity

## Troubleshooting

### **Common Issues**

#### **401 Unauthorized**
```bash
# Check token format
curl -H "Authorization: Token YOUR_TOKEN_HERE" /api/users/token/verify/

# Verify token exists  
python manage.py shell
>>> from rest_framework.authtoken.models import Token
>>> Token.objects.filter(key='YOUR_TOKEN_HERE').exists()
```

#### **403 Forbidden**  
- User doesn't have access to requested resource
- Check customer membership permissions

#### **429 Too Many Requests**
- Rate limit exceeded
- Wait for reset time or reduce request frequency

### **Django Shell Helpers**
```python
# Create token for user
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

User = get_user_model()
user = User.objects.get(email='user@example.com')
token, created = Token.objects.get_or_create(user=user)
print(f"Token: {token.key}")

# Revoke all tokens for user
Token.objects.filter(user=user).delete()
```

## Migration from Legacy Auth

If you have existing authentication, migrate gradually:

1. **Add Token Authentication** (✅ Done)
2. **Update Portal Service** to use tokens
3. **Keep Session Auth** for web UI
4. **Monitor Usage** and fix any issues
5. **Deprecate Legacy** endpoints when ready

The API now supports both session and token authentication for maximum flexibility! 🚀
