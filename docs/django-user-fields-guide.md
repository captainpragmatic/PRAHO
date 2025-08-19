# Django User Fields: Complete Guide

## **🔍 Django Built-in User Fields Explained**

Django's `AbstractUser` comes with several built-in permission fields that serve specific framework purposes:

| Field | Purpose | Scope | When True | Typical Usage |
|-------|---------|-------|-----------|---------------|
| **`is_active`** | Account enabled | User login | User can log in | Account suspension |
| **`is_staff`** | Django admin access | Django admin panel | Can access `/admin/` | Technical admin interface |
| **`is_superuser`** | Django god mode | All Django permissions | Bypasses ALL permission checks | Emergency access |

## **🎯 Detailed Field Explanations**

### **`is_active` - Account Status**
```python
# Purpose: Can the user log in?
user.is_active = True   # ✅ User can log in
user.is_active = False  # ❌ User cannot log in (suspended/deactivated)

# Common usage:
if not user.is_active:
    return "Account is deactivated"
```

### **`is_staff` - Django Admin Panel Access**
```python
# Purpose: Can access Django's /admin/ interface?
user.is_staff = True   # ✅ Can access /admin/ URL
user.is_staff = False  # ❌ Cannot access /admin/ URL

# Django automatically checks this:
# /admin/ -> checks if user.is_staff == True

# Common usage:
@staff_member_required  # Django decorator that checks is_staff
def admin_dashboard(request):
    # Only is_staff=True users can access
```

### **`is_superuser` - Django God Mode**
```python
# Purpose: Has ALL Django permissions automatically?
user.is_superuser = True   # ✅ Has EVERY permission in Django
user.is_superuser = False  # ❌ Must have explicit permissions

# Django behavior:
if user.is_superuser:
    # User has ALL permissions without checking Permission table
    # Can do ANYTHING in Django admin
    # Bypasses all permission checks
```

## **🏢 Our Business Logic Layer**

Our custom `admin_role` field handles **business functionality** (not Django framework):

```python
class User(AbstractUser):
    # Django framework fields (built-in)
    # is_active = models.BooleanField(default=True)      # Account status
    # is_staff = models.BooleanField(default=False)      # Django admin access  
    # is_superuser = models.BooleanField(default=False)  # Django god mode
    
    # PragmaticHost business field (our custom)
    admin_role = models.CharField(
        max_length=20,
        choices=[
            ('admin', 'Administrator'),      # Business admin (not Django admin)
            ('support', 'Support Agent'),    # Customer support
            ('billing', 'Billing Staff'),    # Financial operations
            ('manager', 'Manager'),          # Account management
        ],
        null=True,
        blank=True
    )
```

## **🎭 User Type Examples**

### **1. Django Superuser (Emergency Access)**
```python
user.is_superuser = True   # ✅ Django god mode
user.is_staff = True       # ✅ Auto-implied with superuser
user.admin_role = 'admin'  # ✅ Also business admin
# Can do ANYTHING in Django admin + business functions
```

### **2. Business Administrator**
```python
user.is_superuser = False  # ❌ Not Django god
user.is_staff = True       # ✅ Can access Django admin  
user.admin_role = 'admin'  # ✅ Business admin role
# Can access Django admin + manage customers/billing
```

### **3. Support Agent**
```python
user.is_superuser = False    # ❌ Not Django god
user.is_staff = True         # ✅ Can access Django admin
user.admin_role = 'support'  # ✅ Support role only
# Can access Django admin + handle support tickets
```

### **4. Customer User**
```python
user.is_superuser = False  # ❌ Not Django god
user.is_staff = False      # ❌ Cannot access Django admin
user.admin_role = None     # ❌ No business admin role
# Customer memberships exist -> customer dashboard only
```

### **5. Deactivated User**
```python
user.is_active = False     # ❌ Cannot log in
# All other fields irrelevant - user cannot access anything
```

## **🚦 Permission Flow Examples**

### **Accessing Django Admin Panel (`/admin/`)**
```python
# Django's built-in check:
if user.is_authenticated and user.is_active and user.is_staff:
    # Allow access to /admin/
else:
    # Redirect to login or show 403
```

### **Accessing Business Admin Features**
```python
# Our custom business logic:
if user.admin_role in ['admin', 'support', 'billing', 'manager']:
    # Allow access to business admin features
elif user.is_customer_user:
    # Allow access to customer dashboard
else:
    # No access (orphaned user - should not exist)
```

### **Checking Specific Permissions**
```python
# Django permissions (for Django admin)
if user.has_perm('customers.change_customer'):
    # Can modify customers in Django admin

# Business permissions (our logic)
if user.admin_role == 'billing':
    # Can manage invoices and payments
elif user.admin_role == 'support':
    # Can handle support tickets
```

## **⚠️ Important Notes**

### **Security Best Practices:**
1. **`is_superuser=True`**: Use sparingly! Only for emergency access
2. **`is_staff=True`**: Only for users who need Django admin access
3. **`admin_role`**: Use for business function control
4. **Regular Review**: Audit user permissions regularly

### **Common Mistakes:**
```python
# ❌ WRONG: Using is_staff for business logic
if user.is_staff:
    # Show business admin menu

# ✅ CORRECT: Using admin_role for business logic  
if user.admin_role:
    # Show business admin menu

# ❌ WRONG: Making everyone is_superuser
user.is_superuser = True  # Dangerous!

# ✅ CORRECT: Specific roles for specific purposes
user.admin_role = 'support'  # Safe and specific
```

## **🎯 Summary**

- **`is_active`**: Can user log in? (account status)
- **`is_staff`**: Can user access Django admin? (technical admin)
- **`is_superuser`**: Does user have ALL Django permissions? (emergency access)
- **`admin_role`**: What business functions can user perform? (business admin)

**Each field serves a specific purpose - don't mix Django framework permissions with business logic!**
