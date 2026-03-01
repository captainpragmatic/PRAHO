# ADR-0024: User Model Design: is_staff vs admin_role

## **🚨 Current Issue: Confusing Field Names**

### **Problem Analysis:**
- Django's `is_staff` field is for Django admin panel access
- Our custom `system_role` field is for business role distinction
- **Field names are confusing and create conflicts!**

### **Current Confusing Usage:**
```python
# CONFUSING NAMES 😕
user.is_staff        # Staff of what? Django admin or business staff?
user.system_role     # What does "system" mean exactly?
user.is_superuser    # Super what? Business super user or Django superuser?
```

## **🏗️ Proposed Solution: Clear Naming**

### **Renamed Field: `system_role` → `admin_role`**

```python
class User(AbstractUser):
    # Django admin access (keep as-is for Django framework)
    # is_staff = models.BooleanField(default=False)  # Built-in Django field

    # RENAMED: Business role for internal staff (much clearer!)
    admin_role = models.CharField(
        max_length=20,
        choices=ADMIN_ROLE_CHOICES,
        null=True,
        blank=True,
        help_text=_('Internal admin role. Leave empty for customer users.')
    )

    ADMIN_ROLE_CHOICES = [
        ('admin', _('Administrator')),      # Full business control
        ('support', _('Support Agent')),    # Customer support
        ('billing', _('Billing Staff')),    # Financial operations
        ('manager', _('Manager')),          # Account management
    ]
```

## **🔍 Django Built-in Fields Explained**

### **`is_staff` - Django Admin Panel Access**
- **Purpose**: Can user access `/admin/` URL?
- **Scope**: Django framework only
- **Usage**: Technical admin interface access

### **`is_superuser` - Django God Mode**
- **Purpose**: Has ALL Django permissions automatically
- **Scope**: Django framework only
- **Usage**: Bypass all permission checks in Django admin

### **`admin_role` - Business Role (Our Custom Field)**
- **Purpose**: What business functions can user perform?
- **Scope**: PragmaticHost business logic
- **Usage**: Customer management, billing, support, etc.

## **✅ Clear Usage Examples**

### **Template Logic:**
```html
<!-- OLD CONFUSING -->
{% if user.is_staff %}  <!-- Django admin or business staff? -->
{% if user.system_role %}  <!-- What kind of system role? -->

<!-- NEW CLEAR -->
{% if user.is_admin_user %}  <!-- Has business admin role -->
{% if user.is_customer_user %}  <!-- Has customer access -->
{% if user.admin_role == 'support' %}  <!-- Specific business role -->
```

### **Permission Checks:**
```python
# Django admin access
if user.is_staff:
    # Can access /admin/ interface

# Business admin functions
if user.admin_role:
    # Can perform business operations

# Specific business roles
if user.admin_role == 'billing':
    # Can manage invoices and payments

# Customer access
if user.is_customer_user:
    # Can access customer dashboard
```

## **🎯 Updated User Types**

Every user will be in exactly ONE of these clear categories:

1. **Django Superuser**: `is_superuser=True` (framework god mode)
2. **Business Admin**: `admin_role='admin'`, `is_staff=True` (business control)
3. **Business Staff**: `admin_role='support/billing/manager'`, `is_staff=True` (specific duties)
4. **Customer User**: `admin_role=None`, customer memberships (customer access)
5. **Hybrid Admin**: Has both `admin_role` AND customer memberships (testing accounts)

## **� Migration Plan**

### **Phase 1: Rename Field**
```python
# Migration to rename field
class Migration(migrations.Migration):
    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='system_role',
            new_name='admin_role',
        ),
    ]
```

### **Phase 2: Update Code**
- Replace all `user.system_role` with `user.admin_role`
- Update property methods to use clear names
- Update templates with clear role checks

### **Phase 3: Add Helper Properties**
```python
@property
def is_admin_user(self) -> bool:
    """Check if user has business admin role"""
    return self.admin_role is not None

@property
def is_business_admin(self) -> bool:
    """Check if user has admin business role"""
    return self.admin_role == 'admin'
```

## **✅ Benefits of Clear Naming:**

1. **No Confusion**: `admin_role` clearly means business admin role
2. **Self-Documenting**: Code is easier to understand
3. **Better Onboarding**: New developers understand immediately
4. **Clear Separation**: Django vs Business logic distinction
5. **Future Proof**: Easy to extend with new business roles
