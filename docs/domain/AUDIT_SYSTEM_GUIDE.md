# PRAHO Comprehensive Audit System Guide

## Overview

The PRAHO platform implements a comprehensive user action audit logging system that meets industry standards for security, compliance, and regulatory requirements. This system provides complete visibility into all user activities across the platform, enabling security monitoring, compliance reporting, and forensic investigation.

## Industry Standards Compliance

### Security Frameworks
- **ISO 27001 A.12.4** - Event logging and monitoring
- **NIST Cybersecurity Framework** - Identity and access management logging
- **NIST SP 800-63B** - Authentication and session management auditing
- **SOX Controls** - Financial systems audit trails
- **PCI DSS Requirements** - Payment card industry security logging

### Data Protection Regulations
- **GDPR Articles 12-22** - Data subject rights and consent tracking
- **GDPR Article 30** - Records of processing activities
- **Romanian Law 190/2018** - National GDPR implementation
- **Romanian Business Law** - Tax record retention requirements

## Architecture Overview

### Core Components

```
apps/audit/
├── models.py          # AuditEvent, DataExport, ComplianceLog models
├── services.py        # AuditService, AuthenticationAuditService, GDPR services
├── signals.py         # Django signal handlers for automated audit logging
└── views.py          # Audit dashboard and reporting views
```

### Database Schema

#### AuditEvent Model
```python
class AuditEvent:
    # Identity and timing
    id: UUID                    # Unique event identifier
    timestamp: DateTime         # When the event occurred (indexed)
    user: User                 # Who performed the action
    actor_type: str            # user|system|api

    # Event categorization (NEW)
    action: str                # Specific action performed (200+ types)
    category: str              # Security category (10 categories)
    severity: str              # low|medium|high|critical
    is_sensitive: bool         # Contains PII or security data
    requires_review: bool      # Flagged for manual review

    # Context and location
    ip_address: IPAddress      # Client IP address
    user_agent: str           # Client user agent
    session_key: str          # Session identifier
    request_id: str           # Request correlation ID

    # What changed
    content_type: ContentType  # Model that was affected
    object_id: str            # ID of the affected object
    old_values: JSON          # Previous values
    new_values: JSON          # New values
    description: str          # Human-readable description
    metadata: JSON            # Additional context data
```

### Event Categories

#### 1. Authentication Events
- **Purpose**: Track login/logout activities, session management
- **Severity**: Medium to High
- **Examples**: `login_success`, `login_failed_password`, `session_expired`
- **Compliance**: NIST SP 800-63B, ISO 27001

#### 2. Authorization Events
- **Purpose**: Track role/permission changes, access control
- **Severity**: High
- **Examples**: `role_assigned`, `permission_revoked`, `staff_role_changed`
- **Compliance**: SOX, ISO 27001

#### 3. Account Management Events
- **Purpose**: Track profile changes, identity verification
- **Severity**: Medium
- **Examples**: `profile_updated`, `email_changed`, `phone_updated`
- **Compliance**: GDPR Article 12

#### 4. Data Protection Events
- **Purpose**: Track data exports, deletions, breaches
- **Severity**: High to Critical
- **Examples**: `data_export_requested`, `data_deletion_completed`
- **Compliance**: GDPR Articles 15, 17, 20

#### 5. Security Events
- **Purpose**: Track security incidents, threats, anomalies
- **Severity**: Critical
- **Examples**: `security_incident_detected`, `brute_force_attempt`
- **Compliance**: ISO 27001, NIST

#### 6. Privacy Events
- **Purpose**: Track consent changes, privacy settings
- **Severity**: High
- **Examples**: `gdpr_consent_withdrawn`, `marketing_consent_granted`
- **Compliance**: GDPR Articles 6, 7

#### 7. Business Operation Events
- **Purpose**: Track routine business activities
- **Severity**: Low
- **Examples**: `invoice_created`, `order_placed`
- **Compliance**: Romanian Business Law

#### 8. System Administration Events
- **Purpose**: Track administrative actions, maintenance
- **Severity**: High
- **Examples**: `user_impersonation_started`, `configuration_changed`
- **Compliance**: SOX, ISO 27001

#### 9. Integration Events
- **Purpose**: Track API usage, webhook configuration
- **Severity**: Medium
- **Examples**: `api_key_generated`, `webhook_configured`
- **Compliance**: PCI DSS (if applicable)

#### 10. Compliance Events
- **Purpose**: Track regulatory compliance activities
- **Severity**: High
- **Examples**: `vat_validation_completed`, `efactura_submitted`
- **Compliance**: Romanian Tax Law

## Audit Event Actions (200+ Types)

### Authentication Events (NIST SP 800-63B)
```python
# Login/Logout
'login_success', 'login_failed', 'login_failed_password',
'login_failed_user_not_found', 'login_failed_account_locked',
'logout_manual', 'logout_session_expired', 'logout_security_event'

# Account Security
'account_locked', 'account_unlocked', 'session_rotation'
```

### Password Management (NIST SP 800-63B)
```python
'password_changed', 'password_reset_requested', 'password_reset_completed',
'password_compromised', 'password_strength_weak', 'password_expired'
```

### 2FA/MFA Security Events
```python
'2fa_enabled', '2fa_disabled', '2fa_admin_reset',
'2fa_backup_codes_generated', '2fa_verification_success',
'2fa_device_registered', '2fa_recovery_used'
```

### Profile & Account Management (GDPR Article 12-22)
```python
'profile_updated', 'email_changed', 'phone_updated', 'name_changed',
'language_preference_changed', 'timezone_changed',
'emergency_contact_updated'
```

### Privacy & Consent (GDPR Articles 6, 7, 13, 14)
```python
'privacy_settings_changed', 'gdpr_consent_granted', 'gdpr_consent_withdrawn',
'marketing_consent_granted', 'cookie_consent_updated',
'privacy_policy_accepted', 'terms_of_service_accepted'
```

### Authorization Events (RBAC/ABAC)
```python
'role_assigned', 'role_removed', 'permission_granted', 'permission_revoked',
'staff_role_changed', 'customer_role_changed', 'access_denied'
```

### Customer Relationship Management
```python
'customer_membership_created', 'primary_customer_changed',
'customer_access_granted', 'customer_context_switched'
```

### Security Events (ISO 27001 A.12.4)
```python
'security_incident_detected', 'suspicious_activity', 'brute_force_attempt',
'malicious_request', 'rate_limit_exceeded', 'ip_blocked'
```

### Data Protection Events (GDPR)
```python
'data_export_requested', 'data_export_completed', 'data_export_downloaded',
'data_deletion_requested', 'data_anonymization_completed',
'data_breach_detected', 'data_breach_reported'
```

## Signal-Based Audit Implementation

### User Profile Changes
```python
@receiver(post_save, sender=User)
def audit_user_profile_changes(sender, instance, created, **kwargs):
    """Automatically audit critical user profile changes"""
    if created:
        return

    update_fields = kwargs.get('update_fields', None)
    if update_fields:
        sensitive_fields = {'email', 'phone', 'staff_role', 'two_factor_enabled'}
        changed_fields = set(update_fields) & sensitive_fields

        for field in changed_fields:
            _create_audit_event(
                action=f'{field}_changed',
                user=instance,
                content_object=instance,
                new_values={field: getattr(instance, field)},
                metadata={'security_sensitive': True}
            )
```

### Customer Relationship Changes
```python
@receiver(post_save, sender=CustomerMembership)
def audit_customer_membership_changes(sender, instance, created, **kwargs):
    """Audit customer relationship and role changes"""
    if created:
        _create_audit_event(
            'customer_membership_created',
            user=instance.user,
            content_object=instance,
            metadata={'authorization_change': True}
        )
```

### Custom Business Signals
```python
# Custom signals for business events
api_key_generated = Signal()
privacy_settings_changed = Signal()
customer_context_switched = Signal()

# Usage in views
api_key_generated.send(
    sender=None,
    user=request.user,
    api_key_info={'id': key.id, 'name': key.name},
    request=request
)
```

## Performance Optimizations

### Database Indexing Strategy
```sql
-- Security analysis indexes
CREATE INDEX idx_audit_category_time ON audit_event(category, timestamp DESC);
CREATE INDEX idx_audit_severity_time ON audit_event(severity, timestamp DESC);
CREATE INDEX idx_audit_sensitive_time ON audit_event(is_sensitive, timestamp DESC);
CREATE INDEX idx_audit_review_time ON audit_event(requires_review, timestamp DESC);

-- Threat detection indexes
CREATE INDEX idx_audit_cat_sev_time ON audit_event(category, severity, timestamp DESC);
CREATE INDEX idx_audit_user_cat_time ON audit_event(user_id, category, timestamp DESC);
CREATE INDEX idx_audit_ip_sev_time ON audit_event(ip_address, severity, timestamp DESC);

-- Compliance reporting indexes
CREATE INDEX idx_audit_compliance ON audit_event(user_id, category, is_sensitive, timestamp DESC);
CREATE INDEX idx_audit_time_cat ON audit_event(timestamp, category);
```

### Query Budget Documentation
```python
# List views with documented query budgets
def audit_dashboard_view(request):
    """
    Query Budget: 4 queries
    1. High severity events (1 query)
    2. Recent user activity (1 query)
    3. Compliance events (1 query)
    4. Security incidents (1 query)
    """
```

## Security Analysis Capabilities

### Threat Detection Queries
```python
# Detect brute force attempts
failed_logins = AuditEvent.objects.filter(
    action__startswith='login_failed',
    ip_address=target_ip,
    timestamp__gte=timezone.now() - timedelta(minutes=15)
).count()

# Identify privilege escalation
privilege_changes = AuditEvent.objects.filter(
    category='authorization',
    severity='high',
    requires_review=True,
    timestamp__gte=timezone.now() - timedelta(days=7)
)

# Monitor sensitive data access
sensitive_activity = AuditEvent.objects.filter(
    is_sensitive=True,
    user=target_user,
    timestamp__gte=timezone.now() - timedelta(days=30)
).order_by('-timestamp')
```

### Compliance Reporting
```python
# GDPR Article 30 - Records of processing
gdpr_events = AuditEvent.objects.filter(
    category__in=['privacy', 'data_protection'],
    timestamp__range=[start_date, end_date]
).values('action', 'user__email', 'timestamp', 'metadata')

# Romanian business compliance
business_events = AuditEvent.objects.filter(
    category='business_operation',
    action__in=['invoice_accessed', 'tax_information_updated'],
    timestamp__gte=retention_start_date
)
```

## Usage Examples

### Manual Audit Event Creation
```python
from apps.audit.services import AuditService, AuditEventData, AuditContext

# Create custom audit event
context = AuditContext(
    user=request.user,
    ip_address=get_client_ip(request),
    user_agent=request.META.get('HTTP_USER_AGENT'),
    session_key=request.session.session_key,
    metadata={'custom_field': 'value'}
)

event_data = AuditEventData(
    event_type='custom_business_action',
    content_object=affected_object,
    old_values={'field': 'old_value'},
    new_values={'field': 'new_value'},
    description='Custom business action performed'
)

audit_event = AuditService.log_event(event_data, context)
```

### 2FA Event Logging
```python
from apps.audit.services import TwoFactorAuditRequest

# Log 2FA event
request = TwoFactorAuditRequest(
    event_type='2fa_backup_code_used',
    user=request.user,
    context=AuditContext(
        ip_address=get_client_ip(request),
        metadata={'backup_codes_remaining': remaining_codes}
    ),
    description='User used 2FA backup code for authentication'
)

AuditService.log_2fa_event(request)
```

### GDPR Compliance Events
```python
from apps.audit.services import ComplianceEventRequest

# Log GDPR compliance event
compliance_request = ComplianceEventRequest(
    compliance_type='gdpr_consent',
    reference_id=f'consent_{user.id}_{timestamp}',
    description='User granted marketing consent',
    user=user,
    status='success',
    evidence={'consent_timestamp': timezone.now().isoformat()},
    metadata={'consent_method': 'web_form', 'ip_address': client_ip}
)

AuditService.log_compliance_event(compliance_request)
```

## Testing Strategy

### Comprehensive Test Coverage
```python
# Test audit signal functionality
def test_user_profile_change_audit():
    user = User.objects.create_user(email='test@example.com')
    user.email = 'new@example.com'
    user.save(update_fields=['email'])

    # Verify audit event
    audit_event = AuditEvent.objects.get(action='email_changed')
    assert audit_event.category == 'account_management'
    assert audit_event.severity == 'medium'
    assert audit_event.is_sensitive is True

# Test security event detection
def test_security_incident_flagging():
    _create_audit_event(
        action='password_compromised',
        user=user,
        metadata={'threat_level': 'high'}
    )

    audit_event = AuditEvent.objects.get(action='password_compromised')
    assert audit_event.severity == 'high'
    assert audit_event.requires_review is True
```

## Monitoring and Alerting

### Critical Event Detection
```python
# Events that trigger immediate alerts
CRITICAL_EVENTS = [
    'data_breach_detected',
    'security_incident_detected',
    'password_compromised',
    '2fa_admin_reset',
    'privilege_escalation_attempt'
]

# Events requiring review
REVIEW_REQUIRED_EVENTS = [
    'staff_role_changed',
    'gdpr_consent_withdrawn',
    'data_export_requested',
    'user_impersonation_started'
]
```

### Real-time Monitoring
```python
# Stream processing for real-time alerts
def process_audit_event(audit_event):
    if audit_event.severity == 'critical':
        send_security_alert(audit_event)

    if audit_event.requires_review:
        flag_for_manual_review(audit_event)

    if detect_anomalous_pattern(audit_event):
        trigger_investigation_workflow(audit_event)
```

## Data Retention and Archival

### Retention Policies
- **Security Events**: 7 years (Romanian business law)
- **Authentication Logs**: 2 years (GDPR reasonable period)
- **GDPR Compliance Events**: Indefinite (legal requirement)
- **General Activity**: 1 year (operational needs)

### Archival Strategy
```python
# Automated archival process
def archive_old_events():
    cutoff_date = timezone.now() - timedelta(days=365)

    # Archive non-critical events older than 1 year
    old_events = AuditEvent.objects.filter(
        timestamp__lt=cutoff_date,
        severity__in=['low', 'medium'],
        category__in=['business_operation']
    )

    # Export to long-term storage
    archive_to_s3(old_events)
    old_events.delete()
```

## Best Practices

### Security Considerations
1. **Immutable Logs**: Audit events cannot be modified after creation
2. **Encryption**: Sensitive metadata is encrypted at rest
3. **Access Control**: Audit logs require special permissions to view
4. **Integrity**: Event hashing prevents tampering
5. **Redundancy**: Critical events are replicated to external systems

### Performance Guidelines
1. **Asynchronous Logging**: Use background tasks for non-critical events
2. **Batch Operations**: Group related events to reduce database load
3. **Index Strategy**: Optimize queries for common access patterns
4. **Archival**: Regular cleanup of old events
5. **Monitoring**: Track audit system performance metrics

### Compliance Requirements
1. **Data Minimization**: Only log necessary information
2. **Purpose Limitation**: Use audit data only for stated purposes
3. **Access Logging**: Audit access to audit logs themselves
4. **Retention Limits**: Respect legal retention requirements
5. **Subject Rights**: Support GDPR data subject requests

## Integration with External Systems

### SIEM Integration
```python
# Export events to SIEM systems
def export_to_siem(events):
    for event in events:
        siem_event = {
            'timestamp': event.timestamp.isoformat(),
            'severity': event.severity,
            'category': event.category,
            'user': event.user.email if event.user else 'System',
            'action': event.action,
            'source_ip': event.ip_address,
            'metadata': event.metadata
        }
        send_to_siem(siem_event)
```

### Compliance Dashboards
```python
# Real-time compliance metrics
def get_compliance_metrics():
    return {
        'gdpr_events_today': AuditEvent.objects.filter(
            category='privacy',
            timestamp__date=timezone.now().date()
        ).count(),
        'security_incidents_week': AuditEvent.objects.filter(
            category='security_event',
            severity='critical',
            timestamp__gte=timezone.now() - timedelta(days=7)
        ).count(),
        'failed_logins_hour': AuditEvent.objects.filter(
            action__startswith='login_failed',
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).count()
    }
```

## Conclusion

The PRAHO comprehensive audit system provides enterprise-grade logging and monitoring capabilities that meet the highest industry standards for security, compliance, and regulatory requirements. With over 200 event types, 10 security categories, and automated signal-based logging, the system ensures complete visibility into all user activities while maintaining optimal performance through strategic indexing and efficient query patterns.

The system supports real-time threat detection, compliance reporting, forensic investigation, and integration with external security tools, making it suitable for organizations with stringent security and regulatory requirements.
