"""
PRAHO Platform Constants

Centralized constants for Romanian business compliance, service limits, and SLA definitions.
This file serves as the single source of truth for business rules that span multiple apps.

Following PRAHO architecture principles:
- O(1) maintenance for Romanian legal compliance updates
- Self-documenting business logic
- AI/LLM friendly code comprehension
- Consistent with apps/common/ pattern
"""

from decimal import Decimal
from typing import Final

# ===============================================================================
# ROMANIAN COMPLIANCE 🇷🇴
# ===============================================================================

# Romanian VAT (TVA) regulations - used in billing, orders, customers
ROMANIAN_VAT_RATE: Final[Decimal] = Decimal('0.19')  # 19% standard VAT rate

# Romanian CUI (Unique Registration Code) validation rules
CUI_MIN_LENGTH: Final[int] = 2       # Minimum CUI length
CUI_MAX_LENGTH: Final[int] = 10      # Maximum CUI length

# Business payment terms
PAYMENT_GRACE_PERIOD_DAYS: Final[int] = 5           # Payment grace period
INVOICE_DUE_DAYS_DEFAULT: Final[int] = 30           # Default invoice due period
PROFORMA_VALIDITY_DAYS: Final[int] = 30             # Proforma invoice validity

# Romanian e-Factura compliance
EFACTURA_BATCH_SIZE: Final[int] = 100               # Max invoices per e-Factura batch

# ===============================================================================
# SERVICE LIMITS ⚡
# ===============================================================================

# Domain management limits
MAX_DOMAINS_PER_PACKAGE: Final[int] = 100           # Maximum domains per hosting package
MAX_SUBDOMAINS_PER_DOMAIN: Final[int] = 50          # Maximum subdomains per domain

# Pagination and list views (Query Budget compliance)
DEFAULT_PAGE_SIZE: Final[int] = 25                  # Standard pagination size
MAX_PAGE_SIZE: Final[int] = 100                     # Maximum allowed page size
MIN_PAGE_SIZE: Final[int] = 5                       # Minimum allowed page size

# API rate limiting
API_RATE_LIMIT_PER_HOUR: Final[int] = 1000          # API calls per hour per user
API_BURST_LIMIT: Final[int] = 50                    # Burst limit for API calls

# File upload limits
MAX_ATTACHMENT_SIZE_MB: Final[int] = 25             # Maximum file attachment size
MAX_ATTACHMENTS_PER_TICKET: Final[int] = 5         # Maximum attachments per ticket

# ===============================================================================
# SUPPORT SLA 🎯
# ===============================================================================

# Ticket response time SLAs (in hours)
CRITICAL_TICKET_RESPONSE_HOURS: Final[int] = 1      # Critical priority response time
HIGH_TICKET_RESPONSE_HOURS: Final[int] = 4          # High priority response time
STANDARD_TICKET_RESPONSE_HOURS: Final[int] = 24     # Standard priority response time
LOW_TICKET_RESPONSE_HOURS: Final[int] = 72          # Low priority response time

# Ticket escalation rules
TICKET_AUTO_ESCALATION_HOURS: Final[int] = 48       # Auto-escalate after hours
MAX_TICKET_REASSIGNMENTS: Final[int] = 3            # Maximum reassignment count

# ===============================================================================
# SECURITY & AUTHENTICATION 🔐
# ===============================================================================

# Account lockout policies
MAX_LOGIN_ATTEMPTS: Final[int] = 5                  # Max failed login attempts
ACCOUNT_LOCKOUT_DURATION_MINUTES: Final[int] = 15   # Account lockout duration
PASSWORD_RESET_TOKEN_VALIDITY_HOURS: Final[int] = 24 # Password reset token validity

# 2FA settings
BACKUP_CODE_COUNT: Final[int] = 10                  # Number of backup codes generated
TOTP_VALIDITY_WINDOW: Final[int] = 1                # TOTP time window (30s * window)

# Session management
SESSION_TIMEOUT_MINUTES: Final[int] = 120           # Session timeout for regular users
ADMIN_SESSION_TIMEOUT_MINUTES: Final[int] = 60      # Session timeout for admin users

# ===============================================================================
# BILLING & FINANCIAL 💰
# ===============================================================================

# Currency and decimal precision
CURRENCY_DECIMAL_PLACES: Final[int] = 2             # Decimal places for currency
CURRENCY_MAX_DIGITS: Final[int] = 10                # Maximum digits for currency fields

# Payment processing
PAYMENT_RETRY_ATTEMPTS: Final[int] = 3              # Payment retry attempts
PAYMENT_RETRY_DELAY_HOURS: Final[int] = 24          # Delay between payment retries

# Credit and billing
MINIMUM_CREDIT_BALANCE: Final[Decimal] = Decimal('0.01')  # Minimum credit balance
NEGATIVE_BALANCE_THRESHOLD: Final[Decimal] = Decimal('-100.00')  # Service suspension threshold

# ===============================================================================
# PROVISIONING & HOSTING 🖥️
# ===============================================================================

# Service provisioning timeouts (in minutes)
SERVICE_PROVISION_TIMEOUT_MINUTES: Final[int] = 30  # Max provisioning time
SERVICE_SUSPEND_TIMEOUT_MINUTES: Final[int] = 15    # Max suspension time
SERVICE_TERMINATE_TIMEOUT_MINUTES: Final[int] = 60  # Max termination time

# Resource limits
DEFAULT_DISK_QUOTA_GB: Final[int] = 10              # Default disk quota in GB
DEFAULT_BANDWIDTH_QUOTA_GB: Final[int] = 100        # Default bandwidth quota in GB
MAX_EMAIL_ACCOUNTS_PER_PACKAGE: Final[int] = 50     # Max email accounts per package

# ===============================================================================
# MONITORING & ALERTS 📊
# ===============================================================================

# System monitoring thresholds
CPU_USAGE_WARNING_THRESHOLD: Final[int] = 80        # CPU usage warning threshold (%)
MEMORY_USAGE_WARNING_THRESHOLD: Final[int] = 85     # Memory usage warning threshold (%)
DISK_USAGE_WARNING_THRESHOLD: Final[int] = 90       # Disk usage warning threshold (%)

# Alert frequencies
ALERT_COOLDOWN_MINUTES: Final[int] = 60             # Minimum time between same alerts
HEALTH_CHECK_INTERVAL_MINUTES: Final[int] = 5       # Health check frequency

# ===============================================================================
# DATA RETENTION & GDPR 🗄️
# ===============================================================================

# GDPR compliance periods
GDPR_DATA_RETENTION_YEARS: Final[int] = 7           # General data retention period
GDPR_LOG_RETENTION_MONTHS: Final[int] = 12          # Log retention period
GDPR_EXPORT_RETENTION_DAYS: Final[int] = 30         # GDPR export file retention

# Audit trail
AUDIT_LOG_RETENTION_YEARS: Final[int] = 10          # Audit log retention for compliance
FAILED_LOGIN_LOG_RETENTION_MONTHS: Final[int] = 6   # Failed login attempt retention

# ===============================================================================
# INTEGRATION LIMITS 🔗
# ===============================================================================

# Webhook settings
WEBHOOK_RETRY_ATTEMPTS: Final[int] = 5              # Webhook delivery retry attempts
WEBHOOK_TIMEOUT_SECONDS: Final[int] = 30            # Webhook request timeout
WEBHOOK_BATCH_SIZE: Final[int] = 50                 # Webhooks processed per batch

# External API timeouts
API_REQUEST_TIMEOUT_SECONDS: Final[int] = 30        # External API request timeout
API_CONNECTION_TIMEOUT_SECONDS: Final[int] = 10     # API connection timeout

# ===============================================================================
# EMAIL & NOTIFICATIONS 📧
# ===============================================================================

# Email sending limits
EMAIL_SEND_RATE_PER_HOUR: Final[int] = 100          # Emails per hour limit
EMAIL_BATCH_SIZE: Final[int] = 50                   # Emails processed per batch

# Notification preferences
NOTIFICATION_DIGEST_HOURS: Final[int] = 24          # Digest notification frequency
MAX_NOTIFICATION_HISTORY: Final[int] = 1000         # Max notifications kept in history

# ===============================================================================
# FILE PROCESSING & DISPLAY 📁
# ===============================================================================

# File size conversion
FILE_SIZE_CONVERSION_FACTOR: Final[int] = 1024      # Bytes to KB/MB/GB conversion
FILE_SIZE_CONVERSION_FACTOR_FLOAT: Final[float] = 1024.0  # Float version for precise calculations

# Display limits for admin interfaces  
ADMIN_DISPLAY_ITEM_LIMIT: Final[int] = 5            # Items shown before truncation
USER_AGENT_DISPLAY_LIMIT: Final[int] = 50           # Characters shown for user agent
IDENTIFIER_MAX_LENGTH: Final[int] = 200             # Maximum identifier length

# ===============================================================================
# SUCCESS RATES & THRESHOLDS 📊
# ===============================================================================

# Billing success rate thresholds (percentages)
SUCCESS_RATE_EXCELLENT_THRESHOLD: Final[int] = 50   # Green threshold for success rates
SUCCESS_RATE_WARNING_THRESHOLD: Final[int] = 25     # Orange threshold for success rates

# ===============================================================================
# HTTP STATUS CODES 🌐
# ===============================================================================

# HTTP status code categories
HTTP_CLIENT_ERROR_THRESHOLD: Final[int] = 400       # Start of 4xx client errors

# ===============================================================================
# RATE LIMITING & SECURITY THRESHOLDS 🚨
# ===============================================================================

# Customer service rate limits
MAX_CUSTOMER_LOOKUPS_PER_HOUR: Final[int] = 20      # Customer lookups per IP per hour
MAX_JOIN_NOTIFICATIONS_PER_HOUR: Final[int] = 10    # Join notifications per customer per hour

# Suspicious activity detection
SUSPICIOUS_IP_THRESHOLD: Final[int] = 3             # Different IPs to trigger suspicious activity

# Timing attack prevention
MIN_RESPONSE_TIME_SECONDS: Final[float] = 0.1       # Minimum response time to prevent timing attacks

# Backup code management
BACKUP_CODE_LENGTH: Final[int] = 8                  # Standard backup code length
BACKUP_CODE_LOW_WARNING_THRESHOLD: Final[int] = 2   # Warning when backup codes are low

# ===============================================================================
# ROMANIAN LANGUAGE PLURALIZATION 🇷🇴
# ===============================================================================

# Romanian plural form rules (1, 2-19, 20+)
ROMANIAN_PLURAL_SINGLE: Final[int] = 1              # Singular form
ROMANIAN_PLURAL_FEW_MIN: Final[int] = 2             # Start of "few" plural form  
ROMANIAN_PLURAL_FEW_MAX: Final[int] = 19            # End of "few" plural form
ROMANIAN_PLURAL_MANY_MIN: Final[int] = 20           # Start of "many" plural form

# ===============================================================================
# FUNCTION ARGUMENT POSITIONS 🔧
# ===============================================================================

# Security decorator function argument positions (implementation details)
USER_DATA_ARG_POSITION: Final[int] = 2              # args[1] - user data dictionary position  
CUSTOMER_DATA_ARG_POSITION: Final[int] = 3          # args[2] - customer data dictionary position
INVITER_ARG_POSITION: Final[int] = 1                # args[0] - inviter position
INVITEE_EMAIL_ARG_POSITION: Final[int] = 2          # args[1] - invitee email position  
INVITATION_CUSTOMER_ARG_POSITION: Final[int] = 3    # args[2] - customer position in invitations
INVITATION_ROLE_ARG_POSITION: Final[int] = 4        # args[3] - role position in invitations

# ===============================================================================
# VALIDATION & FORMATTING LENGTHS 📏
# ===============================================================================

# Company and business validation
COMPANY_NAME_MIN_LENGTH: Final[int] = 2             # Minimum company name length
SEARCH_QUERY_MIN_LENGTH: Final[int] = 2             # Minimum search query length

# Email format validation  
EMAIL_PARTS_COUNT: Final[int] = 2                   # Expected parts when splitting email on '@'

# Domain name limits (RFC 1035)
DOMAIN_NAME_MAX_LENGTH: Final[int] = 253            # RFC 1035 max domain name length

# Romanian phone number formatting
PHONE_MOBILE_LENGTH: Final[int] = 9                 # Mobile number length (without country code)
PHONE_LANDLINE_LENGTH: Final[int] = 10              # Landline number length (with area code)
PHONE_FULL_INTERNATIONAL_LENGTH: Final[int] = 11    # Full international format (+40XXXXXXXXX)
PHONE_MIN_VALID_LENGTH: Final[int] = 7              # Minimum valid phone number length

# Romanian postal codes
ROMANIAN_POSTAL_CODE_LENGTH: Final[int] = 6         # Romanian postal codes are 6 digits

# Romanian IBAN format
ROMANIAN_IBAN_LENGTH: Final[int] = 24               # Romanian IBAN is 24 characters

# ===============================================================================
# TIME & DATE CONSTANTS ⏰
# ===============================================================================

# Time conversion constants
SECONDS_PER_MINUTE: Final[int] = 60                  # Seconds in a minute
SECONDS_PER_HOUR: Final[int] = 3600                  # Seconds in an hour (60 * 60)
SECONDS_PER_DAY: Final[int] = 86400                  # Seconds in a day (24 * 60 * 60)
SECONDS_PER_TWO_DAYS: Final[int] = 172800            # Seconds in two days (2 * 86400)
SECONDS_PER_WEEK: Final[int] = 604800                # Seconds in a week (7 * 86400)

# Minutes conversion
MINUTES_PER_HOUR: Final[int] = 60                    # Minutes in an hour

# Days conversion
DAYS_PER_WEEK: Final[int] = 7                        # Days in a week
DAYS_CRITICAL_EXPIRY: Final[int] = 7                 # Critical expiry threshold (days)
DAYS_WARNING_EXPIRY: Final[int] = 30                 # Warning expiry threshold (days)

# Romanian language time formatting thresholds
ROMANIAN_TIME_MINUTE_PLURAL_THRESHOLD: Final[int] = 20  # Minutes threshold for Romanian plural
ROMANIAN_TIME_HOUR_PLURAL_THRESHOLD: Final[int] = 20    # Hours threshold for Romanian plural

# ===============================================================================
# DISPLAY & FORMATTING CONSTANTS 🎨
# ===============================================================================

# Text truncation limits
TEXT_TRUNCATE_LIMIT: Final[int] = 30                 # Characters before truncation
TEXT_TRUNCATE_DISPLAY: Final[int] = 27               # Characters shown after truncation

# List display limits
LIST_DISPLAY_LIMIT: Final[int] = 5                   # Items shown before "show more"

# ===============================================================================
# PERFORMANCE & MONITORING THRESHOLDS 📊
# ===============================================================================

# Performance monitoring thresholds (percentages)
HIGH_USAGE_THRESHOLD: Final[int] = 90                # High usage warning (90%)
MEDIUM_USAGE_THRESHOLD: Final[int] = 75              # Medium usage warning (75%)
FULL_USAGE_THRESHOLD: Final[int] = 100               # Full usage threshold (100%)
RETRY_WARNING_THRESHOLD: Final[int] = 66             # Retry warning threshold (66%)

# Success rate thresholds for notifications (percentages)
EXCELLENT_SUCCESS_RATE: Final[int] = 95              # Excellent success rate threshold
GOOD_SUCCESS_RATE: Final[int] = 85                   # Good success rate threshold

# Text preview limits for admin displays
SUBJECT_PREVIEW_LIMIT: Final[int] = 50               # Email subject preview limit
TITLE_PREVIEW_LIMIT: Final[int] = 50                 # Title preview limit
CONTENT_PREVIEW_LIMIT: Final[int] = 100              # Content preview limit
DESCRIPTION_PREVIEW_LIMIT: Final[int] = 80           # Description preview limit
SUBJECT_PREVIEW_DISPLAY: Final[int] = 47             # Characters shown for subject
TITLE_PREVIEW_DISPLAY: Final[int] = 47               # Characters shown for title
CONTENT_PREVIEW_DISPLAY: Final[int] = 97             # Characters shown for content
DESCRIPTION_PREVIEW_DISPLAY: Final[int] = 77         # Characters shown for description

# Special values
NO_EXPIRY_SENTINEL: Final[int] = 999999              # Sentinel value for "no expiry"

# Time thresholds for urgent notifications (in seconds)
URGENT_RESPONSE_THRESHOLD: Final[int] = 3600         # 1 hour for urgent response
URGENT_RESOLUTION_THRESHOLD: Final[int] = 7200       # 2 hours for urgent resolution
