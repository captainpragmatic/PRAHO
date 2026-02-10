"""
Virtualmin Input Validation Framework - PRAHO Platform
Comprehensive validation for Virtualmin API parameters with security focus.
"""

import ipaddress
import re
from typing import Any

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.common.validators import SecureInputValidator

# Validation constants
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_STRENGTH_TYPES = 3
MAX_EMAIL_LENGTH = 254  # RFC 5321 limit
MAX_EMAIL_LOCAL_LENGTH = 64  # RFC 5321 limit
MAX_TEMPLATE_NAME_LENGTH = 50
MAX_PARAMETER_VALUE_LENGTH = 1000
MIN_DOMAIN_LENGTH = 3
MAX_DOMAIN_LENGTH = 253  # RFC 1035 limit
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 32


class VirtualminValidator:
    """
    Secure validation for Virtualmin API parameters.

    Follows PRAHO validation patterns from apps/common/validators.py with
    Virtualmin-specific security considerations.
    """

    # Virtualmin domain name validation (RFC 1035 compliant)
    DOMAIN_PATTERN = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )

    # Virtualmin username validation (alphanumeric + underscore, no spaces)
    USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,32}$")

    # Virtualmin password validation (printable ASCII, exclude problematic chars)
    PASSWORD_PATTERN = re.compile(r"^[!-~]{8,128}$")

    # Email validation pattern (stricter than Django's for Virtualmin)
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    # Template name validation
    TEMPLATE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,50}$")

    @staticmethod
    def validate_domain_name(domain: str) -> str:
        """
        Validate domain name for Virtualmin virtual server creation.

        Args:
            domain: Domain name to validate

        Returns:
            Normalized domain name (lowercase)

        Raises:
            ValidationError: If domain is invalid
        """
        if not domain:
            raise ValidationError(_("Domain name is required"))

        # Input validation and security check
        if not isinstance(domain, str):
            raise ValidationError(_("Invalid input format"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(domain)

        # Normalize to lowercase
        domain = domain.lower().strip()

        # Length validation
        if len(domain) < MIN_DOMAIN_LENGTH:
            raise ValidationError(_("Domain name must be at least 3 characters"))
        if len(domain) > MAX_DOMAIN_LENGTH:  # RFC 1035 limit
            raise ValidationError(_("Domain name must be less than 253 characters"))

        # Pattern validation
        if not VirtualminValidator.DOMAIN_PATTERN.match(domain):
            raise ValidationError(_("Invalid domain name format"))

        # Check for reserved domains
        reserved_domains = ["localhost", "example.com", "example.org", "example.net", "test.local", "invalid", "local"]
        if domain in reserved_domains:
            raise ValidationError(_("Domain name is reserved"))

        # Check for suspicious patterns
        if ".." in domain or domain.startswith(".") or domain.endswith("."):
            raise ValidationError(_("Invalid domain name format"))

        return domain

    @staticmethod
    def validate_username(username: str) -> str:
        """
        Validate username for Virtualmin account.

        Args:
            username: Username to validate

        Returns:
            Validated username

        Raises:
            ValidationError: If username is invalid
        """
        if not username:
            raise ValidationError(_("Username is required"))

        # Input validation and security check
        if not isinstance(username, str):
            raise ValidationError(_("Invalid input format"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(username)

        # Length validation
        if len(username) < MIN_USERNAME_LENGTH:
            raise ValidationError(_("Username must be at least 3 characters"))
        if len(username) > MAX_USERNAME_LENGTH:
            raise ValidationError(_("Username must be less than 32 characters"))

        # Pattern validation
        if not VirtualminValidator.USERNAME_PATTERN.match(username):
            raise ValidationError(_("Username can only contain letters, numbers, and underscores"))

        # Check for reserved usernames
        reserved_usernames = [
            "root",
            "admin",
            "administrator",
            "www",
            "mail",
            "ftp",
            "test",
            "guest",
            "daemon",
            "nobody",
            "www-data",
        ]
        if username.lower() in reserved_usernames:
            raise ValidationError(_("Username is reserved"))

        return username

    @staticmethod
    def validate_api_username(username: str) -> str:
        """
        Validate username for Virtualmin API access (less restrictive than virtual account usernames).

        Args:
            username: API username to validate

        Returns:
            Validated username

        Raises:
            ValidationError: If username is invalid
        """
        if not username:
            raise ValidationError(_("Username is required"))

        # Input validation and security check
        if not isinstance(username, str):
            raise ValidationError(_("Invalid input format"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(username)

        # Length validation
        if len(username) < MIN_USERNAME_LENGTH:
            raise ValidationError(_("Username must be at least 3 characters"))
        if len(username) > MAX_USERNAME_LENGTH:
            raise ValidationError(_("Username must be less than 32 characters"))

        # Pattern validation
        if not VirtualminValidator.USERNAME_PATTERN.match(username):
            raise ValidationError(_("Username can only contain letters, numbers, and underscores"))

        # Check for reserved API usernames (more permissive for API access)
        reserved_api_usernames = [
            "admin",
            "administrator",
            "www",
            "mail",
            "ftp",
            "test",
            "guest",
            "daemon",
            "nobody",
            "www-data",
        ]
        # Note: 'root' is explicitly allowed for API access as it's common in Virtualmin setups
        if username.lower() in reserved_api_usernames:
            raise ValidationError(_("Username is reserved"))

        return username

    @staticmethod
    def validate_password(password: str) -> str:
        """
        Validate password for Virtualmin account.

        Args:
            password: Password to validate

        Returns:
            Validated password

        Raises:
            ValidationError: If password is invalid
        """
        if not password:
            raise ValidationError(_("Password is required"))

        # Length validation
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValidationError(_("Password must be at least 8 characters"))
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValidationError(_("Password must be less than 128 characters"))

        # Pattern validation (printable ASCII only)
        if not VirtualminValidator.PASSWORD_PATTERN.match(password):
            raise ValidationError(_("Password contains invalid characters"))

        # Strength validation
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        strength_count = sum([has_upper, has_lower, has_digit, has_special])
        if strength_count < MIN_PASSWORD_STRENGTH_TYPES:
            raise ValidationError(
                _("Password must contain at least 3 of: uppercase, lowercase, digits, special characters")
            )

        return password

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate email address for Virtualmin mailbox.

        Args:
            email: Email address to validate

        Returns:
            Normalized email address (lowercase)

        Raises:
            ValidationError: If email is invalid
        """
        if not email:
            raise ValidationError(_("Email address is required"))

        # Input validation and security check
        if not isinstance(email, str):
            raise ValidationError(_("Invalid input format"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(email)

        email = email.lower().strip()

        # Length validation
        if len(email) > MAX_EMAIL_LENGTH:  # RFC 5321 limit
            raise ValidationError(_("Email address is too long"))

        # Pattern validation
        if not VirtualminValidator.EMAIL_PATTERN.match(email):
            raise ValidationError(_("Invalid email address format"))

        # Split validation
        if email.count("@") != 1:
            raise ValidationError(_("Email address must contain exactly one @ symbol"))

        local, domain = email.split("@")

        # Local part validation
        if len(local) > MAX_EMAIL_LOCAL_LENGTH:  # RFC 5321 limit
            raise ValidationError(_("Email local part is too long"))
        if not local:
            raise ValidationError(_("Email local part is required"))

        # Domain part validation (reuse domain validator)
        try:
            VirtualminValidator.validate_domain_name(domain)
        except ValidationError as e:
            raise ValidationError(f"Invalid email domain: {e}") from e

        return email

    @staticmethod
    def validate_template_name(template: str) -> str:
        """
        Validate Virtualmin template name.

        Args:
            template: Template name to validate

        Returns:
            Validated template name

        Raises:
            ValidationError: If template name is invalid
        """
        if not template:
            return "Default"  # Virtualmin default template

        # Input validation and security check
        if not isinstance(template, str):
            raise ValidationError(_("Invalid input format"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(template)

        # Length validation
        if len(template) > MAX_TEMPLATE_NAME_LENGTH:
            raise ValidationError(_("Template name must be less than 50 characters"))

        # Pattern validation
        if not VirtualminValidator.TEMPLATE_PATTERN.match(template):
            raise ValidationError(_("Template name can only contain letters, numbers, hyphens, and underscores"))

        return template

    @staticmethod
    def validate_quota_mb(quota: int | None) -> int | None:
        """
        Validate disk quota in megabytes.

        Args:
            quota: Quota in MB (None for unlimited)

        Returns:
            Validated quota or None for unlimited

        Raises:
            ValidationError: If quota is invalid
        """
        if quota is None:
            return None

        if not isinstance(quota, int):
            raise ValidationError(_("Quota must be an integer"))

        if quota < 0:
            raise ValidationError(_("Quota cannot be negative"))

        # Reasonable limits (1TB max)
        if quota > 1024 * 1024:  # 1TB in MB
            raise ValidationError(_("Quota too large (maximum 1TB)"))

        return quota

    @staticmethod
    def validate_bandwidth_mb(bandwidth: int | None) -> int | None:
        """
        Validate monthly bandwidth in megabytes.

        Args:
            bandwidth: Bandwidth in MB (None for unlimited)

        Returns:
            Validated bandwidth or None for unlimited

        Raises:
            ValidationError: If bandwidth is invalid
        """
        if bandwidth is None:
            return None

        if not isinstance(bandwidth, int):
            raise ValidationError(_("Bandwidth must be an integer"))

        if bandwidth < 0:
            raise ValidationError(_("Bandwidth cannot be negative"))

        # Reasonable limits (10TB max per month)
        if bandwidth > 10 * 1024 * 1024:  # 10TB in MB
            raise ValidationError(_("Bandwidth too large (maximum 10TB/month)"))

        return bandwidth

    @staticmethod
    def validate_server_hostname(hostname: str) -> str:
        """
        Validate Virtualmin server hostname.

        Args:
            hostname: Server hostname to validate

        Returns:
            Validated hostname

        Raises:
            ValidationError: If hostname is invalid
        """
        if not hostname:
            raise ValidationError(_("Server hostname is required"))

        # Input validation and security check
        if not isinstance(hostname, str):
            raise ValidationError(_("Invalid input format"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(hostname)

        hostname = hostname.lower().strip()

        # Try IP address first
        try:
            ipaddress.ip_address(hostname)
            return hostname  # Valid IP address
        except ValueError:
            pass

        # Validate as domain name
        return VirtualminValidator.validate_domain_name(hostname)

    @staticmethod
    def validate_virtualmin_program(program: str) -> str:
        """
        Validate Virtualmin API program name.

        Args:
            program: Program name to validate

        Returns:
            Validated program name

        Raises:
            ValidationError: If program is not allowed
        """
        if not program:
            raise ValidationError(_("Program name is required"))

        # Input validation and security check
        if not isinstance(program, str):
            raise ValidationError(_("Invalid input format"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(program)

        # Allowed Virtualmin programs (whitelist approach)
        allowed_programs = {
            # Domain management
            "create-domain",
            "delete-domain",
            "list-domains",
            "modify-domain",
            "enable-domain",
            "disable-domain",
            "get-domain",
            # Alias management
            "create-alias",
            "delete-alias",
            "list-aliases",
            # Subdomain management
            "create-subdomain",
            "delete-subdomain",
            "list-subdomains",
            # User management
            "create-user",
            "delete-user",
            "list-users",
            "modify-user",
            # Database management
            "create-database",
            "delete-database",
            "list-databases",
            # SSL management
            "request-letsencrypt-cert",
            "install-cert",
            "list-certs",
            # DNS management
            "create-dns",
            "delete-dns",
            "list-dns",
            "modify-dns",
            # Backup management
            "backup-domain",
            "restore-domain",
            "list-backups",
            # Template management
            "get-template",
            "list-templates",
            # Monitoring
            "list-bandwidth",
            # System info
            "list-plans",
            "get-plan",
            "info",
        }

        if program not in allowed_programs:
            raise ValidationError(f"Program '{program}' is not allowed")

        return program

    @staticmethod
    def validate_api_response_format(format_type: str) -> str:
        """
        Validate Virtualmin API response format.

        Args:
            format_type: Response format to validate

        Returns:
            Validated format type

        Raises:
            ValidationError: If format is not supported
        """
        if not format_type:
            return "json"  # Default to JSON

        format_type = format_type.lower().strip()

        allowed_formats = {"json", "xml", "text"}
        if format_type not in allowed_formats:
            raise ValidationError(f"Format '{format_type}' not supported. Use: {', '.join(allowed_formats)}")

        return format_type

    @staticmethod
    def validate_virtualmin_params(params: dict[str, Any]) -> dict[str, Any]:
        """
        Validate and sanitize Virtualmin API parameters.

        Args:
            params: Parameters dictionary to validate

        Returns:
            Validated and sanitized parameters

        Raises:
            ValidationError: If any parameter is invalid
        """
        if not isinstance(params, dict):
            raise ValidationError(_("Parameters must be a dictionary"))

        validated_params = {}

        for key, value in params.items():
            # Validate parameter names
            if not isinstance(key, str):
                raise ValidationError(_("Invalid parameter name"))

            # XSS/injection check for key
            SecureInputValidator._check_malicious_patterns(key)

            # Validate parameter values based on type
            if isinstance(value, str):
                # XSS/injection check for string values
                SecureInputValidator._check_malicious_patterns(value)

            # Length limits for all string parameters
            if isinstance(value, str) and len(value) > MAX_PARAMETER_VALUE_LENGTH:
                raise ValidationError(f"Parameter '{key}' value too long")

            validated_params[key] = value

        return validated_params
