"""
Security Validation Utilities for PRAHO Portal
Production-safe secret validation with development-friendly warnings.
"""

import logging
import math
import os
import re
from typing import ClassVar

logger = logging.getLogger(__name__)

# Entropy thresholds for secret strength evaluation
MIN_ENTROPY_THRESHOLD = 3.5
GOOD_ENTROPY_THRESHOLD = 4.0
CHARSET_RATIO_THRESHOLD = 0.6
# Score thresholds for overall validation rating
STRONG_SCORE_THRESHOLD = 70
MODERATE_SCORE_THRESHOLD = 50
WEAK_SCORE_THRESHOLD = 20
RECOMMENDATION_SCORE_THRESHOLD = 80


# Entropy thresholds for secret strength evaluation
# Score thresholds for overall validation rating


class SecretValidationResult:
    """Result of secret validation with detailed feedback"""

    def __init__(self, is_valid: bool, score: int, issues: list[str], suggestions: list[str]):
        self.is_valid = is_valid
        self.score = score  # 0-100 security score
        self.issues = issues
        self.suggestions = suggestions

    def __bool__(self) -> bool:
        return self.is_valid


class SecretValidator:
    """
    🔒 Production-grade secret validation with development flexibility.

    Validation levels:
    - DEVELOPMENT: Warnings only, allows weak secrets
    - STAGING: Warnings become errors for non-dev secrets
    - PRODUCTION: Strict validation, fails fast on weak secrets
    """

    # Known weak/development secrets to flag immediately
    KNOWN_WEAK_SECRETS: ClassVar[set[str]] = {
        "portal-dev-key-change-in-production",
        "dev-shared-secret",
        "dev-shared-secret-change-in-production",
        "dev-key-change-in-production",
        "your-secret-key-here-change-in-production",
        "django-insecure",
        "secret-key",
        "change-me",
        "dev-token-123",
        "test-secret",
        "123456",
        "password",
        "secret",
        "admin",
    }

    # Common patterns that indicate weak secrets
    WEAK_PATTERNS: ClassVar[list[str]] = [
        r"^dev[-_]",  # Starts with "dev-" or "dev_"
        r"[-_]dev[-_]",  # Contains "-dev-" or "_dev_"
        r"test[-_]",  # Contains "test-" or "test_"
        r"change[-_]",  # Contains "change-"
        r"example",  # Contains "example"
        r"your[-_]",  # Contains "your-"
        r"placeholder",  # Contains "placeholder"
        r"^(secret|password|admin|key)$",  # Just common words
    ]

    def __init__(self, environment: str = "development"):
        """
        Initialize validator with environment context.

        Args:
            environment: 'development', 'staging', or 'production'
        """
        self.environment = environment.lower()

    def validate_secret(self, secret: str, secret_name: str, min_length: int = 32) -> SecretValidationResult:
        """
        🔒 Comprehensive secret validation with detailed feedback.

        Args:
            secret: The secret value to validate
            secret_name: Name of the secret (for logging)
            min_length: Minimum required length

        Returns:
            SecretValidationResult with validation details
        """
        issues = []
        suggestions = []
        score = 100  # Start with perfect score, deduct for issues

        # Basic checks
        if not secret:
            issues.append("Secret is empty or None")
            score = 0
        elif len(secret) < min_length:
            issues.append(f"Secret is too short ({len(secret)} chars, minimum {min_length})")
            score -= 30

        # Check against known weak secrets
        if secret.lower() in {s.lower() for s in self.KNOWN_WEAK_SECRETS}:
            issues.append("Secret matches a known development/weak default")
            score -= 50

        # Check against weak patterns
        for pattern in self.WEAK_PATTERNS:
            if re.search(pattern, secret.lower()):
                issues.append(f"Secret matches weak pattern: {pattern}")
                score -= 20
                break

        # Entropy analysis
        entropy_score = self._calculate_entropy(secret)
        if entropy_score < MIN_ENTROPY_THRESHOLD:  # Very low entropy
            issues.append(f"Secret has very low entropy ({entropy_score:.2f})")
            score -= 30
        elif entropy_score < GOOD_ENTROPY_THRESHOLD:  # Low entropy
            issues.append(f"Secret has low entropy ({entropy_score:.2f})")
            score -= 15

        # Character variety check
        variety_score = self._check_character_variety(secret)
        if variety_score < CHARSET_RATIO_THRESHOLD:
            issues.append("Secret lacks character variety (missing uppercase, lowercase, numbers, or symbols)")
            score -= 10

        # Generate suggestions for improvement
        if issues:
            suggestions.extend(self._generate_suggestions(secret_name, issues))

        # Determine if secret is valid based on environment
        is_valid = self._determine_validity(score, secret_name)

        return SecretValidationResult(is_valid=is_valid, score=max(0, score), issues=issues, suggestions=suggestions)

    def _calculate_entropy(self, secret: str) -> float:
        """Calculate Shannon entropy of the secret"""
        if not secret:
            return 0.0

        # Count character frequencies
        char_counts: dict[str, int] = {}
        for char in secret:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate Shannon entropy
        entropy = 0.0
        length = len(secret)
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _check_character_variety(self, secret: str) -> float:
        """Check variety of character types in secret"""
        if not secret:
            return 0.0

        has_lower = any(c.islower() for c in secret)
        has_upper = any(c.isupper() for c in secret)
        has_digit = any(c.isdigit() for c in secret)
        has_special = any(not c.isalnum() for c in secret)

        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        return variety_count / 4.0  # Return as ratio 0.0-1.0

    def _generate_suggestions(self, secret_name: str, issues: list[str]) -> list[str]:
        """Generate helpful suggestions for fixing secret issues"""
        suggestions = []

        if any("empty" in issue for issue in issues):
            suggestions.append(f"Set {secret_name} environment variable with a strong secret")

        if any("short" in issue for issue in issues):
            suggestions.append("Use a longer secret (32+ characters recommended)")

        if any("known" in issue or "weak pattern" in issue for issue in issues):
            suggestions.append("Generate a new cryptographically random secret")

        if any("entropy" in issue for issue in issues):
            suggestions.append("Use a more random secret with varied characters")

        if any("variety" in issue for issue in issues):
            suggestions.append("Include uppercase, lowercase, numbers, and symbols")

        # Add generation command
        suggestions.append(
            'Generate strong secret: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
        )

        return suggestions

    def _determine_validity(self, score: int, secret_name: str) -> bool:
        """Determine if secret is valid based on environment and score"""
        if self.environment == "production":
            # Production: Strict validation
            return score >= STRONG_SCORE_THRESHOLD  # High bar for production
        elif self.environment == "staging":
            # Staging: Medium validation (catch issues before prod)
            return score >= MODERATE_SCORE_THRESHOLD
        else:
            # Development: Permissive (allow weak secrets for dev ease)
            return score >= WEAK_SCORE_THRESHOLD  # Only block obviously broken secrets

    def validate_and_warn(self, secret: str, secret_name: str, min_length: int = 32) -> bool:
        """
        🔒 Validate secret and emit appropriate warnings/errors based on environment.

        Args:
            secret: The secret value to validate
            secret_name: Name of the secret (for logging)
            min_length: Minimum required length

        Returns:
            bool: True if secret is acceptable for current environment

        Raises:
            ValueError: In production/staging if secret is too weak
        """
        result = self.validate_secret(secret, secret_name, min_length)

        if result.is_valid:
            if result.score < RECOMMENDATION_SCORE_THRESHOLD:  # Good but not great
                logger.info(f"✅ [Security] {secret_name} passed validation (score: {result.score}/100)")
            else:
                logger.debug(f"✅ [Security] {secret_name} has strong security (score: {result.score}/100)")
        else:
            # Format issues and suggestions for logging
            issues_text = "; ".join(result.issues)
            suggestions_text = " | ".join(result.suggestions[:2])  # Limit to first 2 suggestions

            error_msg = (
                f"🔒 [Security] {secret_name} validation failed (score: {result.score}/100)\n"
                f"Issues: {issues_text}\n"
                f"Suggestions: {suggestions_text}"
            )

            if self.environment == "production":
                logger.error(f"🚨 {error_msg}")
                raise ValueError(
                    f"SECURITY ERROR: {secret_name} is too weak for production environment. "
                    f"Issues: {issues_text}. {suggestions_text}"
                )
            elif self.environment == "staging":
                logger.warning(f"⚠️ {error_msg}")
                # Could be upgraded to error in the future
            else:
                logger.warning(f"⚠️ [Dev] {error_msg}")

        return result.is_valid


def validate_django_secret_key(secret_key: str, environment: str = "development") -> bool:
    """
    🔒 Validate Django SECRET_KEY with appropriate environment handling.

    Args:
        secret_key: Django SECRET_KEY value
        environment: Current environment ('development', 'staging', 'production')

    Returns:
        bool: True if secret is acceptable for environment

    Raises:
        ValueError: In production if SECRET_KEY is too weak
    """
    validator = SecretValidator(environment)
    return validator.validate_and_warn(secret_key, "SECRET_KEY", min_length=50)


def validate_platform_api_secret(api_secret: str, environment: str = "development") -> bool:
    """
    🔒 Validate Platform API HMAC secret with appropriate environment handling.

    Args:
        api_secret: Platform API HMAC secret value
        environment: Current environment ('development', 'staging', 'production')

    Returns:
        bool: True if secret is acceptable for environment

    Raises:
        ValueError: In production if API secret is too weak
    """
    validator = SecretValidator(environment)
    return validator.validate_and_warn(api_secret, "PLATFORM_API_SECRET", min_length=32)


def detect_environment() -> str:
    """
    🔍 Auto-detect current environment from Django settings and environment variables.

    Returns:
        str: Detected environment ('development', 'staging', 'production')
    """
    # Check Django settings module
    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", "")

    if "prod" in settings_module.lower():
        return "production"
    elif "staging" in settings_module.lower():
        return "staging"
    elif "dev" in settings_module.lower() or "test" in settings_module.lower():
        return "development"

    # Check DEBUG setting
    debug = os.environ.get("DEBUG", "True").lower()
    if debug in ("false", "0", "no"):
        return "production"

    # Default to development for safety
    return "development"


def validate_all_secrets() -> bool:
    """
    🔒 Validate all critical secrets for the current environment.

    Called during Django startup to ensure security requirements are met.

    Returns:
        bool: True if all secrets pass validation for current environment

    Raises:
        ValueError: In production if any critical secret is too weak
    """
    environment = detect_environment()
    logger.info(f"🔍 [Security] Running secret validation for environment: {environment}")

    all_valid = True

    # Validate Django SECRET_KEY
    secret_key = os.environ.get("SECRET_KEY")
    if secret_key:
        try:
            valid = validate_django_secret_key(secret_key, environment)
            all_valid = all_valid and valid
        except ValueError:
            all_valid = False
            raise
    else:
        logger.warning("⚠️ [Security] SECRET_KEY not found in environment")
        if environment == "production":
            raise ValueError("SECURITY ERROR: SECRET_KEY environment variable must be set in production")

    # Validate Platform API Secret
    api_secret = os.environ.get("PLATFORM_API_SECRET")
    if api_secret:
        try:
            valid = validate_platform_api_secret(api_secret, environment)
            all_valid = all_valid and valid
        except ValueError:
            all_valid = False
            raise
    else:
        logger.warning("⚠️ [Security] PLATFORM_API_SECRET not found in environment")
        if environment == "production":
            raise ValueError("SECURITY ERROR: PLATFORM_API_SECRET environment variable must be set in production")

    if all_valid:
        logger.info(f"✅ [Security] All secrets validated successfully for {environment} environment")
    else:
        logger.warning(f"⚠️ [Security] Some secrets have issues in {environment} environment")

    return all_valid
