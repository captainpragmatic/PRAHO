# ===============================================================================
# API THROTTLING CLASSES 🚦
# ===============================================================================

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


class StandardAPIThrottle(UserRateThrottle):
    """Standard rate limiting for PRAHO API endpoints"""
    rate = '1000/hour'  # Generous for portal service integration


class BurstAPIThrottle(UserRateThrottle):
    """Higher rate limit for search/autocomplete endpoints"""
    rate = '60/min'  # Good for real-time search


class AuthThrottle(AnonRateThrottle):
    """Restrictive rate limiting for auth endpoints"""
    rate = '5/min'  # Prevent brute force attacks
