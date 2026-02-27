"""
Provisioning Forms - PRAHO Platform
Core provisioning forms and backwards compatibility imports.

Note: Virtualmin-specific forms have been moved to virtualmin_forms.py
"""

# Backward compatibility imports for existing code
from .virtualmin_forms import (
    VirtualminAccountForm,
    VirtualminBackupForm,
    VirtualminBulkActionForm,
    VirtualminHealthCheckForm,
    VirtualminRestoreForm,
    VirtualminServerForm,
)

# Re-export for backward compatibility
__all__ = [
    "VirtualminAccountForm",
    "VirtualminBackupForm",
    "VirtualminBulkActionForm",
    "VirtualminHealthCheckForm",
    "VirtualminRestoreForm",
    "VirtualminServerForm",
]
