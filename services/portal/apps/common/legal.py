"""The Terms of Service version, named by the date the current text took effect.

The portal shows it on /terms/; Platform records it when a customer accepts the terms.
The text is shared/ui/templates/legal/terms_of_service_content.html. The Platform keeps its
own copy of this constant (service isolation); tests/integration/test_terms_version_parity.py
keeps the two equal and fails when the text changes without a new version.
"""

TERMS_OF_SERVICE_VERSION = "2024-12-27"
