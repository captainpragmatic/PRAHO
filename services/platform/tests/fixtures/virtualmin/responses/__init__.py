"""
Virtualmin API response fixture factories.

Factory functions returning dicts that match the real Virtualmin JSON API format
(from json-lib.pl / remote.cgi). Parameterizable for different domains/scenarios.

Usage:
    from tests.fixtures.virtualmin.responses import create_domain, list_domains

    response = create_domain.success(domain="example.com")
    error_response = create_domain.conflict(domain="example.com")
"""
