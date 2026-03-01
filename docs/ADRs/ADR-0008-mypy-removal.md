# ADR-0008: MyPy Removal

**Status:** Superseded by ADR-0009
**Date:** 2025-08-27
**Authors:** Development Team

## Context

After encountering ~995 MyPy errors with strict mode enabled across the PRAHO Platform codebase, this ADR proposed removing MyPy entirely as a type-checking tool. The majority of errors were Django framework noise rather than actual bugs.

## Decision

Remove MyPy from the development workflow entirely.

## Outcome

This decision was **superseded by ADR-0009** (Pragmatic MyPy Configuration Strategy), which adopted a layered approach instead — strict typing for business logic (`services.py`, `repos.py`, `gateways.py`) with relaxed rules for Django framework layers (`views.py`, `models.py`, `admin.py`).

The pragmatic approach proved more valuable than full removal, preserving type safety where it catches real bugs while eliminating the noise that motivated this proposal.

## References

- [ADR-0009: Pragmatic MyPy Configuration Strategy](ADR-0009-pragmatic-mypy-strategy.md)
- [ADR-0003: Comprehensive Type Safety Implementation](ADR-0003-comprehensive-type-safety-implementation.md)
