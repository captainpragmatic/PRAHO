# PRAHO Documentation

> Documentation hub for PRAHO (PRAHO Really Automates Hosting Operations) -- a hosting provider management platform built for Romanian business compliance.

## Architecture

- [PRAHO Platform Architecture](architecture/ARCHITECTURE.md) -- Core two-service split, strategic seams pattern, app-level design
- [App Separation Architecture](architecture/app-separation.md) -- Platform vs Portal design and isolation rules
- [Architecture Diagrams](architecture/README.md) -- Mermaid-based visual diagrams (system overview, data flow, deployment, ERD)
- [Dependency Analysis Report](architecture/DEPENDENCY_ANALYSIS.md) -- App coupling metrics and circular dependency analysis
- [Codebase Archaeology Report](architecture/CODEBASE_ARCHAEOLOGY.md) -- Evolution across 3 architectural eras
- [Architecture Changelog](architecture/CHANGELOG.md) -- History of architecture documentation changes

## Architecture Decision Records

- [ADR Index](ADRs/README.md) -- 24 decisions (ADR-0001 through ADR-0025, with ADR-0008 superseded)

## Development Guides

- [Strategic Linting Framework Guide](development/LINTING_GUIDE.md) -- Ruff configuration, rule categories, and linting workflow
- [Pre-commit Hooks Guide](development/PRE_COMMIT_HOOKS_GUIDE.md) -- Hook setup, configuration, and troubleshooting
- [Gradual Typing Configuration](development/GRADUAL_TYPING_CONFIGURATION.md) -- MyPy setup with pragmatic Django typing
- [Tailwind CSS Setup](development/TAILWIND_SETUP.md) -- Tailwind configuration for both services
- [Enhanced Table Component Guide](development/CLICKABLE_DATA_TABLE_GUIDE.md) -- Reusable clickable data table pattern
- [Component Migration Summary](development/COMPONENT_MIGRATION_SUMMARY.md) -- Component refactoring history
- [Django User Fields Guide](development/django-user-fields-guide.md) -- Custom user model field reference
- [N+1 Query Optimization Summary](development/N1_QUERY_OPTIMIZATION_SUMMARY.md) -- select_related/prefetch_related patterns
- [IDE Auto-Formatting Prevention](development/IDE_AUTO_FORMATTING_PREVENTION.md) -- Preventing IDE conflicts with Ruff
- [Trace-Based Dynamic Analysis](development/TRACE_BASED_ANALYSIS.md) -- Runtime tracing for debugging

## Deployment and Operations

- [Deployment Guide](deployment/DEPLOYMENT.md) -- Full deployment instructions, Ansible playbooks, rollback procedures
- [HTTPS Deployment Checklist](deployment/HTTPS_DEPLOYMENT_CHECKLIST.md) -- SSL/TLS setup for PragmaticHost
- [Production Quality Checklist](deployment/PRODUCTION_QUALITY_CHECKLIST.md) -- Pre-launch quality gates
- [Virtualmin Production Optimizations](deployment/VIRTUALMIN_PRODUCTION_OPTIMIZATIONS.md) -- Virtualmin tuning for production

## Security

- [2FA Setup and Key Management](security/2FA-SETUP-AND-KEY-MANAGEMENT.md) -- TOTP setup, encryption key management, backup codes
- [Security Compliance Assessment](security/SECURITY_COMPLIANCE_ASSESSMENT.md) -- GDPR, Romanian Law 190/2018 compliance
- [Security Configuration](security/SECURITY_CONFIGURATION.md) -- Django security settings and hardening
- [Template Security Guidelines](security/TEMPLATE_SECURITY.md) -- XSS prevention, safe template patterns

## Business Domain

- [Audit System Guide](domain/AUDIT_SYSTEM_GUIDE.md) -- Immutable audit trails, GDPR compliance
- [Queue and Task Methodology](domain/QUEUE_TASK_METHODOLOGY.md) -- Django-Q2 async task patterns
- [RefundService Documentation](domain/REFUND_SERVICE.md) -- Refund workflow and business rules
- [Signals Architecture](domain/SIGNALS_ARCHITECTURE.md) -- Django signals design and conventions

## Plans

- [Orders System Analysis](plans/orders.md) -- Order system implementation plan (partially complete)
