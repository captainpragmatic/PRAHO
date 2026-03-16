# ADR-0023: Database Structure — Table Naming Convention and Schema Design

**Status:** Accepted
**Date:** March 2026 (rewritten from pre-implementation draft)
**Authors:** Development Team

> **Diagrams:**
> - [`entity-relationships.mmd`](../architecture/diagrams/entity-relationships.mmd) — ER diagram using db_table names, shows FK relationships
> - [`database-tables.mmd`](../architecture/diagrams/database-tables.mmd) — flat app-grouped taxonomy of all 119 tables

## Context

PRAHO Platform uses Django ORM with PostgreSQL. All 119 concrete models across 15 Django apps
need explicit, consistent `db_table` values so that:

- DBAs and SQL consumers can identify which app owns a table at a glance
- Foreign key references in raw SQL or monitoring queries are unambiguous
- Auto-generated Django names are not relied upon implicitly

Before this rewrite, `db_table` values were a mix of bare names (`currency`, `invoice`),
app-prefixed names (`billing_efactura_document`), and implicit Django-generated names (no
`db_table` set at all). This made it impossible to tell from a table name alone which app owned
it.

## Decision

All Django models **must** declare an explicit `Meta.db_table`. The value follows this convention:

```
{app}_{plural_entity}
```

### Rules

1. **App prefix** — the singular stem of the Django app label (`customer_`, `user_`, `billing_`, `audit_`, etc.). For apps where the label is already singular (billing, audit, infrastructure), the prefix matches the label exactly.
2. **Bare plural** — no redundant app name repetition in the entity part
3. **Root entities** — models that *are* the app's primary entity use the app name alone
   (e.g. `customers`, `users`, `orders`, `products`, `tickets`, `domains`)
4. **All models** — every concrete model sets `db_table` explicitly; no implicit Django names

### Examples

| Model | App | db_table |
|-------|-----|----------|
| Currency | billing | billing_currencies |
| Invoice | billing | billing_invoices |
| Customer | customers | customers — root entity |
| AuditEvent | audit | audit_events |
| Server | provisioning | provisioning_servers |
| Domain | domains | domains — root entity |
| WebAuthnCredential | users | user_webauthn_credentials |

### Rationale

- **Discoverability**: Any engineer or DBA immediately identifies the owning app from a table
  name in pg_stat_activity, slow query logs, or \d output
- **Foreign key clarity**: Raw SQL joins are self-documenting (billing_invoices not invoice)
- **No implicit names**: Django generates {app_label}_{model_name_lower} by default — singular
  and inconsistent. Explicit db_table makes the name a deliberate contract
- **Migration safety**: Explicit db_table means file reorganisations (splitting models into
  feature files) never require schema migrations — see ADR-0012
- **Pre-launch alpha**: Migrations were nuked and regenerated fresh to apply all renames in a
  single clean initial state. Post-launch renames require an AlterModelTable migration

---

## Complete Table Catalog

All 118 tables across 15 apps.

### audit — 11 tables

| db_table | Model |
|----------|-------|
| audit_events | AuditEvent |
| audit_data_exports | AuditDataExport |
| audit_integrity_checks | AuditIntegrityCheck |
| audit_retention_policies | AuditRetentionPolicy |
| audit_search_queries | AuditSearchQuery |
| audit_alerts | AuditAlert |
| audit_compliance_logs | AuditComplianceLog |
| audit_siem_hash_chain_states | AuditSiemHashChainState |
| audit_compliance_reports | AuditComplianceReport |
| audit_siem_export_logs | AuditSiemExportLog |
| audit_cookie_consents | AuditCookieConsent |

### billing — 32 tables

| db_table | Model |
|----------|-------|
| billing_currencies | Currency |
| billing_fx_rates | FxRate |
| billing_invoice_sequences | InvoiceSequence |
| billing_invoices | Invoice |
| billing_invoice_lines | InvoiceLine |
| billing_usage_meters | UsageMeter |
| billing_usage_events | UsageEvent |
| billing_usage_aggregations | UsageAggregation |
| billing_cycles | BillingCycle |
| billing_pricing_tiers | PricingTier |
| billing_pricing_tier_brackets | PricingTierBracket |
| billing_usage_thresholds | UsageThreshold |
| billing_usage_alerts | UsageAlert |
| billing_payments | Payment |
| billing_credit_ledgers | CreditLedger |
| billing_payment_retry_policies | PaymentRetryPolicy |
| billing_payment_retry_attempts | PaymentRetryAttempt |
| billing_payment_collections | PaymentCollectionRun |
| billing_proforma_sequences | ProformaSequence |
| billing_proforma_invoices | ProformaInvoice |
| billing_proforma_lines | ProformaLine |
| billing_refunds | Refund |
| billing_refund_notes | RefundNote |
| billing_refund_status_history | RefundStatusHistory |
| billing_subscriptions | Subscription |
| billing_subscription_changes | SubscriptionChange |
| billing_price_locks | PriceGrandfathering |
| billing_subscription_items | SubscriptionItem |
| billing_tax_rules | TaxRule |
| billing_vat_validations | VatValidation |
| billing_efactura_documents | EFacturaDocument |
| billing_efactura_oauth_tokens | EFacturaOAuthToken |

### common — 2 tables

| db_table | Model |
|----------|-------|
| common_credentials | CredentialVault |
| common_credential_access_logs | CredentialAccessLog |

### customers — 6 tables

| db_table | Model |
|----------|-------|
| customers | Customer — root entity |
| customer_addresses | CustomerAddress |
| customer_payment_methods | CustomerPaymentMethod |
| customer_notes | CustomerNote |
| customer_tax_profiles | CustomerTaxProfile |
| customer_billing_profiles | CustomerBillingProfile |

### domains — 5 tables

| db_table | Model |
|----------|-------|
| domains | Domain — root entity |
| domain_tlds | TLD |
| domain_registrars | Registrar |
| domain_tld_registrar_assignments | TLDRegistrarAssignment |
| domain_order_items | DomainOrderItem |

### infrastructure — 11 tables

| db_table | Model |
|----------|-------|
| infrastructure_cloud_providers | CloudProvider |
| infrastructure_node_regions | NodeRegion |
| infrastructure_node_sizes | NodeSize |
| infrastructure_panel_types | PanelType |
| infrastructure_node_deployments | NodeDeployment |
| infrastructure_node_deployment_logs | NodeDeploymentLog |
| infrastructure_node_deployment_costs | NodeDeploymentCost |
| infrastructure_drift_checks | DriftCheck |
| infrastructure_drift_reports | DriftReport |
| infrastructure_drift_remediations | DriftRemediation |
| infrastructure_drift_snapshots | DriftSnapshot |

### integrations — 2 tables

| db_table | Model |
|----------|-------|
| integration_webhook_events | WebhookEvent |
| integration_webhook_deliveries | WebhookDelivery |

### notifications — 6 tables

| db_table | Model |
|----------|-------|
| notification_email_templates | EmailTemplate |
| notification_email_logs | EmailLog |
| notification_email_campaigns | EmailCampaign |
| notification_email_suppressions | EmailSuppression |
| notification_email_preferences | EmailPreference |
| notification_unsubscribe_tokens | UnsubscribeToken |

### orders — 3 tables

| db_table | Model |
|----------|-------|
| orders | Order — root entity |
| order_items | OrderItem |
| order_status_history | OrderStatusHistory |

### products — 5 tables

| db_table | Model |
|----------|-------|
| products | Product — root entity |
| product_prices | ProductPrice |
| product_relationships | ProductRelationship |
| product_bundles | ProductBundle |
| product_bundle_items | ProductBundleItem |

### promotions — 12 tables

| db_table | Model |
|----------|-------|
| promotion_campaigns | PromotionCampaign |
| promotion_coupons | Coupon |
| promotion_coupon_redemptions | CouponRedemption |
| promotion_customer_loyalties | CustomerLoyalty |
| promotion_gift_cards | GiftCard |
| promotion_gift_card_transactions | GiftCardTransaction |
| promotion_loyalty_programs | LoyaltyProgram |
| promotion_loyalty_tiers | LoyaltyTier |
| promotion_loyalty_transactions | LoyaltyTransaction |
| promotion_referral_codes | ReferralCode |
| promotion_referrals | Referral |
| promotion_rules | PromotionRule |

### provisioning — 12 tables

| db_table | Model |
|----------|-------|
| provisioning_service_plans | ServicePlan |
| provisioning_servers | Server |
| provisioning_services | Service |
| provisioning_tasks | ProvisioningTask |
| provisioning_virtualmin_servers | VirtualminServer |
| provisioning_virtualmin_accounts | VirtualminAccount |
| provisioning_virtualmin_jobs | VirtualminProvisioningJob |
| provisioning_virtualmin_drift_records | VirtualminDriftRecord |
| provisioning_service_relationships | ServiceRelationship |
| provisioning_service_domains | ServiceDomain |
| provisioning_service_groups | ServiceGroup |
| provisioning_service_group_members | ServiceGroupMember |

### settings — 2 tables

| db_table | Model |
|----------|-------|
| setting_categories | SettingCategory |
| setting_entries | SettingEntry |

### tickets — 5 tables

| db_table | Model |
|----------|-------|
| tickets | Ticket — root entity |
| ticket_categories | SupportCategory |
| ticket_comments | TicketComment |
| ticket_attachments | TicketAttachment |
| ticket_worklogs | TicketWorklog |

### users — 5 tables

| db_table | Model |
|----------|-------|
| users | User — root entity |
| user_customer_memberships | CustomerMembership |
| user_profiles | UserProfile |
| user_login_logs | UserLoginLog |
| user_webauthn_credentials | WebAuthnCredential |

---

## Schema Design Decisions

### Django ORM — no raw SQL DDL for app tables

All schema is defined through Django models and migrations. Raw SQL DDL is not maintained
separately. Benefits: type-safe queries, automatic migration tracking, guaranteed model/schema
parity. Raw SQL is only used for health checks (SELECT 1).

### UUID primary keys on business-facing models

Business-facing models (Customer, Invoice, Order, Domain, Product, etc.) use UUID PKs:
- API exposure safety — sequential IDs leak record counts and enable enumeration attacks
- Distributed-insert safety — no coordination required for PK generation

High-throughput internal tables (log entries, audit events, junction tables) may use
auto-increment integer PKs for insert performance.

### Monetary values as integer cents

All money columns use INTEGER (cents), never DECIMAL. See ADR-0025 for full rationale.

### created_at / updated_at on all models

Every model includes created_at = DateTimeField(auto_now_add=True) and
updated_at = DateTimeField(auto_now=True). No exceptions.

### State machine columns

Models with lifecycle states use django-fsm-2 FSMField (stored as plain VARCHAR in
PostgreSQL). See ADR-0034. State transitions are enforced at the Python layer; the DB column
has no CHECK constraint.

### Romanian compliance columns

Invoices carry tax_cents (not vat_cents) to support multiple tax types. Invoice and Proforma
sequence models track last_number for legally required sequential numbering. EFacturaDocument
stores ANAF submission state alongside parent invoices.

---

## Alternatives Considered

### Keep Django's implicit naming
Rejected: singular names (billing_invoice) look wrong in SQL and implicit names become a
footgun when models are moved or renamed during refactors.

### Separate PostgreSQL schema per app (e.g. billing.invoices)
Rejected: Django's multi-schema support requires third-party packages and complicates all
queries. The {app}_ prefix gives the same discoverability at zero tooling cost.

### Bare plural with no prefix (invoices, orders, events)
Rejected: generic names like events, alerts, logs, and tokens are hopelessly ambiguous
across 15 apps in pg_stat_activity and slow query logs.

---

## Related ADRs

- **ADR-0012** — Internal app organisation: explains why explicit db_table makes file
  reorganisation within an app always migration-free
- **ADR-0025** — Monetary amounts stored as integer cents
- **ADR-0034** — django-fsm-2: FSM status fields are plain VARCHAR columns on the tables above
