# ADR-0023: Complete Database Schema - Hosting Provider Billing & Support System

## Overview
PostgreSQL schema for a comprehensive hosting provider platform supporting billing, provisioning, support, and automation. Designed for Romanian/EU compliance with e-Factura, GDPR, and VAT requirements.

## Table of Contents
- [Core Enums](#core-enums)
- [Currency & Exchange Rates](#currency--exchange-rates)
- [Accounts & Teams](#accounts--teams)
- [Product Catalog](#product-catalog)
- [Product & Service Relationships](#product--service-relationships)
- [Domains & TLDs](#domains--tlds)
- [Orders & Services](#orders--services)
- [Multi-Server Infrastructure](#multi-server-infrastructure)
- [Invoicing & Proforma](#invoicing--proforma)
- [Payments & Credits](#payments--credits)
- [Tax & VAT](#tax--vat)
- [Support Tickets](#support-tickets)
- [Knowledge Base](#knowledge-base)
- [Cancellation Workflow](#cancellation-workflow)
- [API Access & Automation](#api-access--automation)
- [Payment Retry Management (Dunning)](#payment-retry-management-dunning)
- [Email System](#email-system)
- [Webhooks & Events](#webhooks--events)
- [Audit & Compliance](#audit--compliance)
- [Indexes & Performance](#indexes--performance)

## Core Enums

```sql
-- Service lifecycle states
CREATE TYPE service_status AS ENUM (
  'pending',
  'active',
  'suspended',
  'canceled',
  'terminated'
);

-- Invoice states (immutable after 'issued')
CREATE TYPE invoice_status AS ENUM (
  'draft',
  'issued',
  'paid',
  'void',
  'refunded',
  'overdue',
  'uncollectible'
);

-- Payment processing states
CREATE TYPE payment_status AS ENUM (
  'pending',
  'succeeded',
  'failed',
  'refunded',
  'partially_refunded'
);

-- Order workflow states
CREATE TYPE order_status AS ENUM (
  'pending',
  'accepted',
  'declined',
  'needs_info',
  'canceled'
);
```

## Currency & Exchange Rates

```sql
-- Supported currencies
CREATE TABLE currency (
  code        CHAR(3) PRIMARY KEY,        -- 'EUR','RON','USD'
  symbol      TEXT NOT NULL,
  decimals    SMALLINT NOT NULL DEFAULT 2,
  is_active   BOOLEAN NOT NULL DEFAULT TRUE
);

-- Daily exchange rates for reporting
CREATE TABLE fx_rate (
  base_code   CHAR(3) NOT NULL REFERENCES currency(code),
  quote_code  CHAR(3) NOT NULL REFERENCES currency(code),
  rate        NUMERIC(18,8) NOT NULL,
  source      TEXT NOT NULL DEFAULT 'ECB', -- ECB, BNR
  as_of       DATE NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (base_code, quote_code, as_of)
);

CREATE INDEX fx_rate_lookup_idx ON fx_rate(base_code, quote_code, as_of DESC);
```

## Accounts & Teams

```sql
-- Customer accounts (companies or individuals)
CREATE TABLE account (
  id               BIGSERIAL PRIMARY KEY,
  name             TEXT NOT NULL,
  type             TEXT NOT NULL CHECK (type IN ('individual','company')),
  country          CHAR(2) NOT NULL,
  tax_id           TEXT,                   -- VAT ID / CUI for companies
  language         TEXT NOT NULL DEFAULT 'en',
  timezone         TEXT NOT NULL DEFAULT 'Europe/Bucharest',
  is_active        BOOLEAN NOT NULL DEFAULT TRUE,
  deleted_at       TIMESTAMPTZ,             -- Soft delete for GDPR
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Link Django users to accounts with roles
CREATE TABLE membership (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  user_id          BIGINT NOT NULL,        -- FK to auth_user.id
  role             TEXT NOT NULL CHECK (role IN ('owner','billing','tech','viewer')),
  is_primary       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (account_id, user_id)
);

CREATE INDEX membership_user_idx ON membership(user_id);
CREATE INDEX account_active_idx ON account(is_active) WHERE is_active = TRUE;
```

## Product Catalog

```sql
-- Products/services offered
CREATE TABLE product (
  id               BIGSERIAL PRIMARY KEY,
  slug             TEXT NOT NULL UNIQUE,
  sku              TEXT UNIQUE,
  name             TEXT NOT NULL,
  description      TEXT,
  kind             TEXT NOT NULL CHECK (kind IN (
    'hosting',     -- Web hosting plans
    'vps',         -- Virtual private servers
    'dedicated',   -- Dedicated servers
    'domain',      -- Domain registration
    'addon',       -- SSL, backup, etc.
    'other'
  )),
  module           TEXT,                   -- 'virtualmin', 'cpanel', 'plesk'
  module_config    JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_active        BOOLEAN NOT NULL DEFAULT TRUE,
  is_featured      BOOLEAN NOT NULL DEFAULT FALSE,
  sort_order       INTEGER NOT NULL DEFAULT 0,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Product pricing by currency and billing cycle
CREATE TABLE product_price (
  id               BIGSERIAL PRIMARY KEY,
  product_id       BIGINT NOT NULL REFERENCES product(id) ON DELETE CASCADE,
  currency         CHAR(3) NOT NULL REFERENCES currency(code),
  billing_period   TEXT NOT NULL CHECK (billing_period IN (
    'one_time',
    'monthly',
    'quarterly',
    'semi_annual',
    'annual',
    'biennial',
    'triennial'
  )),
  amount_cents     BIGINT NOT NULL CHECK (amount_cents >= 0),
  setup_cents      BIGINT NOT NULL DEFAULT 0 CHECK (setup_cents >= 0),

  -- Contract terms
  min_cycles       INTEGER DEFAULT 1,
  termination_fee_cents BIGINT DEFAULT 0,

  -- Pricing version for grandfather pricing
  version          INTEGER NOT NULL DEFAULT 1,
  is_active        BOOLEAN NOT NULL DEFAULT TRUE,
  valid_from       TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_until      TIMESTAMPTZ,

  UNIQUE (product_id, currency, billing_period, version)
);

CREATE INDEX product_price_active_idx ON product_price(product_id, currency)
  WHERE is_active = TRUE;
```

## Product & Service Relationships

```sql
-- Define how products relate at catalog level
CREATE TABLE product_relationship (
  id                 BIGSERIAL PRIMARY KEY,
  parent_product_id  BIGINT NOT NULL REFERENCES product(id) ON DELETE CASCADE,
  child_product_id   BIGINT NOT NULL REFERENCES product(id) ON DELETE CASCADE,
  relationship_type  TEXT NOT NULL CHECK (relationship_type IN (
    'requires',      -- SSL requires a domain
    'includes',      -- Hosting includes free domain
    'addon',         -- Backup is addon to hosting
    'upgrade',       -- VPS is upgrade from shared
    'cross_sell'     -- Suggest related products
  )),
  is_mandatory      BOOLEAN NOT NULL DEFAULT FALSE,
  min_quantity      INTEGER DEFAULT 0,
  max_quantity      INTEGER, -- NULL = unlimited
  config_rules      JSONB,   -- {"auto_provision": true, "sync_cycles": true}
  UNIQUE(parent_product_id, child_product_id, relationship_type)
);

-- Product bundles with special pricing
CREATE TABLE product_bundle (
  id                BIGSERIAL PRIMARY KEY,
  name              TEXT NOT NULL,
  slug              TEXT NOT NULL UNIQUE,
  description       TEXT,
  is_active         BOOLEAN NOT NULL DEFAULT TRUE,
  discount_type     TEXT CHECK (discount_type IN ('percentage','fixed','override')),
  discount_value    NUMERIC(10,2),
  valid_from        TIMESTAMPTZ,
  valid_until       TIMESTAMPTZ
);

CREATE TABLE product_bundle_item (
  id                BIGSERIAL PRIMARY KEY,
  bundle_id         BIGINT NOT NULL REFERENCES product_bundle(id) ON DELETE CASCADE,
  product_id        BIGINT NOT NULL REFERENCES product(id) ON DELETE CASCADE,
  quantity          INTEGER NOT NULL DEFAULT 1,
  is_optional       BOOLEAN NOT NULL DEFAULT FALSE,
  override_price    BIGINT, -- Override price in bundle
  UNIQUE(bundle_id, product_id)
);

-- Service-level relationships (actual provisioned services)
CREATE TABLE service_relationship (
  id                 BIGSERIAL PRIMARY KEY,
  parent_service_id  BIGINT NOT NULL REFERENCES service(id) ON DELETE CASCADE,
  child_service_id   BIGINT NOT NULL REFERENCES service(id) ON DELETE CASCADE,
  relationship_type  TEXT NOT NULL CHECK (relationship_type IN (
    'hosts',         -- Domain hosts website
    'secures',       -- SSL secures domain
    'extends',       -- Backup extends hosting
    'requires'       -- Service requires another
  )),
  sync_billing      BOOLEAN NOT NULL DEFAULT FALSE, -- Align billing cycles
  cascade_suspend   BOOLEAN NOT NULL DEFAULT TRUE,  -- Suspend child if parent suspended
  cascade_cancel    BOOLEAN NOT NULL DEFAULT FALSE, -- Cancel child if parent cancelled
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(parent_service_id, child_service_id)
);

-- Service grouping for related services
CREATE TABLE service_group (
  id                BIGSERIAL PRIMARY KEY,
  account_id        BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  primary_domain    TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX service_rel_parent_idx ON service_relationship(parent_service_id);
CREATE INDEX service_rel_child_idx ON service_relationship(child_service_id);
```

## Domains & TLDs

```sql
-- Domain registrars
CREATE TABLE registrar (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  api_endpoint  TEXT,
  api_type      TEXT CHECK (api_type IN ('enom','opensrs','resellerclub','custom')),
  creds_ref     TEXT,          -- Reference to secret manager
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  meta          JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Top-level domains configuration
CREATE TABLE tld (
  id            BIGSERIAL PRIMARY KEY,
  tld           TEXT NOT NULL UNIQUE,      -- '.com', '.ro', '.eu'
  registrar_id  BIGINT REFERENCES registrar(id) ON DELETE SET NULL,
  features      JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {"dns_mgmt":true,"id_protect":true}
  requirements  JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {"eu_citizen":true}
  is_active     BOOLEAN NOT NULL DEFAULT TRUE
);

-- TLD pricing
CREATE TABLE tld_price (
  id            BIGSERIAL PRIMARY KEY,
  tld_id        BIGINT NOT NULL REFERENCES tld(id) ON DELETE CASCADE,
  currency      CHAR(3) NOT NULL REFERENCES currency(code),
  years         SMALLINT NOT NULL CHECK (years BETWEEN 1 AND 10),
  register_cents BIGINT NOT NULL CHECK (register_cents >= 0),
  transfer_cents BIGINT NOT NULL CHECK (transfer_cents >= 0),
  renew_cents    BIGINT NOT NULL CHECK (renew_cents >= 0),
  restore_cents  BIGINT,  -- Redemption fee
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (tld_id, currency, years)
);

-- Registered domains
CREATE TABLE domain (
  id            BIGSERIAL PRIMARY KEY,
  account_id    BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  tld_id        BIGINT NOT NULL REFERENCES tld(id),
  sld           TEXT NOT NULL,                         -- 'example' in example.com
  fqdn          TEXT GENERATED ALWAYS AS (sld || (SELECT tld FROM tld WHERE id = tld_id)) STORED,
  period_years  SMALLINT NOT NULL DEFAULT 1,
  status        TEXT NOT NULL CHECK (status IN (
    'pending',
    'active',
    'expired',
    'transferring',
    'locked',
    'redemption',
    'canceled'
  )),
  registered_at TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ,
  registrar_ref TEXT,
  nameservers   TEXT[],
  contacts_ref  JSONB NOT NULL DEFAULT '{}'::jsonb,    -- Registrant, admin, tech, billing
  privacy_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  auto_renew    BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (tld_id, sld)
);

-- Domain-service mapping
CREATE TABLE service_domain (
  id                BIGSERIAL PRIMARY KEY,
  service_id        BIGINT NOT NULL REFERENCES service(id) ON DELETE CASCADE,
  domain_id         BIGINT NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
  is_primary        BOOLEAN NOT NULL DEFAULT FALSE,
  subdomain         TEXT, -- NULL for main domain, 'www' for www.example.com
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(service_id, domain_id, subdomain)
);

CREATE INDEX domain_account_status_exp_idx ON domain(account_id, status, expires_at DESC);
CREATE INDEX domain_expiry_active_idx ON domain(expires_at, status) WHERE status = 'active';
CREATE INDEX tld_price_lookup_idx ON tld_price(tld_id, currency, years) WHERE is_active = TRUE;
CREATE INDEX service_domain_lookup_idx ON service_domain(domain_id, service_id);
```

## Orders & Services

```sql
-- Orders (pre-provisioning)
CREATE TABLE "order" (
  id          BIGSERIAL PRIMARY KEY,
  account_id  BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  order_number TEXT UNIQUE,
  status      order_status NOT NULL DEFAULT 'pending',
  notes_admin TEXT,
  notes_customer TEXT,
  promo_code  TEXT,
  ip_address  INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  accepted_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

-- Order line items
CREATE TABLE order_item (
  id               BIGSERIAL PRIMARY KEY,
  order_id         BIGINT NOT NULL REFERENCES "order"(id) ON DELETE CASCADE,
  product_id       BIGINT NOT NULL REFERENCES product(id),
  quantity         INTEGER NOT NULL DEFAULT 1 CHECK (quantity > 0),
  currency         CHAR(3) NOT NULL REFERENCES currency(code),
  unit_price_cents BIGINT NOT NULL CHECK (unit_price_cents >= 0),
  setup_price_cents BIGINT NOT NULL DEFAULT 0,
  billing_period   TEXT NOT NULL,
  config           JSONB NOT NULL DEFAULT '{}'::jsonb, -- Domain name, plan size, etc.
  domain_name      TEXT  -- For domain/hosting orders
);

-- Provisioned services
CREATE TABLE service (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  product_id       BIGINT NOT NULL REFERENCES product(id),
  group_id         BIGINT REFERENCES service_group(id),
  parent_service_id BIGINT REFERENCES service(id), -- For addons

  -- Status & lifecycle
  status           service_status NOT NULL DEFAULT 'pending',
  started_at       TIMESTAMPTZ,
  next_renewal_at  TIMESTAMPTZ,
  suspended_at     TIMESTAMPTZ,
  canceled_at      TIMESTAMPTZ,
  termination_date DATE,

  -- Billing
  currency         CHAR(3) NOT NULL REFERENCES currency(code),
  price_cents      BIGINT NOT NULL CHECK (price_cents >= 0),
  period           TEXT NOT NULL,
  price_version_id BIGINT REFERENCES product_price(id), -- For grandfather pricing

  -- Contract
  contract_end_date DATE,
  auto_renew       BOOLEAN NOT NULL DEFAULT TRUE,
  renewal_cycles   INTEGER, -- NULL = unlimited

  -- Provisioning
  server_id        BIGINT,  -- Will reference server table
  external_ref     TEXT,    -- Virtualmin username, cPanel account, etc.
  username         TEXT,

  -- Domain info
  primary_domain   TEXT,
  additional_domains TEXT[],

  -- Configuration
  config           JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,

  deleted_at       TIMESTAMPTZ  -- Soft delete
);

CREATE INDEX order_account_idx ON "order"(account_id, created_at DESC);
CREATE INDEX order_status_idx ON "order"(status) WHERE status IN ('pending','needs_info');
CREATE INDEX svc_account_status_next_idx ON service(account_id, status, next_renewal_at);
CREATE INDEX svc_renewal_active_idx ON service(next_renewal_at, status)
  WHERE status = 'active' AND next_renewal_at IS NOT NULL;
CREATE INDEX svc_domain_idx ON service(primary_domain) WHERE primary_domain IS NOT NULL;
CREATE INDEX svc_metadata_idx ON service USING GIN(metadata);
```

## Multi-Server Infrastructure

```sql
-- Server groups for load balancing and organization
CREATE TABLE server_group (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  type            TEXT NOT NULL CHECK (type IN ('shared','vps','dedicated','custom')),
  allocation_mode TEXT NOT NULL CHECK (allocation_mode IN (
    'round_robin',   -- Rotate between servers
    'least_loaded',  -- Choose server with most free resources
    'manual'         -- Admin assigns manually
  )),
  location        TEXT, -- 'Bucharest', 'Frankfurt'
  is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

-- Physical/virtual servers
CREATE TABLE server (
  id               BIGSERIAL PRIMARY KEY,
  group_id         BIGINT REFERENCES server_group(id),
  hostname         TEXT NOT NULL UNIQUE,
  ip_address       INET NOT NULL,
  ip_addresses_v6  INET[],

  -- Control panel
  panel_type       TEXT CHECK (panel_type IN ('virtualmin','cpanel','plesk','directadmin','custom')),
  api_endpoint     TEXT NOT NULL,
  api_port         INTEGER DEFAULT 443,
  api_username     TEXT,
  api_key_ref      TEXT, -- Secret manager reference

  -- Capacity
  max_accounts     INTEGER,
  current_accounts INTEGER NOT NULL DEFAULT 0,
  max_disk_gb      INTEGER,
  current_disk_gb  INTEGER NOT NULL DEFAULT 0,
  max_bandwidth_tb NUMERIC(10,2),
  current_bandwidth_tb NUMERIC(10,2) DEFAULT 0,

  -- Monitoring
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','maintenance','offline','full')),
  health_check_url TEXT,
  last_health_check TIMESTAMPTZ,
  health_status    TEXT,

  -- Config
  ns1              TEXT,  -- Primary nameserver
  ns2              TEXT,  -- Secondary nameserver
  shared_ip        INET,  -- Shared hosting IP

  is_active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Service resource usage tracking
CREATE TABLE service_resource_usage (
  id              BIGSERIAL PRIMARY KEY,
  service_id      BIGINT NOT NULL REFERENCES service(id) ON DELETE CASCADE,
  resource_type   TEXT NOT NULL CHECK (resource_type IN (
    'disk_mb',
    'bandwidth_mb',
    'email_accounts',
    'databases',
    'subdomains',
    'ftp_accounts',
    'cpu_percentage',
    'ram_mb',
    'inode_count'
  )),
  used            BIGINT NOT NULL DEFAULT 0,
  allocated       BIGINT NOT NULL,
  last_updated    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(service_id, resource_type)
);

ALTER TABLE service ADD COLUMN server_id BIGINT REFERENCES server(id);

CREATE INDEX server_group_active_idx ON server(group_id, status) WHERE is_active = TRUE;
CREATE INDEX server_capacity_idx ON server(group_id, current_accounts, max_accounts)
  WHERE status = 'active';
CREATE INDEX service_resource_usage_service_idx ON service_resource_usage(service_id);
```

## Invoicing & Proforma

```sql
-- Invoice number sequences (never reuse numbers)
CREATE TABLE invoice_sequence (
  id         BIGSERIAL PRIMARY KEY,
  scope      TEXT NOT NULL DEFAULT 'default',
  prefix     TEXT,
  last_value BIGINT NOT NULL DEFAULT 0,
  UNIQUE(scope)
);

-- Proforma sequence (separate from tax invoices)
CREATE TABLE proforma_sequence (
  id         BIGSERIAL PRIMARY KEY,
  scope      TEXT NOT NULL DEFAULT 'default',
  prefix     TEXT DEFAULT 'PRO-',
  last_value BIGINT NOT NULL DEFAULT 0,
  UNIQUE(scope)
);

-- Proforma invoices (quotes, not tax documents)
CREATE TABLE proforma_invoice (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL REFERENCES account(id) ON DELETE RESTRICT,
  number           TEXT NOT NULL UNIQUE,
  currency         CHAR(3) NOT NULL REFERENCES currency(code),

  -- Amounts
  subtotal_cents   BIGINT NOT NULL DEFAULT 0,
  tax_cents        BIGINT NOT NULL DEFAULT 0,
  total_cents      BIGINT NOT NULL DEFAULT 0,

  -- Validity
  valid_until      TIMESTAMPTZ,
  converted_to_invoice BIGINT REFERENCES invoice(id),

  -- Billing address snapshot
  bill_to_name     TEXT NOT NULL,
  bill_to_tax_id   TEXT,
  bill_to_email    TEXT,
  bill_to_address1 TEXT,
  bill_to_address2 TEXT,
  bill_to_city     TEXT,
  bill_to_region   TEXT,
  bill_to_postal   TEXT,
  bill_to_country  CHAR(2) NOT NULL,

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  meta             JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Proforma line items
CREATE TABLE proforma_line (
  id               BIGSERIAL PRIMARY KEY,
  proforma_id      BIGINT NOT NULL REFERENCES proforma_invoice(id) ON DELETE CASCADE,
  kind             TEXT NOT NULL CHECK (kind IN ('service','setup','discount','misc')),
  service_id       BIGINT REFERENCES service(id) ON DELETE SET NULL,
  description      TEXT NOT NULL,
  quantity         NUMERIC(12,3) NOT NULL DEFAULT 1,
  unit_price_cents BIGINT NOT NULL DEFAULT 0,
  tax_rate         NUMERIC(5,4) NOT NULL DEFAULT 0.0000,
  line_total_cents BIGINT NOT NULL DEFAULT 0
);

-- Tax invoices (immutable after issued)
CREATE TABLE invoice (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL REFERENCES account(id) ON DELETE RESTRICT,
  number           TEXT NOT NULL UNIQUE,
  status           invoice_status NOT NULL DEFAULT 'draft',

  -- Amounts
  currency         CHAR(3) NOT NULL REFERENCES currency(code),
  exchange_to_ron  NUMERIC(18,6), -- For Romanian reporting
  subtotal_cents   BIGINT NOT NULL DEFAULT 0,
  tax_cents        BIGINT NOT NULL DEFAULT 0,
  total_cents      BIGINT NOT NULL DEFAULT 0,
  balance_cents    BIGINT NOT NULL DEFAULT 0, -- Amount still owed

  -- Dates
  issued_at        TIMESTAMPTZ,
  due_at           TIMESTAMPTZ,
  paid_at          TIMESTAMPTZ,
  voided_at        TIMESTAMPTZ,

  -- Billing address snapshot (immutable)
  bill_to_name     TEXT NOT NULL,
  bill_to_tax_id   TEXT,
  bill_to_email    TEXT,
  bill_to_address1 TEXT,
  bill_to_address2 TEXT,
  bill_to_city     TEXT,
  bill_to_region   TEXT,
  bill_to_postal   TEXT,
  bill_to_country  CHAR(2) NOT NULL,

  -- System
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_at        TIMESTAMPTZ, -- Set when issued, no more edits
  meta             JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Invoice line items (append-only after locked)
CREATE TABLE invoice_line (
  id               BIGSERIAL PRIMARY KEY,
  invoice_id       BIGINT NOT NULL REFERENCES invoice(id) ON DELETE CASCADE,
  kind             TEXT NOT NULL CHECK (kind IN (
    'service',
    'setup',
    'usage',    -- Overage charges
    'credit',
    'discount',
    'refund',
    'misc'
  )),
  service_id       BIGINT REFERENCES service(id) ON DELETE SET NULL,
  description      TEXT NOT NULL,
  period_start     DATE,
  period_end       DATE,
  quantity         NUMERIC(12,3) NOT NULL DEFAULT 1,
  unit_price_cents BIGINT NOT NULL DEFAULT 0,
  tax_rate         NUMERIC(5,4) NOT NULL DEFAULT 0.0000,
  tax_amount_cents BIGINT NOT NULL DEFAULT 0,
  line_total_cents BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX inv_account_created_idx ON invoice(account_id, created_at DESC);
CREATE INDEX inv_account_unpaid_idx ON invoice(account_id, due_at)
  WHERE status IN ('issued','overdue');
CREATE INDEX inv_open_idx ON invoice(account_id) WHERE status IN ('issued','overdue');
CREATE INDEX invline_service_idx ON invoice_line(service_id);
CREATE INDEX invline_invoice_idx ON invoice_line(invoice_id);
```

## Payments & Credits

```sql
-- Payment transactions
CREATE TABLE payment (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL REFERENCES account(id) ON DELETE RESTRICT,
  invoice_id       BIGINT REFERENCES invoice(id) ON DELETE SET NULL,

  -- Payment details
  status           payment_status NOT NULL,
  method           TEXT NOT NULL CHECK (method IN (
    'card',
    'bank_transfer',
    'paypal',
    'stripe',
    'credit_balance',
    'cash',
    'check',
    'other'
  )),

  -- Amounts
  amount_cents     BIGINT NOT NULL CHECK (amount_cents >= 0),
  currency         CHAR(3) NOT NULL REFERENCES currency(code),
  fee_cents        BIGINT DEFAULT 0, -- Payment processor fees

  -- Gateway info
  gateway          TEXT,
  gateway_txn_id   TEXT,
  gateway_response JSONB,

  -- Card info (PCI compliant - only last 4 digits)
  card_last4       CHAR(4),
  card_brand       TEXT,

  -- Timestamps
  received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  refunded_at      TIMESTAMPTZ,

  meta             JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Credit/debit ledger
CREATE TABLE credit_ledger (
  id           BIGSERIAL PRIMARY KEY,
  account_id   BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  invoice_id   BIGINT REFERENCES invoice(id) ON DELETE SET NULL,
  payment_id   BIGINT REFERENCES payment(id) ON DELETE SET NULL,

  -- Transaction
  type         TEXT NOT NULL CHECK (type IN ('credit','debit')),
  amount_cents BIGINT NOT NULL,
  balance_cents BIGINT NOT NULL, -- Running balance after this transaction
  currency     CHAR(3) NOT NULL REFERENCES currency(code),

  reason       TEXT NOT NULL,
  description  TEXT,

  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   BIGINT -- user_id who created
);

-- Refunds
CREATE TABLE refund (
  id           BIGSERIAL PRIMARY KEY,
  payment_id   BIGINT NOT NULL REFERENCES payment(id),
  invoice_id   BIGINT REFERENCES invoice(id),

  amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
  currency     CHAR(3) NOT NULL REFERENCES currency(code),

  reason       TEXT NOT NULL,
  gateway_txn_id TEXT,

  status       TEXT NOT NULL CHECK (status IN ('pending','completed','failed')),

  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  requested_by BIGINT NOT NULL -- user_id
);

CREATE INDEX pay_account_created_idx ON payment(account_id, received_at DESC);
CREATE INDEX pay_invoice_idx ON payment(invoice_id) WHERE invoice_id IS NOT NULL;
CREATE INDEX credit_ledger_account_idx ON credit_ledger(account_id, created_at DESC);
CREATE INDEX refund_payment_idx ON refund(payment_id);
```

## Tax & VAT

```sql
-- Tax rates by country
CREATE TABLE tax_rule (
  id          BIGSERIAL PRIMARY KEY,
  country     CHAR(2) NOT NULL,
  region      TEXT, -- For US states, Canadian provinces
  tax_type    TEXT NOT NULL DEFAULT 'VAT',
  rate        NUMERIC(5,4) NOT NULL, -- 0.1900 for 19%
  valid_from  DATE NOT NULL,
  valid_to    DATE,
  UNIQUE (country, COALESCE(region, ''), valid_from)
);

-- Customer tax profiles
CREATE TABLE customer_tax_profile (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL UNIQUE REFERENCES account(id) ON DELETE CASCADE,

  -- VAT
  vat_id           TEXT,
  vat_validated_at TIMESTAMPTZ,
  vat_valid        BOOLEAN,
  reverse_charge   BOOLEAN NOT NULL DEFAULT FALSE,

  -- Evidence for VAT MOSS
  evidence         JSONB NOT NULL DEFAULT '{}'::jsonb,
  /* Example evidence:
    {
      "billing_country": "RO",
      "ip_country": "RO",
      "bank_country": "RO"
    }
  */

  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Romanian e-Factura integration
CREATE TABLE efactura_document (
  id           BIGSERIAL PRIMARY KEY,
  invoice_id   BIGINT NOT NULL UNIQUE REFERENCES invoice(id) ON DELETE CASCADE,

  xml          TEXT NOT NULL,  -- Signed XML
  pdf          BYTEA,          -- PDF version

  status       TEXT NOT NULL CHECK (status IN (
    'draft',
    'queued',
    'submitted',
    'accepted',
    'rejected',
    'error'
  )),

  anaf_id      TEXT,
  anaf_index   TEXT,

  submitted_at TIMESTAMPTZ,
  response_at  TIMESTAMPTZ,
  response     JSONB,

  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX tax_rule_lookup_idx ON tax_rule(country, valid_from DESC);
CREATE INDEX efactura_status_idx ON efactura_document(status)
  WHERE status IN ('queued','submitted');
```

## Support Tickets

```sql
-- Support departments
CREATE TABLE support_department (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  email       TEXT,
  is_active   BOOLEAN NOT NULL DEFAULT TRUE,
  auto_assign BOOLEAN NOT NULL DEFAULT FALSE,
  sort_order  INTEGER NOT NULL DEFAULT 0
);

-- Support tickets
CREATE TABLE ticket (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
  department_id    BIGINT NOT NULL REFERENCES support_department(id),

  -- Ticket info
  ticket_number    TEXT NOT NULL UNIQUE,
  subject          TEXT NOT NULL,
  status           TEXT NOT NULL CHECK (status IN (
    'open',
    'pending',      -- Awaiting customer
    'on_hold',
    'in_progress',
    'solved',
    'closed'
  )),
  priority         TEXT NOT NULL CHECK (priority IN ('low','normal','high','urgent')) DEFAULT 'normal',

  -- Assignment
  assigned_to      BIGINT, -- staff user_id
  assigned_at      TIMESTAMPTZ,

  -- Related entities
  service_id       BIGINT REFERENCES service(id) ON DELETE SET NULL,

  -- Tracking
  created_by_user  BIGINT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_customer_reply TIMESTAMPTZ,
  last_staff_reply TIMESTAMPTZ,

  -- Resolution
  solved_at        TIMESTAMPTZ,
  solved_by        BIGINT,

  -- SLA
  sla_response_due TIMESTAMPTZ,
  sla_resolve_due  TIMESTAMPTZ,

  meta             JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Ticket messages
CREATE TABLE ticket_message (
  id              BIGSERIAL PRIMARY KEY,
  ticket_id       BIGINT NOT NULL REFERENCES ticket(id) ON DELETE CASCADE,
  author_user_id  BIGINT,

  -- Message
  body_markdown   TEXT NOT NULL,
  body_html       TEXT,

  -- Type
  is_internal     BOOLEAN NOT NULL DEFAULT FALSE, -- Staff-only notes
  is_system       BOOLEAN NOT NULL DEFAULT FALSE, -- Automated messages

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Ticket attachments
CREATE TABLE ticket_attachment (
  id            BIGSERIAL PRIMARY KEY,
  ticket_id     BIGINT NOT NULL REFERENCES ticket(id) ON DELETE CASCADE,
  message_id    BIGINT REFERENCES ticket_message(id) ON DELETE SET NULL,

  filename      TEXT NOT NULL,
  content_type  TEXT NOT NULL,
  size_bytes    BIGINT NOT NULL,
  storage_path  TEXT NOT NULL,

  uploaded_by   BIGINT NOT NULL,
  uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Canned responses
CREATE TABLE ticket_canned_response (
  id            BIGSERIAL PRIMARY KEY,
  department_id BIGINT REFERENCES support_department(id),

  name          TEXT NOT NULL,
  subject       TEXT,
  body          TEXT NOT NULL,

  usage_count   INTEGER NOT NULL DEFAULT 0,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,

  created_by    BIGINT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX tkt_account_status_idx ON ticket(account_id, status, last_activity_at DESC);
CREATE INDEX tkt_open_priority_idx ON ticket(department_id, priority DESC, created_at)
  WHERE status IN ('open','pending');
CREATE INDEX tkt_assigned_idx ON ticket(assigned_to, status) WHERE assigned_to IS NOT NULL;
CREATE INDEX tkt_sla_idx ON ticket(sla_response_due) WHERE status = 'open';
CREATE INDEX tkt_number_idx ON ticket(ticket_number);
```

## Knowledge Base

```sql
-- KB Categories with nesting
CREATE TABLE kb_category (
  id              BIGSERIAL PRIMARY KEY,
  parent_id       BIGINT REFERENCES kb_category(id) ON DELETE CASCADE,
  slug            TEXT NOT NULL UNIQUE,
  name            TEXT NOT NULL,
  description     TEXT,
  icon            TEXT,
  is_visible      BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order      INTEGER NOT NULL DEFAULT 0,
  view_count      INTEGER NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- KB Articles
CREATE TABLE kb_article (
  id              BIGSERIAL PRIMARY KEY,
  category_id     BIGINT NOT NULL REFERENCES kb_category(id),
  slug            TEXT NOT NULL,
  title           TEXT NOT NULL,
  summary         TEXT,
  content         TEXT NOT NULL,
  keywords        TEXT[],

  -- Publishing
  is_published    BOOLEAN NOT NULL DEFAULT FALSE,
  is_featured     BOOLEAN NOT NULL DEFAULT FALSE,
  is_pinned       BOOLEAN NOT NULL DEFAULT FALSE,

  -- Metrics
  view_count      INTEGER NOT NULL DEFAULT 0,
  helpful_yes     INTEGER NOT NULL DEFAULT 0,
  helpful_no      INTEGER NOT NULL DEFAULT 0,
  avg_rating      NUMERIC(2,1),
  rating_count    INTEGER NOT NULL DEFAULT 0,

  -- Tracking
  last_reviewed   TIMESTAMPTZ,
  created_by      BIGINT NOT NULL,
  updated_by      BIGINT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE(category_id, slug)
);

-- Article feedback
CREATE TABLE kb_article_feedback (
  id              BIGSERIAL PRIMARY KEY,
  article_id      BIGINT NOT NULL REFERENCES kb_article(id) ON DELETE CASCADE,
  account_id      BIGINT REFERENCES account(id) ON DELETE SET NULL,
  session_id      TEXT,

  helpful         BOOLEAN,
  rating          INTEGER CHECK (rating BETWEEN 1 AND 5),
  comment         TEXT,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE(article_id, account_id),
  UNIQUE(article_id, session_id)
);

-- Related articles
CREATE TABLE kb_article_related (
  id              BIGSERIAL PRIMARY KEY,
  article_id      BIGINT NOT NULL REFERENCES kb_article(id) ON DELETE CASCADE,
  related_id      BIGINT NOT NULL REFERENCES kb_article(id) ON DELETE CASCADE,
  relevance_score NUMERIC(3,2) DEFAULT 1.0,
  UNIQUE(article_id, related_id),
  CHECK(article_id != related_id)
);

-- Search tracking
CREATE TABLE kb_search_log (
  id              BIGSERIAL PRIMARY KEY,
  query           TEXT NOT NULL,
  results_count   INTEGER NOT NULL,
  clicked_article BIGINT REFERENCES kb_article(id),
  account_id      BIGINT REFERENCES account(id),
  session_id      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Full-text search index
CREATE INDEX kb_article_search_idx ON kb_article USING GIN(
  to_tsvector('english', title || ' ' || content)
);
CREATE INDEX kb_article_keywords_idx ON kb_article USING GIN(keywords);
CREATE INDEX kb_article_published_idx ON kb_article(is_published, category_id);
CREATE INDEX kb_article_featured_idx ON kb_article(is_featured) WHERE is_featured = TRUE;
CREATE INDEX kb_search_log_query_idx ON kb_search_log(query, created_at DESC);
```

## Cancellation Workflow

```sql
-- Cancellation requests
CREATE TABLE cancellation_request (
  id                BIGSERIAL PRIMARY KEY,
  service_id        BIGINT NOT NULL REFERENCES service(id) ON DELETE CASCADE,
  account_id        BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,

  -- Request details
  type              TEXT NOT NULL CHECK (type IN ('immediate','end_of_billing')),
  reason            TEXT NOT NULL CHECK (reason IN (
    'not_using',
    'too_expensive',
    'missing_features',
    'poor_performance',
    'poor_support',
    'switching_provider',
    'business_closing',
    'other'
  )),
  reason_details    TEXT,
  competitor        TEXT,

  -- Workflow status
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending',
    'in_review',
    'retention_offer',
    'approved',
    'rejected',
    'withdrawn',
    'completed'
  )),

  -- Dates
  requested_date    DATE NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at       TIMESTAMPTZ,
  reviewed_by       BIGINT,
  completed_at      TIMESTAMPTZ,

  -- Retention
  retention_offered BOOLEAN NOT NULL DEFAULT FALSE,
  retention_notes   TEXT,
  retention_accepted BOOLEAN,

  UNIQUE(service_id)
);

-- Retention offers
CREATE TABLE retention_offer (
  id                BIGSERIAL PRIMARY KEY,
  cancellation_id   BIGINT NOT NULL REFERENCES cancellation_request(id),

  offer_type        TEXT NOT NULL CHECK (offer_type IN (
    'discount_percentage',
    'discount_fixed',
    'free_months',
    'upgrade',
    'downgrade',
    'addon_free',
    'custom'
  )),
  offer_value       JSONB NOT NULL,
  valid_until       TIMESTAMPTZ,

  presented_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  presented_by      BIGINT NOT NULL,

  response          TEXT CHECK (response IN ('accepted','rejected','no_response')),
  responded_at      TIMESTAMPTZ
);

-- Cancellation automation rules
CREATE TABLE cancellation_automation (
  id                BIGSERIAL PRIMARY KEY,
  product_id        BIGINT REFERENCES product(id),
  reason            TEXT,
  min_account_age_days INTEGER,
  max_account_value NUMERIC(10,2),

  auto_approve      BOOLEAN NOT NULL DEFAULT FALSE,
  auto_offer_type   TEXT,
  auto_offer_value  JSONB,

  is_active         BOOLEAN NOT NULL DEFAULT TRUE
);

-- Post-cancellation survey
CREATE TABLE cancellation_survey (
  id                BIGSERIAL PRIMARY KEY,
  cancellation_id   BIGINT NOT NULL REFERENCES cancellation_request(id),

  improvement_feedback TEXT,
  feature_requests  TEXT[],
  would_recommend   INTEGER CHECK (would_recommend BETWEEN 0 AND 10),
  may_return        BOOLEAN,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX cancel_req_status_idx ON cancellation_request(status, created_at)
  WHERE status IN ('pending','in_review');
CREATE INDEX cancel_req_service_idx ON cancellation_request(service_id);
CREATE INDEX cancel_req_date_idx ON cancellation_request(requested_date)
  WHERE status IN ('approved','pending');
```

## API Access & Automation

```sql
-- API tokens
CREATE TABLE api_token (
  id                BIGSERIAL PRIMARY KEY,
  account_id        BIGINT REFERENCES account(id) ON DELETE CASCADE,
  user_id           BIGINT NOT NULL,

  -- Token details
  name              TEXT NOT NULL,
  description       TEXT,
  token_hash        TEXT NOT NULL UNIQUE,
  token_prefix      TEXT NOT NULL,

  -- Permissions
  permissions       JSONB NOT NULL DEFAULT '[]'::jsonb,
  /* Example:
    ["invoices:read", "invoices:write", "services:read",
     "services:provision", "domains:manage", "tickets:create"]
  */

  -- Restrictions
  allowed_ips       INET[],
  rate_limit_per_hour INTEGER DEFAULT 1000,
  rate_limit_per_day  INTEGER DEFAULT 10000,

  -- Tracking
  last_used_at      TIMESTAMPTZ,
  last_used_ip      INET,
  use_count         INTEGER NOT NULL DEFAULT 0,

  -- Lifecycle
  expires_at        TIMESTAMPTZ,
  is_active         BOOLEAN NOT NULL DEFAULT TRUE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at        TIMESTAMPTZ,
  revoked_by        BIGINT,
  revoke_reason     TEXT
);

-- API request logging
CREATE TABLE api_request_log (
  id                BIGSERIAL PRIMARY KEY,
  token_id          BIGINT REFERENCES api_token(id) ON DELETE SET NULL,

  method            TEXT NOT NULL,
  endpoint          TEXT NOT NULL,
  request_body_size INTEGER,
  response_status   INTEGER,
  response_time_ms  INTEGER,

  ip_address        INET,
  user_agent        TEXT,
  error_message     TEXT,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Webhook subscriptions
CREATE TABLE webhook_subscription (
  id                BIGSERIAL PRIMARY KEY,
  account_id        BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,

  name              TEXT NOT NULL,
  url               TEXT NOT NULL,
  secret            TEXT NOT NULL,
  events            TEXT[] NOT NULL,
  /* Events:
    ["invoice.created", "invoice.paid", "service.suspended",
     "service.activated", "ticket.created", "domain.expiring"]
  */

  is_active         BOOLEAN NOT NULL DEFAULT TRUE,
  retry_failed      BOOLEAN NOT NULL DEFAULT TRUE,
  max_retries       INTEGER DEFAULT 3,

  -- Stats
  success_count     INTEGER NOT NULL DEFAULT 0,
  failure_count     INTEGER NOT NULL DEFAULT 0,
  last_triggered    TIMESTAMPTZ,
  last_success      TIMESTAMPTZ,
  last_failure      TIMESTAMPTZ,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Webhook deliveries
CREATE TABLE webhook_delivery (
  id                BIGSERIAL PRIMARY KEY,
  subscription_id   BIGINT NOT NULL REFERENCES webhook_subscription(id) ON DELETE CASCADE,

  event_type        TEXT NOT NULL,
  event_id          TEXT NOT NULL,
  payload           JSONB NOT NULL,
  attempt_count     INTEGER NOT NULL DEFAULT 1,

  response_status   INTEGER,
  response_body     TEXT,
  response_time_ms  INTEGER,

  status            TEXT NOT NULL CHECK (status IN ('pending','success','failed','abandoned')),
  next_retry_at     TIMESTAMPTZ,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at      TIMESTAMPTZ
);

-- Rate limiting
CREATE TABLE api_rate_limit (
  id                BIGSERIAL PRIMARY KEY,
  token_id          BIGINT NOT NULL REFERENCES api_token(id) ON DELETE CASCADE,
  window_start      TIMESTAMPTZ NOT NULL,
  window_type       TEXT NOT NULL CHECK (window_type IN ('hour','day')),
  request_count     INTEGER NOT NULL DEFAULT 1,
  UNIQUE(token_id, window_start, window_type)
);

CREATE INDEX api_token_hash_idx ON api_token(token_hash) WHERE is_active = TRUE;
CREATE INDEX api_token_prefix_idx ON api_token(token_prefix);
CREATE INDEX api_request_log_token_idx ON api_request_log(token_id, created_at DESC);
CREATE INDEX webhook_delivery_status_idx ON webhook_delivery(status, next_retry_at)
  WHERE status = 'pending';
```

## Payment Retry Management (Dunning)

```sql
-- Dunning configuration
CREATE TABLE dunning_config (
  id                BIGSERIAL PRIMARY KEY,
  name              TEXT NOT NULL,

  retry_schedule    JSONB NOT NULL,
  /* Example:
    [
      {"days": 1, "email": "payment_failed"},
      {"days": 3, "email": "payment_retry_3day"},
      {"days": 7, "email": "payment_retry_7day", "action": "suspend"},
      {"days": 14, "email": "payment_final", "action": "terminate"}
    ]
  */

  max_retries       INTEGER NOT NULL DEFAULT 3,
  retry_on_soft_decline BOOLEAN NOT NULL DEFAULT TRUE,
  suspend_on_failure BOOLEAN NOT NULL DEFAULT TRUE,

  is_default        BOOLEAN NOT NULL DEFAULT FALSE,
  is_active         BOOLEAN NOT NULL DEFAULT TRUE
);

-- Active dunning processes
CREATE TABLE dunning_process (
  id                BIGSERIAL PRIMARY KEY,
  invoice_id        BIGINT NOT NULL REFERENCES invoice(id),
  config_id         BIGINT NOT NULL REFERENCES dunning_config(id),

  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN (
    'active',
    'paused',
    'succeeded',
    'failed',
    'cancelled'
  )),

  current_step      INTEGER NOT NULL DEFAULT 0,
  retry_count       INTEGER NOT NULL DEFAULT 0,
  last_retry_at     TIMESTAMPTZ,
  next_retry_at     TIMESTAMPTZ,

  original_amount   BIGINT NOT NULL,
  recovered_amount  BIGINT DEFAULT 0,

  started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  succeeded_at      TIMESTAMPTZ,
  failed_at         TIMESTAMPTZ,

  UNIQUE(invoice_id)
);

-- Dunning attempts
CREATE TABLE dunning_attempt (
  id                BIGSERIAL PRIMARY KEY,
  process_id        BIGINT NOT NULL REFERENCES dunning_process(id),
  attempt_number    INTEGER NOT NULL,

  payment_method    TEXT,
  amount_cents      BIGINT NOT NULL,

  status            TEXT NOT NULL CHECK (status IN (
    'pending',
    'processing',
    'succeeded',
    'failed',
    'error'
  )),
  failure_reason    TEXT,
  gateway_response  JSONB,

  email_sent        TEXT,
  service_action    TEXT,

  attempted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at      TIMESTAMPTZ
);

-- Smart retry rules
CREATE TABLE dunning_smart_rule (
  id                BIGSERIAL PRIMARY KEY,
  rule_type         TEXT NOT NULL CHECK (rule_type IN (
    'skip_low_value',
    'skip_new_customer',
    'vip_extended',
    'card_type',
    'failure_code'
  )),
  conditions        JSONB NOT NULL,
  action            JSONB NOT NULL,
  priority          INTEGER NOT NULL DEFAULT 100,
  is_active         BOOLEAN NOT NULL DEFAULT TRUE
);

-- Payment behavior tracking
CREATE TABLE payment_behavior (
  id                BIGSERIAL PRIMARY KEY,
  account_id        BIGINT NOT NULL REFERENCES account(id),

  total_payments    INTEGER NOT NULL DEFAULT 0,
  successful_payments INTEGER NOT NULL DEFAULT 0,
  failed_payments   INTEGER NOT NULL DEFAULT 0,

  dunning_cycles    INTEGER NOT NULL DEFAULT 0,
  dunning_recoveries INTEGER NOT NULL DEFAULT 0,
  avg_recovery_days NUMERIC(5,2),

  risk_score        NUMERIC(3,2) DEFAULT 0.5,
  risk_factors      JSONB,

  preferred_payment_day INTEGER,
  avg_payment_delay_days NUMERIC(5,2),

  last_updated      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX dunning_process_status_idx ON dunning_process(status, next_retry_at)
  WHERE status = 'active';
CREATE INDEX dunning_process_invoice_idx ON dunning_process(invoice_id);
CREATE INDEX payment_behavior_risk_idx ON payment_behavior(risk_score DESC);
```

## Email System

```sql
-- Email templates
CREATE TABLE email_template (
  id           BIGSERIAL PRIMARY KEY,
  key          TEXT NOT NULL,
  locale       TEXT NOT NULL DEFAULT 'en',

  subject      TEXT NOT NULL,
  body_html    TEXT NOT NULL,
  body_text    TEXT,

  variables    TEXT[], -- Available variables for this template

  is_active    BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (key, locale)
);

-- Email log
CREATE TABLE email_log (
  id           BIGSERIAL PRIMARY KEY,
  account_id   BIGINT REFERENCES account(id) ON DELETE SET NULL,

  to_addr      TEXT NOT NULL,
  cc_addr      TEXT,
  bcc_addr     TEXT,
  from_addr    TEXT NOT NULL,
  reply_to     TEXT,

  template_key TEXT,
  subject      TEXT NOT NULL,

  sent_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  status       TEXT NOT NULL CHECK (status IN (
    'queued',
    'sent',
    'delivered',
    'opened',
    'clicked',
    'bounced',
    'failed',
    'spam'
  )),

  provider     TEXT,
  provider_id  TEXT,

  opened_at    TIMESTAMPTZ,
  clicked_at   TIMESTAMPTZ,
  bounced_at   TIMESTAMPTZ,

  meta         JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX email_log_account_idx ON email_log(account_id, sent_at DESC);
CREATE INDEX email_log_status_idx ON email_log(status, sent_at DESC);
CREATE INDEX email_to_sent_idx ON email_log(to_addr, sent_at DESC);
```

## Webhooks & Events

```sql
-- Webhook event deduplication
CREATE TABLE webhook_event (
  id           BIGSERIAL PRIMARY KEY,
  source       TEXT NOT NULL,         -- 'stripe','paypal','virtualmin'
  event_id     TEXT NOT NULL,         -- Provider's unique ID

  received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at TIMESTAMPTZ,

  status       TEXT NOT NULL CHECK (status IN ('pending','processed','failed','skipped')),

  payload      JSONB NOT NULL,
  signature    TEXT,

  error        TEXT,

  UNIQUE (source, event_id)
);

CREATE UNIQUE INDEX webhook_source_event_udx ON webhook_event(source, event_id);
CREATE INDEX webhook_pending_idx ON webhook_event(status, received_at)
  WHERE status = 'pending';
```

## Audit & Compliance

```sql
-- Immutable audit log
CREATE TABLE audit_event (
  id           BIGSERIAL PRIMARY KEY,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Actor
  actor_user_id BIGINT,
  actor_type   TEXT, -- 'user','system','api'
  ip_address   INET,
  user_agent   TEXT,

  -- Action
  action       TEXT NOT NULL, -- 'login','invoice.create','service.suspend'
  resource     TEXT NOT NULL, -- 'invoice:123','service:456'

  -- Changes
  old_values   JSONB,
  new_values   JSONB,

  -- Context
  request_id   TEXT,
  session_id   TEXT,

  meta         JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- GDPR data processing records
CREATE TABLE gdpr_consent (
  id           BIGSERIAL PRIMARY KEY,
  account_id   BIGINT NOT NULL REFERENCES account(id),

  consent_type TEXT NOT NULL CHECK (consent_type IN (
    'terms',
    'privacy',
    'marketing',
    'cookies',
    'data_processing'
  )),

  version      TEXT NOT NULL,
  given_at     TIMESTAMPTZ NOT NULL,
  withdrawn_at TIMESTAMPTZ,

  ip_address   INET,
  user_agent   TEXT,

  UNIQUE(account_id, consent_type, version)
);

-- Data retention policy
CREATE TABLE data_retention_policy (
  id           BIGSERIAL PRIMARY KEY,
  table_name   TEXT NOT NULL UNIQUE,
  retention_days INTEGER NOT NULL,

  anonymize    BOOLEAN NOT NULL DEFAULT FALSE,
  hard_delete  BOOLEAN NOT NULL DEFAULT TRUE,

  last_run     TIMESTAMPTZ,
  next_run     TIMESTAMPTZ,

  is_active    BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX audit_actor_created_idx ON audit_event(actor_user_id, created_at DESC);
CREATE INDEX audit_resource_idx ON audit_event(resource, created_at DESC);
CREATE INDEX audit_action_idx ON audit_event(action, created_at DESC);
```

## Indexes & Performance

```sql
-- ============================================================================
-- PERFORMANCE INDEXES
-- ============================================================================

-- Dashboard queries
CREATE INDEX inv_account_unpaid_idx ON invoice(account_id, due_at)
  WHERE status IN ('issued','overdue');

-- Renewal processing
CREATE INDEX svc_renewal_active_idx ON service(next_renewal_at, status)
  WHERE status = 'active' AND next_renewal_at IS NOT NULL;

-- Domain monitoring
CREATE INDEX domain_expiry_active_idx ON domain(expires_at, status)
  WHERE status = 'active';

-- Support queue
CREATE INDEX ticket_open_priority_idx ON ticket(department_id, priority DESC, created_at)
  WHERE status IN ('open','pending');

-- Payment reconciliation
CREATE INDEX payment_gateway_idx ON payment(gateway, gateway_txn_id)
  WHERE gateway_txn_id IS NOT NULL;

-- Usage queries
CREATE INDEX service_usage_period_idx ON service_resource_usage(service_id, last_updated);

-- ============================================================================
-- PARTITIONING STRATEGY (for scale)
-- ============================================================================

-- Partition audit events by month
CREATE TABLE audit_event_2025_01 PARTITION OF audit_event
  FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE audit_event_2025_02 PARTITION OF audit_event
  FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

-- Partition email log by month
CREATE TABLE email_log_2025_01 PARTITION OF email_log
  FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- ============================================================================
-- MAINTENANCE VIEWS
-- ============================================================================

-- Services requiring renewal
CREATE VIEW services_pending_renewal AS
SELECT s.*, a.name as account_name, p.name as product_name
FROM service s
JOIN account a ON s.account_id = a.id
JOIN product p ON s.product_id = p.id
WHERE s.status = 'active'
  AND s.next_renewal_at <= NOW() + INTERVAL '7 days';

-- Overdue invoices summary
CREATE VIEW overdue_invoices AS
SELECT i.*, a.name as account_name,
       NOW() - i.due_at as overdue_days
FROM invoice i
JOIN account a ON i.account_id = a.id
WHERE i.status IN ('issued','overdue')
  AND i.due_at < NOW()
ORDER BY i.due_at;

-- Server capacity overview
CREATE VIEW server_capacity AS
SELECT sg.name as group_name, s.*,
       ROUND((s.current_accounts::NUMERIC / NULLIF(s.max_accounts, 0)) * 100, 2) as usage_percentage
FROM server s
LEFT JOIN server_group sg ON s.group_id = sg.id
WHERE s.is_active = TRUE
ORDER BY usage_percentage DESC;
```

## Module Extension Pattern

```sql
-- Module registry for plugins
CREATE TABLE module_registry (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  version         TEXT NOT NULL,

  config_schema   JSONB,  -- JSON Schema for validation
  hooks           TEXT[], -- Events it listens to
  permissions     TEXT[], -- Required permissions

  is_active       BOOLEAN NOT NULL DEFAULT TRUE,
  installed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  installed_by    BIGINT NOT NULL
);

-- Module configuration
CREATE TABLE module_config (
  id              BIGSERIAL PRIMARY KEY,
  module_id       BIGINT NOT NULL REFERENCES module_registry(id),

  key             TEXT NOT NULL,
  value           JSONB NOT NULL,

  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by      BIGINT,

  UNIQUE(module_id, key)
);

-- Module-specific tables can be created with prefix
-- Example: cpanel_accounts, plesk_subscriptions, custom_fields
```

## Initial Data & Constants

```sql
-- Insert initial currencies
INSERT INTO currency (code, symbol, decimals) VALUES
  ('EUR', '€', 2),
  ('RON', 'lei', 2),
  ('USD', '$', 2),
  ('GBP', '£', 2);

-- Insert initial tax rules (Romanian VAT)
INSERT INTO tax_rule (country, tax_type, rate, valid_from) VALUES
  ('RO', 'VAT', 0.1900, '2024-01-01'),
  ('EU', 'VAT', 0.0000, '2024-01-01'); -- Reverse charge

-- Insert support departments
INSERT INTO support_department (name, email, sort_order) VALUES
  ('General', 'support@example.com', 1),
  ('Billing', 'billing@example.com', 2),
  ('Technical', 'tech@example.com', 3),
  ('Abuse', 'abuse@example.com', 4);

-- Insert default dunning config
INSERT INTO dunning_config (name, retry_schedule, is_default) VALUES
  ('Standard', '[
    {"days": 1, "email": "payment_failed"},
    {"days": 3, "email": "payment_retry"},
    {"days": 7, "email": "payment_warning", "action": "suspend"},
    {"days": 14, "email": "payment_final", "action": "terminate"}
  ]'::jsonb, TRUE);

-- Create sequences
INSERT INTO invoice_sequence (scope, prefix, last_value) VALUES
  ('default', 'INV-', 100000);

INSERT INTO proforma_sequence (scope, prefix, last_value) VALUES
  ('default', 'PRO-', 100000);
```

---

## Notes

1. **All monetary values are stored as integers in cents** to avoid floating-point issues
2. **Invoices are immutable after being issued** - changes require credit notes
3. **Soft deletes on critical tables** for GDPR compliance and recovery
4. **JSONB used for flexible module configuration** without schema changes
5. **Comprehensive indexes** based on real query patterns from WHMCS/Blesta
6. **Partitioning ready** for high-volume tables (audit, email logs)
7. **Romanian e-Factura ready** with proper invoice sequencing and XML storage
8. **Multi-server support** with automatic allocation and capacity tracking
9. **Complete product relationships** supporting bundles, addons, and dependencies
10. **Full dunning/retry management** for failed payments with smart rules

This schema supports everything WHMCS, Blesta, and FOSSBilling offer, plus modern requirements like API automation, comprehensive audit trails, and EU compliance.
