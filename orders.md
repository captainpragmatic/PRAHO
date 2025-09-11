# 📦 PRAHO Orders System Analysis

## ✅ Implementation Update (Portal + Platform)

This documents what is now implemented across Portal and Platform, and what remains regarding draft → pending automation and the customer-visible flow.

### What’s Implemented Now
- Platform Orders API (HMAC-secured)
  - Endpoints under `/api/orders/`:
    - `GET /api/orders/products/` and `GET /api/orders/products/{slug}/` for catalog.
    - `POST /api/orders/calculate/` computes authoritative totals (includes setup + 19% VAT).
    - `POST /api/orders/create/` creates an Order with item snapshots (unit price, setup, billing period).
    - `POST /api/orders/` and `POST /api/orders/{order_id}/` list/detail scoped to customer.
  - Pricing resolution on create: we resolve `ProductPrice` using `currency + billing_period`, snapshot `unit_price_cents`, `setup_cents`, and `billing_period` into `OrderItem`s, and recalc order totals from items.
  - VAT branching: per-item VAT is computed via Order VAT Rules (EU-compliant). Romania rate updated to 21% (reverse charge for EU B2B, destination VAT for EU B2C, 0% for non‑EU).

- Portal Orders app (session cart, HTMX flow)
  - Catalog → Cart → Checkout → Create Order → Confirmation.
  - Session cart with validation, rate limiting, and mini‑cart widget.
  - Cart totals call Platform `/api/orders/calculate/` (server-authoritative).
  - Create Order calls Platform `/api/orders/create/` and then shows confirmation by POSTing to `/api/orders/{id}/`.
  - CSRF is enforced on HTMX requests (global header + form tokens).
  - UI updated to display TVA (21%) labels.

### Platform Behavior on Creation (current)
- New orders are created with status `draft` (intended as a safe, editable snapshot/quote state). No invoice is issued; no payment expected yet.
- Each `OrderItem` is created with `provisioning_status = pending` (this is the provisioning pipeline state, not payment). This does NOT trigger provisioning while the order is `draft`.
- Provisioning only kicks in after status transitions managed by signals:
  - `pending → processing` → invoice generation hook.
  - `processing → completed` → provisioning starts for items.

## 🔄 Status Lifecycle & Automation Plan

Today’s lifecycle, by design:
- `draft` → initial state at creation (editable, non‑payable).
- `pending` → awaiting payment.
- `processing` → payment received; billing hooks run.
- `completed` → provisioning begins; services created and linked to items.

What we’ll automate next:
- Draft → Pending (self‑serve orders)
  - Option A (simple): Immediately transition to `pending` after `/api/orders/create/` for portal‑origin orders. This makes the order “awaiting payment” without staff action.
  - Option B (with proforma): On transition to `pending`, generate a proforma and expose a “Pay” action. Keep the existing invoice generation hook on `processing`.

- Pending → Processing
  - Triggered by payment capture (gateway/webhook/controller). When payment is confirmed, move `pending → processing`. Current signals then run invoice generation on this transition.

- Processing → Completed
  - When fulfillment criteria are met (e.g., invoice issued, integrity checks OK), move to `completed` to start provisioning. Items with `provisioning_status = pending` will be queued for provisioning.

Notes:
- Customers cannot (and should not) pay while an order is `draft`.
- Customers do not see “provisioning status” of items; they only see the order and its items/totals. Provisioning runs only after `completed`.

## ✅ Staff Workflow: Draft Validation Before Pending

Draft as an initial state is correct: it allows staff to verify legal/billing correctness before the order becomes payable. We will gate the `draft → pending` transition behind a deterministic validation service.

### Draft Preflight Validation (new)
- Service: `OrderPreflightValidationService`
  - API: `validate(order: Order) -> tuple[list[str], list[str]]` (errors, warnings) and `assert_valid(order)` raising on blocking errors.
  - Checks:
    - Customer profile completeness: company/person name, email, billing address fields (line1, city, county, postal code, country), phone.
    - Tax context: VAT number presence/format when business; country present and ISO‑2; business flag coherent.
    - VAT scenario & amounts: recompute via `OrderVATCalculator` (RO 21% / EU B2B reverse / EU B2C destination / non‑EU 0%) against order snapshot; totals must match; mismatch = error.
    - Pricing snapshot: each `OrderItem` must have `product_price_id` in `meta`, a valid `billing_period`, non‑negative `unit_price_cents`/`setup_cents`.
    - Product state: product is still active and price for the chosen period exists (warning if changed since snapshot, error if missing).
    - Currency consistency: order currency supported and consistent with item price currency.
    - Totals consistency: `order.total_cents == sum(items subtotal + VAT)`; otherwise error (forces re‑calc).
  - Output is shown to staff with quick links to fix customer profile or edit the order.

### Enforcement
- Status transition hook: On `draft → pending`, call `OrderPreflightValidationService.assert_valid(order)`. If errors exist, refuse transition (showing errors in UI). Warnings may allow override by `billing`/`admin` roles (audited).
- Staff UI: “Run Validation” button on draft orders (HTMX) shows errors/warnings; “Promote to Pending” enabled only when no errors.
- Audit: log preflight result and any override in `audit` logs.

### Why this approach
- Prevents issuing payable orders with broken billing/tax data (GDPR and fiscal compliance).
- Keeps VAT calculation single‑sourced (OrderVATCalculator) and verified at transition time.
- Clean separation of concerns: all validation rules live in one service, reusable by APIs and UI.

### Future (optional)
- Auto‑fix suggestions (e.g., fill VAT rate reasoning into order `meta`).
- VIES validation for EU VAT numbers.

## 👣 Implementation Plan (for the draft preflight)
1) Add `apps/orders/preflight.py` with `OrderPreflightValidationService` (pure functions; no side effects).
2) Wire into `OrderService.update_order_status` for `draft → pending` (call and fail with `Err` on blocking errors).
3) Staff UI in Platform: add “Run Validation” and surface results on draft order page; gate “Promote to Pending”.
4) Tests: unit tests for each validation check + an integration test for blocking transition.
5) Docs: short runbook for staff and troubleshooting (e.g., VAT mismatch reasons).

## 📝 To‑Do (Follow‑ups)

1) Draft → Pending automation (Portal/Platform)
- Add a small platform endpoint or reuse status service to set portal orders to `pending` immediately after create (or behind a feature flag `auto_pending=true`).
- Optional: Generate a proforma on enter `pending` and expose it to the customer.

2) Payments integration (later)
- On successful payment, call platform to transition `pending → processing` (invoice generation is already wired there via signals).
- When post‑payment checks pass, transition `processing → completed` to trigger provisioning.

3) Portal “My Orders” view
- Add a list/detail page in portal backed by `POST /api/orders/` and `POST /api/orders/{id}/` so customers can see history and statuses.

4) Tests & docs
- DRF tests for `/api/orders/create/` (prices/periods snapshot, totals with setup & VAT) and `/api/orders/calculate/` (warnings, edge periods).
  - VAT tests to cover RO 21%, EU B2B reverse charge (0%), EU B2C destination rate, non‑EU 0%.
- Portal tests for cart → checkout → create (already scaffolded; expand to cover confirmation and CSRF/HTMX flows).

— End of implementation update —

## 🔍 **Current State Analysis**

### **What's Missing:**
1. **Product/Service Catalog**: No integrated product selection system
2. **Order Creation Form**: The form shows placeholder content  
3. **Shopping Cart**: No cart/basket functionality
4. **Product-Order Integration**: Limited connection to provisioning system

### **What's There:**
- Order models support both `product_id` and `service_id` foreign keys
- Service layer has all the business logic for order creation
- Templates show order items properly once created

## 🛠️ **How Orders Should Work** (Based on the Architecture)

Looking at the models and codebase, here's how order placement should flow:

### **1. Product/Service Selection**
Orders should pull from the **Products app** (`apps/products/`):
```python
# From apps/orders/models.py - OrderItem has these relationships:
product = models.ForeignKey('products.Product', ...)  # Hosting plans, domains, etc.
service = models.ForeignKey('provisioning.Service', ...)  # Active customer services (for existing services)
```

### **2. Order Creation Process**
The intended flow appears to be:
1. **Browse Products** → View available hosting plans, domains, add-ons
2. **Add to Cart** → Select products with quantities and configurations  
3. **Customer Details** → Billing address, VAT info (Romanian compliance)
4. **Review & Place** → Confirm order with VAT calculations
5. **Payment & Provisioning** → Convert to invoice and provision services

### **3. Integration Points**
The order system is designed to integrate with:
- **`apps/products/`** - Product catalog with pricing and specifications
- **`apps/provisioning/`** - Service management and provisioning after order completion
- **`apps/billing/`** - Convert orders to proformas/invoices
- **`apps/customers/`** - Customer billing profiles and addresses

## 📊 **Product Catalog Discovery**

✅ **Products are defined in `apps/products/models.py`** - This is the master catalog!

The system has a comprehensive product catalog with:

### **Core Product Model** (`apps/products/models.py`)
- **Product Types**: `shared_hosting`, `vps`, `dedicated`, `domain`, `ssl`, `email`, `backup`, `addon`, `license`, `support`
- **Multi-currency Pricing**: `ProductPrice` model with billing periods (monthly, annual, etc.)
- **Romanian Compliance**: VAT handling, pricing in cents to avoid float issues
- **Product Relationships**: Upsells, cross-sells, requirements, bundles
- **Advanced Features**: Product bundles, promotional pricing, module configuration

### **Provisioning Integration** (`apps/provisioning/models.py`)
- **ServicePlan**: Different structure - appears to be legacy or alternative approach
- **Pricing**: Direct Romanian Lei pricing fields
- **Features**: JSON-based specifications

## 🔗 **Current Product-Order Integration**

✅ **Orders ARE connected to products**, but the integration is incomplete:

```python
# From apps/orders/models.py - OrderItem
class OrderItem(models.Model):
    # Product relationship
    product = models.ForeignKey(
        'products.Product',  # ✅ Connected to products app
        on_delete=models.PROTECT,
        help_text=_("Product being ordered")
    )
    
    # Product snapshot fields
    product_name = models.CharField(...)     # Snapshot of product name
    product_type = models.CharField(...)     # Snapshot of product type
    billing_period = models.CharField(...)   # Billing frequency
    
    # Pricing snapshot (protects against price changes)
    unit_price_cents = models.BigIntegerField(...)
    setup_cents = models.BigIntegerField(...)
    tax_cents = models.BigIntegerField(...)
    
    # Configuration for provisioning
    config = models.JSONField(...)           # Product-specific config
    domain_name = models.CharField(...)      # Associated domain
```

## 📋 **What Needs to Be Implemented**

To complete the order placement functionality, you would need:

### **Phase 1: Product Catalog Frontend**
1. **Product List View** - Browse available products by category
2. **Product Detail View** - Show specifications, pricing options, configure
3. **Product API/HTMX** - Dynamic pricing based on billing period selection

### **Phase 2: Shopping Cart System**  
1. **Cart Model/Session** - Store selected products before order creation
2. **Cart Management** - Add/remove items, quantity updates
3. **Cart UI** - Review items, see totals with VAT

### **Phase 3: Complete Order Form**
1. **Replace Placeholder Form** - Real product selection interface
2. **Customer Selection** (staff) or auto-populate (customers)  
3. **Billing Address Form** - Romanian VAT fields with validation
4. **Real-time Calculations** - VAT, totals, discounts

### **Phase 4: Integration Polish**
1. **Product-Price Integration** - Use `ProductPrice` model for current pricing
2. **Provisioning Triggers** - Auto-create services after order completion
3. **Bundle Support** - Handle `ProductBundle` and `ProductBundleItem`

## 🚀 **Recommended Implementation Path**

**You're absolutely right** - the first step should be connecting to the existing product catalog!

### **Priority 1: Product Integration in Orders** ⭐
1. Update order creation service to fetch products from `apps.products`
2. Use `Product.get_price_for_period()` method for current pricing  
3. Create product selection interface in order form
4. Test with a few sample products

### **Priority 2: Simple Product Catalog**
1. Create basic product list view (`/app/products/`)
2. Show active products with pricing
3. "Add to Order" functionality (skip cart for now)

### **Priority 3: Enhanced Order Flow**
1. Multi-step order process
2. Configuration options per product type
3. Domain selection for hosting products

## 🎯 **Quick Win Implementation**

The fastest path to working order placement:

1. **Populate Product Catalog** - Add sample products via Django admin
2. **Product Selection Dropdown** - Replace order form placeholder with real product list
3. **Price Lookup** - Use `ProductPrice` model to get current pricing  
4. **Basic Order Creation** - Connect form to existing order service

This would give you a functional order system in ~1-2 hours of focused development.

## 🔧 **Technical Notes**

- **Products App** is the source of truth for catalog
- **Provisioning App** seems to have overlapping `ServicePlan` model (possible legacy)
- **Orders** properly snapshot product data to preserve pricing history
- **Romanian VAT** is handled correctly throughout the system
- **UUID Primary Keys** used consistently for security

The foundation is solid - just need to connect the UI layer to the existing product catalog! 🎉

## ✅ **Analysis Complete & Documented**

Perfect! I've discovered the key insight: 

**Orders ARE connected to products** - the `OrderItem` model has a foreign key to `apps.products.Product`, but the **frontend integration is missing**.

## 🎯 **Key Findings:**

1. **Products exist** in `apps/products/models.py` with comprehensive catalog:
   - Product types (hosting, VPS, domains, SSL, etc.)
   - Multi-currency pricing with `ProductPrice` model
   - Romanian VAT compliance built-in
   - Product relationships, bundles, promotional pricing

2. **Orders are connected** via `OrderItem.product` foreign key to `products.Product`

3. **Missing piece**: The order creation form doesn't pull from the product catalog - it just shows placeholder content

## 🚀 **Next Steps (Your Suggestion is Spot On!)**

You're absolutely right - **connecting orders to pull from the existing product catalog** should be the first step:

1. **Populate some sample products** via Django admin
2. **Update order creation form** to show real products instead of placeholder
3. **Use `ProductPrice` model** for current pricing
4. **Test end-to-end** order creation with real products

This would give you a functional order placement system very quickly since all the infrastructure is already there!

The analysis is now documented in `/Users/claudiu/Developer/PRAHO/orders.md` for reference. Would you like me to implement the product integration next?
