# Mobile Screenshot Pass Plan

**Date**: 2026-03-04
**Tool**: Playwright MCP plugin (NOT Chrome MCP)
**Viewport**: 390x844 (iPhone 14 Pro)
**Credentials**: e2e-customer@test.local / test123

## Pre-requisites

1. Close ALL Chrome windows (Playwright needs to launch its own instance)
2. Ensure `make dev` is running (platform :8700 + portal :8701)

## Pages to Screenshot (13 pages)

Already have mobile screenshots for: Phase 1 (Auth — 6 screenshots) + Phase 2 (Dashboard — 1) + Phase 3 partial (profile_view — 1)

### Phase 3: Profile & Account (need 5 more)
| # | Page | URL | Filename |
|---|------|-----|----------|
| 1 | Company Profile | `/company/` | `03_profile/mobile_company_profile.png` |
| 2 | Change Password | `/change-password/` | `03_profile/mobile_change_password.png` |
| 3 | MFA Management | `/mfa/` | `03_profile/mobile_mfa_management.png` |
| 4 | Privacy Dashboard | `/privacy/` | `03_profile/mobile_privacy_dashboard.png` |
| 5 | Company Edit | `/company/edit/` | `03_profile/mobile_company_edit.png` |

### Phase 4: Billing (need 2)
| # | Page | URL | Filename |
|---|------|-----|----------|
| 6 | Invoice List | `/billing/invoices/` | `04_billing/mobile_invoices_list.png` |
| 7 | Invoice Detail | `/billing/invoices/INV-000082/` | `04_billing/mobile_invoice_detail.png` |

### Phase 5: Orders (need 2)
| # | Page | URL | Filename |
|---|------|-----|----------|
| 8 | Product Catalog | `/order/` | `05_orders/mobile_catalog.png` |
| 9 | Product Detail | `/order/products/product-1/` | `05_orders/mobile_product_detail.png` |

### Phase 6: Services (need 2)
| # | Page | URL | Filename |
|---|------|-----|----------|
| 10 | Service List | `/services/` | `06_services/mobile_services_list.png` |
| 11 | Service Detail | `/services/70/` | `06_services/mobile_service_detail.png` |

### Phase 7: Tickets (need 3)
| # | Page | URL | Filename |
|---|------|-----|----------|
| 12 | Ticket List | `/tickets/` | `07_tickets/mobile_tickets_list.png` |
| 13 | Ticket Create | `/tickets/create/` | `07_tickets/mobile_ticket_create.png` |
| 14 | Ticket Detail | `/tickets/86/` | `07_tickets/mobile_ticket_detail.png` |

## Execution Protocol

For EACH page:
1. `browser_resize` to 390x844
2. `browser_navigate` to URL
3. `browser_take_screenshot` with `filename` param → saves to QA/screenshots/{subfolder}/mobile_{name}.png
4. **VERIFY**: `ls` the screenshot file exists
5. **APPEND** action log entry to QA/action_log.md immediately
6. Move to next page

## Checkpoints

- After Phase 3 (page 5): verify 5 new files in `03_profile/`
- After Phase 4 (page 7): verify 2 new files in `04_billing/`
- After Phase 5 (page 9): verify 2 new files in `05_orders/`
- After Phase 6 (page 11): verify 2 new files in `06_services/`
- After Phase 7 (page 14): verify 3 new files in `07_tickets/`
- Final: `find QA/screenshots -name "mobile_*" | wc -l` should be 22 (8 existing + 14 new)

## Post-completion

1. Update QA/qa_report.md with mobile findings
2. Ensure action_log.md has all 14 new entries
3. Count all screenshots (desktop + mobile) for final inventory
