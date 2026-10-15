# Legal documents

PRAHO ships no legal text. Each deployment publishes its own Terms of Service, Privacy Policy and Cookie Policy, and the customer portal shows them (ADR-0058). Until Terms of Service are in force, nobody can register.

## Publishing

1. Sign in to the staff platform as an administrator and open **Settings → Legal documents**.
2. Choose the document, the language and the date it takes effect (today or later), and write the text in Markdown. Headings, lists, links, emphasis, quotes and tables are kept; anything else is removed.
3. **Preview** shows the result. **Publish** makes it a release, numbered `<effective date>.<n>`.

A release is never edited or removed. To correct one, publish another: the newest release whose date has come is the one in force. Customers who accepted an earlier release keep that record, and the portal still shows it at `/legal/<id>/`.

Publish each document at least in the default language (`system.default_language`): a language without its own release shows the default language's.

The portal shows the releases at `/terms/`, `/privacy-policy/` and `/cookie-policy/`. The staff platform's old addresses for them redirect there: to `https://` and `PORTAL_DOMAIN`, or to the customer portal URL staff set.

## What PRAHO records

- **Registration**: the Terms of Service release the customer accepted (`User.terms_document`), when, and an audit event naming the release by id, language, number and hash, together with the Privacy Policy release shown as a notice. Nobody is asked to tick a box consenting to the processing of their account's data: that processing performs the contract, and the privacy notice informs (GDPR Art. 13). If a newer terms release takes effect while someone is confirming their account, they are asked to read it first.
- **Ordering**: the Terms of Service release the checkout page linked (`Order.terms_document`) and, for an EU consumer, when they asked for the services to start within the 14-day withdrawal period (`Order.early_start_requested_at`), each with an audit event. The confirmation email attaches that release and states the request: the customer's durable copy.
- **Cookie choices**: the Cookie Policy release in force in the visitor's language (`CookieConsent.cookie_document`, its number in `consent_version`).
- **Publishing**: an audit event with the same reference and the publishing staff account.

## What the portal stores in the browser

The Cookie Policy page lists these under your own text, from the code that sets them: the session cookie, the CSRF cookie, `cookie_consent`, `cookie_consent_id`, the language cookie, `pendingCookieConsent` (local storage, until the choice is recorded), the htmx history cache (session storage, until the tab closes), and Stripe's own cookies on payment pages. Describe anything you add, such as analytics, in your Cookie Policy.

## Services PRAHO can send personal data to

Name in your Privacy Policy the ones your deployment enables:

| Service | When | What it receives |
|---|---|---|
| Stripe | Card payments | Payment and billing details |
| Your email provider (SMTP, Amazon SES, SendGrid or Mailgun) | Every customer email | Recipient address and message |
| Your hosting servers (Virtualmin) | Provisioning | Account, domain and contact details |
| Domain registrars (Gandi, ROTLD) | Domain orders | Registrant contact details |
| EU VIES | VAT number checks (EU operators) | The VAT number, and your own as requester |
| ANAF e-Factura, SmartBill, BNR | Romanian operators only | Invoices and their parties; BNR receives nothing personal |
| Cloud providers (Hetzner, DigitalOcean, Vultr, Linode, AWS) | Staff deploy hosting nodes | Server configuration, no customer data |
| S3-compatible storage | `MEDIA_STORAGE=s3` | Invoice PDFs, ticket attachments, GDPR exports |

## CNP collected for a .ro registration

When a .ro registrar requires a Romanian individual's CNP, checkout collects it through the write-only tax-profile API and stores it encrypted on `CustomerTaxProfile.cnp`. That profile also supplies the buyer identifier on subsequent proformas, invoices and e-Factura submissions. The registration and checkout notices state both uses; describe both, the registrar and enabled invoice recipients, and the applicable retention in your published Privacy Policy. The API never returns the CNP and its audit event records only that it was set.

## Development and tests

`generate_sample_data` and the e2e seed publish a SAMPLE release of each document in English and Romanian, marked as not legal text.
