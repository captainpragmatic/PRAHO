# ADR-0047: Jurisdiction-Parameterised Tax Policy and the Fiscal-Data Boundary

- **Status:** Accepted
- **Date:** 2026-09-15
- **Supersedes/extends:** [ADR-0041](ADR-0041-foreign-currency-efactura-accounting.md) (foreign-currency e-Factura accounting), [ADR-0005](ADR-0005-single-constants-file-architecture.md) (single constants file architecture)
- **Related:** [ADR-0015](ADR-0015-configuration-resolution-order.md) (configuration resolution order), [ADR-0042](ADR-0042-settings-catalog-and-consumer-contract.md) (settings consumer contract), [ADR-0016](ADR-0016-audit-trail-enforcement.md) (audit trail enforcement), [ADR-0025](ADR-0025-monetary-amounts-in-cents.md) (monetary amounts in cents)

> This ADR records a software-architecture decision. It is not legal, tax, or accounting
> advice, and it does not describe any particular operator's fiscal position. See NOTICE.md.

## Context

PRAHO determines VAT treatment for every billable document. Two facts about that code, taken
together, are the reason for this ADR.

**First, the supplier's jurisdiction is structural rather than configured.** `TaxService`
branches on the *customer's* country while the *supplier* is implicitly Romanian: the Romanian
branch is the home case, the EU branch applies destination-country rates unconditionally, and
no code path expresses "this supply is taxed where the supplier is established." That encodes
exactly one legal posture. A deployer established in another member state cannot express its
own; a deployer whose cross-border consumer supplies fall below the EU-wide micro-threshold
(and who has made no election into destination taxation) cannot express that either; nor can
one applying the cross-border small-enterprise scheme. The software offers a single answer to
a question that has several lawful answers.

**Second, PRAHO is distributed under GPL-3.0-or-later and is deployed by its author's company
as well as, potentially, by other operators.** Those two roles have different data. The
software's design — what modes exist, what evidence is required, what is recorded — is
product. An operator's place of establishment, registrations, special-scheme elections,
threshold position, and the classification of its own catalogue are *that operator's* fiscal
facts. When the code assumes a single operator, those facts have nowhere to live except the
codebase and its public issue tracker, and they leak there by default. This has already
happened.

A third, narrower observation shapes the evidence rules below: the decisions the system makes
are only as defensible as the evidence captured *at the moment of the decision*. Validation
services cannot be queried retroactively, and customer-location signals are not reconstructable
after the fact. Evidence not recorded when the document was produced is unrecoverable.

## Decision

### 1. Supplier jurisdiction becomes a parameter

A **jurisdiction policy pack** supplies, per deployment, the inputs the tax engine currently
assumes. Romania ships as the reference implementation because the project originated there;
it is a reference, not a default that fits every deployment. A pack provides:

- supplier country and VAT identity;
- per-product **place-of-supply classification** — not an ESS/non-ESS boolean, but which
  rule governs the product: electronically supplied, customer-placed by category, or the
  general rule. Whether a product is electronically supplied is the distinction the election
  below turns on, but it is not the only one that matters, and other categories carry their
  own rules. Classification is a per-product attribute, never inferred from the product type
  enum;
- the active **cross-border B2C election** (below) — the pack's only deployment-wide
  place-of-supply choice;
- the **evidence policy** for business-status determination and for customer-location
  determination;
- registrations and special schemes, recorded as **reporting facts only** — never as
  rate-selection switches. A registration describes where a liability is *declared*, not
  where it *arises*.

### 2. One deployment election; four per-supply outcomes

These are two different things and must not be modelled as one. **Exactly one** choice is
deployment-wide and effective-dated — the election governing **intra-EU** cross-border B2C
supplies of electronically supplied services. It reaches nothing else: not B2B, not non-ESS
products, and not customers outside the EU.

| Election | Effect on intra-EU cross-border B2C ESS |
|---|---|
| `SUPPLIER_COUNTRY` | Taxed where the supplier is established |
| `DESTINATION` | Taxed in the customer's member state |

Every other outcome is **derived per supply** from that supply's own evidence — customer
status, customer location, and product classification — because a single deployment serves
all of them simultaneously:

Each outcome is a function of three inputs — customer status, customer location, and the
product's place-of-supply classification. None of them alone is sufficient:

| Outcome | Derived when |
|---|---|
| Domestic | Customer is in the supplier's country |
| Reverse charge | EU B2B, and the recorded customer evidence satisfies the evidence policy |
| Intra-EU B2C, **election applies** | EU consumer in another member state, product classified electronically supplied; the election decides where it is taxed |
| Intra-EU B2C, **rule-governed** | EU consumer in another member state, product not electronically supplied; the product's own classification decides — the general rule places it at the supplier, a customer-placed category places it with the consumer. The election does not reach it |
| Outside scope | Customer outside the EU **and** the product's classification places the supply there. A product that falls to the general rule is taxable at the supplier even when the consumer is abroad |

The third input is the one most easily dropped. "EU consumer" does not by itself invoke the
election, and "customer outside the EU" does not by itself put a supply outside scope; in
both cases the product's classification decides. An implementation that reads only status and
location will select the wrong jurisdiction for every product outside the electronically-
supplied category.

Modelling all four as one selectable mode would make a mixed customer population
unrepresentable: a deployment that elected `DESTINATION` for its EU consumers must still
apply reverse charge to an eligible EU business and outside-scope treatment to a non-EU
customer, without any configuration change between orders. The election is policy; the rest
is evidence.

`OUTSIDE_SCOPE` is deliberately distinct from a zero rate. A supply outside the scope of a
tax is not a taxable supply at a rate of zero, and the two are not interchangeable at the
document layer: electronic-invoice standards reject an out-of-scope line that carries a rate
element at all.

### 3. Fiscal values are deployment data, never code — the boundary rule

**No fiscal fact about the deploying operator may exist in this repository.** Not as a
constant, a default argument, a fixture, a seed migration, a test fixture that doubles as
production data, or prose in documentation, an ADR, an issue, or a commit message.

All such values resolve through `SettingsService` per ADR-0015, as **effective-dated records
with provenance** — value, the date it takes effect, and who attested it. The repository
defines the *record shape*; the deployment supplies the *values*. This is the same
code/configuration separation ADR-0005 draws for constants, applied to a class of data where
the consequence of getting it wrong is not a bug but a disclosure.

Two properties follow, and both are the point:

- Changing fiscal policy is a configuration change with an audit trail, never a code change
  and never a deploy. Advice, when it arrives, selects and dates the election.
- There is no syntactically valid place in the codebase for an operator's fiscal position to
  land, so the leak has no pressure behind it. The boundary is structural, not a matter of
  editorial discipline.

Deployment-supplied, effective-dated facts include (non-exhaustive): supplier establishment(s);
the cross-border B2C election, its commencement date and its binding window; threshold
aggregates where a threshold governs that election; registrations and scheme memberships;
per-product service classification. There is exactly one deployment-wide place-of-supply
setting — a schema carrying both an election and a separate four-valued "mode" would
reintroduce the mixed-customer defect this ADR exists to prevent.

### 4. Typed decision result and snapshot provenance v2

Place-of-supply resolution returns a typed result, not a rate. It carries: customer status and
the evidence for it; customer country and its evidence source; supplier jurisdiction; resolved
place of supply; scenario and tax category; the tax-rule identity and effective date actually
used; the policy pack version; and a human-readable reason.

That result is snapshotted onto the document, extending the existing `vat_evidence` record
(which already versions the decision, is copied forward at conversion without recomputation,
and is covered by issue-time immutability). Provenance v2 adds the fields above, and — where
the evidence policy requires evidence — **the evidence actually used**, because under
electronic-reporting record-keeping rules the location evidence is itself part of the
mandatory record, not merely an input to it.

Line-level rates and categories remain authoritative. A document may carry several tax
categories; a single document-level rate cannot represent it and must not be introduced.

### 5. Evidence gates ship as mechanisms, defaulted to current behaviour

Business-status and customer-location evidence gates are built as mechanisms controlled by the
policy pack, with defaults preserving present behaviour. The mechanism is jurisdiction-neutral
engineering; requiring it is policy, and policy is data. This lets the gates land, be tested,
and be reviewed without any deployment's treatment changing until its own policy record says so.

Two behaviours are fixed regardless of policy, because they are failure-handling rather than
treatment:

- **Fail closed on unresolvable policy.** Missing, ambiguous, or expired policy state rejects
  the operation *before* an order becomes payable, rather than proceeding on a guess. This
  mirrors the currency-admission rule in ADR-0046: the alternative to refusing at admission is
  taking money for a document that cannot be lawfully issued.
- **Evidence unavailability is not evidence of absence.** When an external validation service
  is unreachable, the system holds or falls back to the conservative treatment; it never
  records a negative result it did not receive.

### 6. Issued documents never recompute

Document generation and statutory reporting read stored evidence only, and fail closed when a
required field is absent. No issued document consults live configuration — a rule ADR-0041
established for exchange rates and this ADR extends to the whole tax decision.

## Consequences

**Positive.** Jurisdiction becomes configurable, which is a prerequisite for any deployment
outside the reference jurisdiction. Fiscal policy changes without a release. The public
repository stops being a place where an operator's fiscal position can accumulate. Decisions
become auditable against the policy and evidence that produced them, rather than against
whatever configuration happens to be live at audit time.

**Negative / costs.** A policy-pack indirection sits in front of logic that is currently
direct, and every tax decision gains a resolution step. Deployments must supply configuration
that previously came free as a hardcoded assumption, so first-run setup is heavier and
fail-closed behaviour will reject under-configured deployments — deliberately. Per-product
classification must be populated for existing catalogues. Snapshot records grow.

**Neutral.** The reference jurisdiction's behaviour is preserved by the default policy pack,
so no existing deployment changes treatment on upgrade.

## Alternatives considered

**A boolean or registration flag selecting the rate (`registered ? destination : home`).**
Rejected: it conflates where a liability is *declared* with where it *arises*. A registration
is a reporting fact; treating it as the rate switch produces the right answer only by
coincidence and makes the wrong answer unrepresentable.

**A single global company-configuration singleton.** Rejected: it would create a second source
of truth competing with `SettingsService` and ADR-0015's resolution order, and — critically —
it would still be a place in the codebase where fiscal values could be defaulted, which is the
failure mode this ADR exists to remove.

**Keeping the Romanian assumption and documenting it as a limitation.** Rejected: the
assumption is not merely a missing feature. It is what forces operator-specific fiscal truth
into the repository, and it makes the single most consequential tax input the only one that
cannot be reviewed, dated, or audited.

**Deriving classification from the existing `product_type` field.** Rejected: whether a
service is electronically supplied turns on how it is actually delivered — the degree of human
involvement in each supply — not on the catalogue category it is sold under. Two products
sharing a type can classify differently, and a bundle can classify differently from its parts.

## Notes

The reference jurisdiction pack implements Romanian rules and is maintained on a best-effort
basis; legislative change is frequent and the pack may lag it. A deployer's own advice governs
its configuration. Nothing in this repository, including the reference pack, constitutes advice
or a representation of fitness for any operator's compliance obligations.
