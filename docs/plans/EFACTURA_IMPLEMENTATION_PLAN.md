# e-Factura Implementation Plan

## Executive Summary

This document outlines a comprehensive implementation plan for integrating the Romanian **e-Factura** (RO e-Invoice) system into the PRAHO Platform. The integration will enable automatic submission of invoices to ANAF (Romanian National Agency for Fiscal Administration) in compliance with Romanian tax law.

**Target Compliance**: January 2025 B2B/B2C mandate with 5-day submission requirement.

---

## Table of Contents

1. [Legal Requirements](#1-legal-requirements)
2. [Technical Architecture](#2-technical-architecture)
3. [Existing Integration Points](#3-existing-integration-points)
4. [Implementation Phases](#4-implementation-phases)
5. [Data Models](#5-data-models)
6. [API Client Design](#6-api-client-design)
7. [XML Generation (UBL 2.1)](#7-xml-generation-ubl-21)
8. [Audit & Compliance Integration](#8-audit--compliance-integration)
9. [Error Handling & Retry Logic](#9-error-handling--retry-logic)
10. [Testing Strategy](#10-testing-strategy)
11. [Security Considerations](#11-security-considerations)
12. [Deployment & Rollout](#12-deployment--rollout)

---

## 1. Legal Requirements

### 1.1 Mandatory Compliance Dates

| Transaction Type | Mandatory Date | Penalty Grace Period |
|------------------|----------------|---------------------|
| B2B (Business to Business) | January 1, 2024 | Expired |
| B2C (Business to Consumer) | January 1, 2025 | March 31, 2025 |
| Simplified Invoices (B2B/B2C) | January 1, 2025 | March 31, 2025 |

### 1.2 Key Legal Constraints

- **Submission Deadline**: 5 calendar days from invoice issuance
- **Format**: UBL 2.1 XML with CIUS-RO national specification
- **Sequential Numbering**: Required by Romanian law (already implemented in PRAHO)
- **Minimum Amount**: Simplified invoices ≤100 EUR via cash register are exempt
- **GDPR**: B2C invoices may use 13-digit zero placeholder for beneficiary ID

### 1.3 Penalties

| Business Size | Fine Range (RON) |
|---------------|------------------|
| Large | 5,000 - 10,000 |
| Medium | 2,500 - 5,000 |
| Small | 1,000 - 2,500 |

### 1.4 Exemptions

- Point-of-sale transactions with fiscal receipt (electronic cash register)
- Associations, foundations, farmers: exempt until July 1, 2025

---

## 2. Technical Architecture

### 2.1 System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PRAHO Platform                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐   │
│  │   Invoice    │───▶│  e-Factura   │───▶│    EFacturaDocument      │   │
│  │    Model     │    │   Service    │    │        Model             │   │
│  └──────────────┘    └──────────────┘    └──────────────────────────┘   │
│         │                   │                        │                   │
│         ▼                   ▼                        ▼                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐   │
│  │   Signals    │    │ XML Builder  │    │   WebhookEvent           │   │
│  │ (auto-trigger)│    │  (UBL 2.1)  │    │  (status polling)        │   │
│  └──────────────┘    └──────────────┘    └──────────────────────────┘   │
│                              │                        │                  │
└──────────────────────────────┼────────────────────────┼──────────────────┘
                               │                        │
                               ▼                        ▼
                    ┌──────────────────────────────────────────┐
                    │            ANAF e-Factura API            │
                    ├──────────────────────────────────────────┤
                    │  OAuth2 ───▶ Upload ───▶ Status ───▶ PDF │
                    └──────────────────────────────────────────┘
```

### 2.2 ANAF API Endpoints

| Environment | Base URL |
|-------------|----------|
| **Production** | `https://api.anaf.ro/prod/FCTEL/rest` |
| **Test/Sandbox** | `https://api.anaf.ro/test/FCTEL/rest` |

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/upload` | POST | Submit invoice XML |
| `/stareMesaj` | GET | Check submission status |
| `/descarcare` | GET | Download processed response |
| `/listaMesaje` | GET | List available messages |
| `/validare` | POST | Validate XML (optional) |
| `/transformare` | POST | Convert XML to PDF |

### 2.3 OAuth2 Authentication

| Endpoint | URL |
|----------|-----|
| **Authorization** | `https://logincert.anaf.ro/anaf-oauth2/v1/authorize` |
| **Token** | `https://logincert.anaf.ro/anaf-oauth2/v1/token` |

**Requirements**:
- Digital certificate registered with ANAF SPV
- Application registered in ANAF developer portal
- Client ID and Client Secret from ANAF

---

## 3. Existing Integration Points

### 3.1 Already Implemented in PRAHO

| Component | Location | Status |
|-----------|----------|--------|
| Invoice e-Factura fields | `apps/billing/invoice_models.py:157-161` | ✅ Fields exist |
| Settings configuration | `config/settings/base.py:291-292` | ✅ Env vars defined |
| Async task placeholder | `apps/billing/tasks.py:27-60` | ⚠️ Stub only |
| Signal trigger | `apps/billing/signals.py:1174-1189` | ✅ Logic exists |
| WebhookEvent source | `apps/integrations/models.py:52` | ✅ 'efactura' defined |
| Audit events | `apps/audit/models.py:262-264` | ✅ Events defined |
| ComplianceLog | `apps/audit/models.py:675` | ✅ 'efactura_submission' |
| EFacturaService placeholder | `apps/billing/services.py` | ⚠️ Referenced but not implemented |

### 3.2 Invoice Model e-Factura Fields

```python
# apps/billing/invoice_models.py (lines 157-164)
efactura_id = models.CharField(max_length=100, blank=True)
efactura_sent = models.BooleanField(default=False)
efactura_sent_date = models.DateTimeField(null=True, blank=True)
efactura_response = models.JSONField(default=dict, blank=True)
xml_file = models.FileField(upload_to="invoices/xml/", blank=True, null=True)
```

### 3.3 Audit Event Types (Already Defined)

```python
# apps/audit/models.py
("efactura_submitted", "e-Factura Submitted"),
("efactura_accepted", "e-Factura Accepted"),
("efactura_rejected", "e-Factura Rejected"),
("invoice_xml_generated", "Invoice XML Generated"),
```

### 3.4 Signal Flow (Existing)

```python
# apps/billing/signals.py
def _requires_efactura_submission(invoice: Invoice) -> bool:
    return (
        invoice.bill_to_country == "RO"
        and bool(invoice.bill_to_tax_id)
        and invoice.total >= E_FACTURA_MINIMUM_AMOUNT  # 100 RON
    )

def _trigger_efactura_submission(invoice: Invoice) -> None:
    async_task("apps.billing.tasks.submit_efactura", str(invoice.id))
```

---

## 4. Implementation Phases

### Phase 1: Foundation (Week 1-2)

| Task | Priority | Effort |
|------|----------|--------|
| Create `EFacturaDocument` model | Critical | 4h |
| Implement OAuth2 client | Critical | 8h |
| Add settings & credential vault integration | Critical | 4h |
| Create e-Factura app structure | High | 2h |

### Phase 2: XML Generation (Week 2-3)

| Task | Priority | Effort |
|------|----------|--------|
| Implement UBL 2.1 Invoice XML builder | Critical | 16h |
| Implement UBL 2.1 Credit Note XML builder | Critical | 8h |
| Add CIUS-RO validation | Critical | 8h |
| Create XML template tests | High | 8h |

### Phase 3: API Integration (Week 3-4)

| Task | Priority | Effort |
|------|----------|--------|
| Implement upload endpoint client | Critical | 8h |
| Implement status polling | Critical | 4h |
| Implement download endpoint | High | 4h |
| Add retry logic with exponential backoff | High | 4h |

### Phase 4: Workflow Integration (Week 4-5)

| Task | Priority | Effort |
|------|----------|--------|
| Update billing signals | Critical | 4h |
| Implement async tasks (Django-Q2) | Critical | 4h |
| Add scheduled status polling job | High | 4h |
| Integrate with WebhookEvent model | High | 4h |

### Phase 5: Audit & Compliance (Week 5-6)

| Task | Priority | Effort |
|------|----------|--------|
| Integrate with ComplianceLog | Critical | 4h |
| Add BillingAuditService events | High | 4h |
| Create compliance dashboard | Medium | 8h |
| Add alert system for failures | High | 4h |

### Phase 6: Testing & Rollout (Week 6-7)

| Task | Priority | Effort |
|------|----------|--------|
| Unit tests | Critical | 8h |
| Integration tests with ANAF sandbox | Critical | 8h |
| E2E tests | High | 4h |
| Production deployment | Critical | 4h |

**Total Estimated Effort**: ~140 hours (3.5 weeks full-time)

---

## 5. Data Models

### 5.1 EFacturaDocument Model

```python
# apps/billing/efactura_models.py

class EFacturaDocument(models.Model):
    """
    Track e-Factura submission lifecycle for Romanian compliance.

    Follows ANAF API flow: generate → upload → poll status → download response
    """

    STATUS_CHOICES = (
        ('draft', 'Draft'),           # XML generated, not submitted
        ('queued', 'Queued'),         # In Django-Q queue
        ('submitted', 'Submitted'),   # Sent to ANAF, awaiting validation
        ('processing', 'Processing'), # ANAF is validating
        ('accepted', 'Accepted'),     # ANAF accepted (valid e-Factura)
        ('rejected', 'Rejected'),     # ANAF rejected (validation errors)
        ('error', 'Error'),           # System error (network, auth, etc.)
    )

    DOCUMENT_TYPE_CHOICES = (
        ('invoice', 'Invoice'),
        ('credit_note', 'Credit Note'),
        ('debit_note', 'Debit Note'),
    )

    # Core relationships
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    invoice = models.OneToOneField(
        'billing.Invoice',
        on_delete=models.CASCADE,
        related_name='efactura_document'
    )

    # Document metadata
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')

    # ANAF identifiers
    anaf_upload_index = models.CharField(max_length=100, blank=True)  # index_incarcare
    anaf_download_id = models.CharField(max_length=100, blank=True)   # id_descarcare
    anaf_response_id = models.CharField(max_length=100, blank=True)   # Response message ID

    # XML storage
    xml_content = models.TextField(blank=True)  # Generated UBL XML
    xml_file = models.FileField(upload_to='efactura/xml/', blank=True)
    xml_hash = models.CharField(max_length=64, blank=True)  # SHA-256 for integrity

    # Response storage
    anaf_response = models.JSONField(default=dict, blank=True)
    validation_errors = models.JSONField(default=list, blank=True)
    signed_pdf = models.FileField(upload_to='efactura/pdf/', blank=True)

    # Timestamps
    xml_generated_at = models.DateTimeField(null=True, blank=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    response_at = models.DateTimeField(null=True, blank=True)

    # Retry tracking
    retry_count = models.PositiveIntegerField(default=0)
    next_retry_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'efactura_document'
        verbose_name = 'e-Factura Document'
        indexes = [
            models.Index(
                fields=['status', 'submitted_at'],
                name='efactura_status_idx',
                condition=Q(status__in=['queued', 'submitted', 'processing'])
            ),
            models.Index(fields=['invoice']),
            models.Index(fields=['anaf_upload_index']),
        ]
```

### 5.2 EFacturaCredential Model (Credential Vault)

```python
# Use existing CredentialVault pattern from provisioning app

# Settings additions (apps/settings/models.py)
EFACTURA_SETTINGS = {
    'efactura_enabled': ('boolean', False, 'Enable e-Factura integration'),
    'efactura_environment': ('choice', 'test', 'API environment', ['test', 'production']),
    'efactura_company_cui': ('string', '', 'Company CUI for e-Factura'),
    'efactura_auto_submit': ('boolean', True, 'Auto-submit on invoice issue'),
    'efactura_b2c_enabled': ('boolean', True, 'Enable B2C e-Factura (2025)'),
    'efactura_retry_max_attempts': ('integer', 5, 'Max retry attempts'),
    'efactura_polling_interval_minutes': ('integer', 15, 'Status polling interval'),
}
```

### 5.3 Migration Plan

```python
# Migration: 0010_efactura_document.py

def create_efactura_document_from_existing(apps, schema_editor):
    """
    Create EFacturaDocument records for existing invoices
    that have efactura_sent=True
    """
    Invoice = apps.get_model('billing', 'Invoice')
    EFacturaDocument = apps.get_model('billing', 'EFacturaDocument')

    for invoice in Invoice.objects.filter(efactura_sent=True):
        EFacturaDocument.objects.create(
            invoice=invoice,
            document_type='invoice',
            status='accepted',  # Assume historical submissions succeeded
            anaf_upload_index=invoice.efactura_id,
            submitted_at=invoice.efactura_sent_date,
            response_at=invoice.efactura_sent_date,
            anaf_response=invoice.efactura_response,
        )
```

---

## 6. API Client Design

### 6.1 Client Structure

```python
# apps/billing/efactura/client.py

from dataclasses import dataclass
from typing import Optional
from enum import Enum
import httpx

class EFacturaEnvironment(Enum):
    TEST = "test"
    PRODUCTION = "prod"

@dataclass
class EFacturaConfig:
    """Configuration for e-Factura API client."""
    client_id: str
    client_secret: str
    company_cui: str
    environment: EFacturaEnvironment = EFacturaEnvironment.TEST
    timeout: int = 30

    @property
    def base_url(self) -> str:
        return f"https://api.anaf.ro/{self.environment.value}/FCTEL/rest"

    @property
    def oauth_authorize_url(self) -> str:
        return "https://logincert.anaf.ro/anaf-oauth2/v1/authorize"

    @property
    def oauth_token_url(self) -> str:
        return "https://logincert.anaf.ro/anaf-oauth2/v1/token"


class EFacturaClient:
    """
    Client for Romanian ANAF e-Factura API.

    Implements OAuth2 authentication and all e-Factura operations.
    """

    def __init__(self, config: EFacturaConfig):
        self.config = config
        self._access_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

    # --- Authentication ---

    def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        """Generate OAuth2 authorization URL for user consent."""
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': redirect_uri,
            'state': state,
            'token_content_type': 'jwt',
        }
        return f"{self.config.oauth_authorize_url}?{urlencode(params)}"

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> TokenResponse:
        """Exchange authorization code for access token."""
        ...

    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        """Refresh expired access token."""
        ...

    # --- Document Operations ---

    async def upload_invoice(
        self,
        xml_content: str,
        standard: str = "UBL",
        cif: str = None,
        extern: bool = False,
        autofactura: bool = False,
    ) -> UploadResponse:
        """
        Upload invoice XML to ANAF.

        Args:
            xml_content: UBL 2.1 XML document
            standard: Document type (UBL, CN for Credit Note, CII, RASP)
            cif: Company CUI (numeric, no 'RO' prefix)
            extern: True if buyer is non-Romanian
            autofactura: True if self-invoicing

        Returns:
            UploadResponse with index_incarcare for status tracking
        """
        params = {'standard': standard, 'cif': cif or self.config.company_cui}
        if extern:
            params['extern'] = 'DA'
        if autofactura:
            params['autofactura'] = 'DA'

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.config.base_url}/upload",
                params=params,
                content=xml_content.encode('utf-8'),
                headers={
                    'Authorization': f'Bearer {self._access_token}',
                    'Content-Type': 'application/xml',
                },
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return UploadResponse.from_response(response)

    async def get_upload_status(self, upload_index: str) -> StatusResponse:
        """
        Check status of uploaded document.

        Possible statuses:
        - 'in processing': Still being validated
        - 'ok': Accepted, id_descarcare available
        - 'nok': Rejected, errors available
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.config.base_url}/stareMesaj",
                params={'id_incarcare': upload_index},
                headers={'Authorization': f'Bearer {self._access_token}'},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return StatusResponse.from_response(response)

    async def download_response(self, download_id: str) -> bytes:
        """Download processed e-Factura response (signed PDF or error details)."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.config.base_url}/descarcare",
                params={'id': download_id},
                headers={'Authorization': f'Bearer {self._access_token}'},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.content

    async def list_messages(
        self,
        days: int = 60,
        cif: str = None,
        filter_type: str = None,
    ) -> list[MessageInfo]:
        """
        List available messages from ANAF.

        Args:
            days: Number of days to query (1-60)
            cif: Company CUI
            filter_type: 'E' for errors only, 'T' for all
        """
        params = {'zile': days, 'cif': cif or self.config.company_cui}
        if filter_type:
            params['filtru'] = filter_type

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.config.base_url}/listaMesaje",
                params=params,
                headers={'Authorization': f'Bearer {self._access_token}'},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return [MessageInfo.from_dict(m) for m in response.json().get('mesaje', [])]

    async def validate_xml(self, xml_content: str, standard: str = "UBL") -> ValidationResult:
        """Validate XML against ANAF schema (optional pre-upload check)."""
        ...

    async def convert_to_pdf(self, xml_content: str, standard: str = "UBL") -> bytes:
        """Convert XML to PDF visualization."""
        ...
```

### 6.2 Response Data Classes

```python
# apps/billing/efactura/responses.py

@dataclass
class UploadResponse:
    """Response from upload endpoint."""
    success: bool
    upload_index: str  # index_incarcare
    message: str
    errors: list[str]

    @classmethod
    def from_response(cls, response: httpx.Response) -> 'UploadResponse':
        data = response.json()
        return cls(
            success=response.status_code == 200,
            upload_index=data.get('index_incarcare', ''),
            message=data.get('message', ''),
            errors=data.get('errors', []),
        )

@dataclass
class StatusResponse:
    """Response from status check endpoint."""
    status: str  # 'in processing', 'ok', 'nok'
    download_id: Optional[str]  # id_descarcare (when status='ok')
    errors: list[ValidationError]

    @property
    def is_processing(self) -> bool:
        return self.status == 'in processing'

    @property
    def is_accepted(self) -> bool:
        return self.status == 'ok'

    @property
    def is_rejected(self) -> bool:
        return self.status == 'nok'

@dataclass
class ValidationError:
    """ANAF validation error."""
    code: str
    message: str
    field: Optional[str]
```

---

## 7. XML Generation (UBL 2.1)

### 7.1 XML Builder Service

```python
# apps/billing/efactura/xml_builder.py

from lxml import etree
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice

# UBL 2.1 Namespaces
NAMESPACES = {
    'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
    'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
    'ubl': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
}

# CIUS-RO Customization ID
CIUS_RO_CUSTOMIZATION = 'urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1'


class UBLInvoiceBuilder:
    """
    Build UBL 2.1 Invoice XML compliant with Romanian CIUS-RO.

    Reference: https://mfinante.gov.ro/web/efactura/informatii-tehnice
    """

    def __init__(self, invoice: 'Invoice'):
        self.invoice = invoice
        self.root = None

    def build(self) -> str:
        """Generate complete UBL 2.1 Invoice XML."""
        self._create_root()
        self._add_metadata()
        self._add_supplier_party()
        self._add_customer_party()
        self._add_payment_terms()
        self._add_tax_total()
        self._add_legal_monetary_total()
        self._add_invoice_lines()

        return etree.tostring(
            self.root,
            pretty_print=True,
            xml_declaration=True,
            encoding='UTF-8'
        ).decode('utf-8')

    def _create_root(self):
        """Create Invoice root element with namespaces."""
        self.root = etree.Element(
            '{urn:oasis:names:specification:ubl:schema:xsd:Invoice-2}Invoice',
            nsmap={
                None: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
                'cac': NAMESPACES['cac'],
                'cbc': NAMESPACES['cbc'],
            }
        )

    def _add_metadata(self):
        """Add invoice metadata (ID, issue date, currency, etc.)."""
        # CustomizationID (CIUS-RO)
        etree.SubElement(
            self.root,
            '{%s}CustomizationID' % NAMESPACES['cbc']
        ).text = CIUS_RO_CUSTOMIZATION

        # ProfileID
        etree.SubElement(
            self.root,
            '{%s}ProfileID' % NAMESPACES['cbc']
        ).text = 'urn:fdc:peppol.eu:2017:poacc:billing:01:1.0'

        # Invoice ID (sequential number)
        etree.SubElement(
            self.root,
            '{%s}ID' % NAMESPACES['cbc']
        ).text = self.invoice.number

        # Issue Date
        etree.SubElement(
            self.root,
            '{%s}IssueDate' % NAMESPACES['cbc']
        ).text = self.invoice.issued_at.strftime('%Y-%m-%d')

        # Due Date
        if self.invoice.due_at:
            etree.SubElement(
                self.root,
                '{%s}DueDate' % NAMESPACES['cbc']
            ).text = self.invoice.due_at.strftime('%Y-%m-%d')

        # Invoice Type Code (380 = Commercial Invoice)
        etree.SubElement(
            self.root,
            '{%s}InvoiceTypeCode' % NAMESPACES['cbc']
        ).text = '380'

        # Document Currency Code
        etree.SubElement(
            self.root,
            '{%s}DocumentCurrencyCode' % NAMESPACES['cbc']
        ).text = self.invoice.currency.code

    def _add_supplier_party(self):
        """Add supplier (seller) information."""
        supplier = etree.SubElement(
            self.root,
            '{%s}AccountingSupplierParty' % NAMESPACES['cac']
        )
        party = etree.SubElement(supplier, '{%s}Party' % NAMESPACES['cac'])

        # Get company info from settings
        from apps.settings.services import SettingsService
        company_name = SettingsService.get('company_name', 'PragmaticHost SRL')
        company_cui = SettingsService.get('efactura_company_cui', '')
        company_reg_number = SettingsService.get('company_registration_number', '')

        # PartyIdentification (CUI)
        party_id = etree.SubElement(party, '{%s}PartyIdentification' % NAMESPACES['cac'])
        id_elem = etree.SubElement(party_id, '{%s}ID' % NAMESPACES['cbc'])
        id_elem.text = company_cui
        id_elem.set('schemeID', 'RO:CUI')

        # PartyName
        party_name = etree.SubElement(party, '{%s}PartyName' % NAMESPACES['cac'])
        etree.SubElement(
            party_name,
            '{%s}Name' % NAMESPACES['cbc']
        ).text = company_name

        # PostalAddress
        self._add_postal_address(party, is_supplier=True)

        # PartyTaxScheme (VAT)
        self._add_party_tax_scheme(party, f'RO{company_cui}')

        # PartyLegalEntity
        legal = etree.SubElement(party, '{%s}PartyLegalEntity' % NAMESPACES['cac'])
        etree.SubElement(
            legal,
            '{%s}RegistrationName' % NAMESPACES['cbc']
        ).text = company_name
        etree.SubElement(
            legal,
            '{%s}CompanyID' % NAMESPACES['cbc']
        ).text = company_reg_number

    def _add_customer_party(self):
        """Add customer (buyer) information."""
        customer = etree.SubElement(
            self.root,
            '{%s}AccountingCustomerParty' % NAMESPACES['cac']
        )
        party = etree.SubElement(customer, '{%s}Party' % NAMESPACES['cac'])

        # PartyIdentification
        if self.invoice.bill_to_tax_id:
            party_id = etree.SubElement(party, '{%s}PartyIdentification' % NAMESPACES['cac'])
            id_elem = etree.SubElement(party_id, '{%s}ID' % NAMESPACES['cbc'])

            # Handle Romanian CUI format
            tax_id = self.invoice.bill_to_tax_id
            if tax_id.startswith('RO'):
                id_elem.text = tax_id[2:]  # Remove RO prefix
                id_elem.set('schemeID', 'RO:CUI')
            else:
                id_elem.text = tax_id

        # PartyName
        party_name = etree.SubElement(party, '{%s}PartyName' % NAMESPACES['cac'])
        etree.SubElement(
            party_name,
            '{%s}Name' % NAMESPACES['cbc']
        ).text = self.invoice.bill_to_name

        # PostalAddress
        self._add_customer_address(party)

        # PartyTaxScheme
        if self.invoice.bill_to_tax_id:
            self._add_party_tax_scheme(party, self.invoice.bill_to_tax_id)

        # PartyLegalEntity
        legal = etree.SubElement(party, '{%s}PartyLegalEntity' % NAMESPACES['cac'])
        etree.SubElement(
            legal,
            '{%s}RegistrationName' % NAMESPACES['cbc']
        ).text = self.invoice.bill_to_name

    def _add_invoice_lines(self):
        """Add invoice line items."""
        for idx, line in enumerate(self.invoice.lines.all(), 1):
            inv_line = etree.SubElement(
                self.root,
                '{%s}InvoiceLine' % NAMESPACES['cac']
            )

            # Line ID
            etree.SubElement(
                inv_line,
                '{%s}ID' % NAMESPACES['cbc']
            ).text = str(idx)

            # Invoiced Quantity
            quantity = etree.SubElement(
                inv_line,
                '{%s}InvoicedQuantity' % NAMESPACES['cbc']
            )
            quantity.text = str(line.quantity)
            quantity.set('unitCode', 'C62')  # Unit code for "one"

            # Line Extension Amount (subtotal without tax)
            line_ext = etree.SubElement(
                inv_line,
                '{%s}LineExtensionAmount' % NAMESPACES['cbc']
            )
            line_ext.text = str(line.unit_price * line.quantity)
            line_ext.set('currencyID', self.invoice.currency.code)

            # Item
            item = etree.SubElement(inv_line, '{%s}Item' % NAMESPACES['cac'])
            etree.SubElement(
                item,
                '{%s}Description' % NAMESPACES['cbc']
            ).text = line.description
            etree.SubElement(
                item,
                '{%s}Name' % NAMESPACES['cbc']
            ).text = line.description[:100]  # Truncate for name field

            # ClassifiedTaxCategory
            tax_cat = etree.SubElement(item, '{%s}ClassifiedTaxCategory' % NAMESPACES['cac'])
            etree.SubElement(
                tax_cat,
                '{%s}ID' % NAMESPACES['cbc']
            ).text = 'S'  # Standard rate
            etree.SubElement(
                tax_cat,
                '{%s}Percent' % NAMESPACES['cbc']
            ).text = str(float(line.tax_rate) * 100)

            tax_scheme = etree.SubElement(tax_cat, '{%s}TaxScheme' % NAMESPACES['cac'])
            etree.SubElement(
                tax_scheme,
                '{%s}ID' % NAMESPACES['cbc']
            ).text = 'VAT'

            # Price
            price = etree.SubElement(inv_line, '{%s}Price' % NAMESPACES['cac'])
            price_amount = etree.SubElement(
                price,
                '{%s}PriceAmount' % NAMESPACES['cbc']
            )
            price_amount.text = str(line.unit_price)
            price_amount.set('currencyID', self.invoice.currency.code)

    # ... additional helper methods ...


class UBLCreditNoteBuilder(UBLInvoiceBuilder):
    """Build UBL 2.1 Credit Note XML for refunds."""

    def _create_root(self):
        """Create CreditNote root element."""
        self.root = etree.Element(
            '{urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2}CreditNote',
            nsmap={
                None: 'urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2',
                'cac': NAMESPACES['cac'],
                'cbc': NAMESPACES['cbc'],
            }
        )

    def _add_metadata(self):
        """Add credit note metadata with reference to original invoice."""
        super()._add_metadata()

        # CreditNoteTypeCode
        etree.SubElement(
            self.root,
            '{%s}CreditNoteTypeCode' % NAMESPACES['cbc']
        ).text = '381'  # Credit note related to goods or services

        # BillingReference (link to original invoice)
        if hasattr(self.invoice, 'original_invoice') and self.invoice.original_invoice:
            billing_ref = etree.SubElement(
                self.root,
                '{%s}BillingReference' % NAMESPACES['cac']
            )
            invoice_ref = etree.SubElement(
                billing_ref,
                '{%s}InvoiceDocumentReference' % NAMESPACES['cac']
            )
            etree.SubElement(
                invoice_ref,
                '{%s}ID' % NAMESPACES['cbc']
            ).text = self.invoice.original_invoice.number
```

### 7.2 CIUS-RO Validation

```python
# apps/billing/efactura/validator.py

from lxml import etree
import importlib.resources

class CIUSROValidator:
    """
    Validate UBL 2.1 XML against Romanian CIUS-RO schematron rules.

    Downloads validation artifacts from:
    https://mfinante.gov.ro/web/efactura/informatii-tehnice
    """

    SCHEMATRON_VERSION = '1.0.9'

    def __init__(self):
        self._load_schematron()

    def _load_schematron(self):
        """Load CIUS-RO schematron rules."""
        # Load from bundled resources or download from ANAF
        self.schematron = None  # Initialize schematron validator

    def validate(self, xml_content: str) -> ValidationResult:
        """
        Validate XML against CIUS-RO rules.

        Returns:
            ValidationResult with is_valid flag and list of errors
        """
        try:
            doc = etree.fromstring(xml_content.encode('utf-8'))

            errors = []

            # 1. XSD Schema validation
            xsd_errors = self._validate_xsd(doc)
            errors.extend(xsd_errors)

            # 2. Schematron business rules
            if not xsd_errors:
                schematron_errors = self._validate_schematron(doc)
                errors.extend(schematron_errors)

            return ValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
            )
        except etree.XMLSyntaxError as e:
            return ValidationResult(
                is_valid=False,
                errors=[ValidationError(code='XML_SYNTAX', message=str(e))],
            )

    def _validate_xsd(self, doc: etree._Element) -> list[ValidationError]:
        """Validate against UBL 2.1 XSD schema."""
        ...

    def _validate_schematron(self, doc: etree._Element) -> list[ValidationError]:
        """Validate against CIUS-RO schematron rules."""
        ...
```

---

## 8. Audit & Compliance Integration

### 8.1 Audit Events

All e-Factura operations must be logged using the existing audit infrastructure:

```python
# apps/billing/efactura/audit.py

from apps.audit.services import (
    AuditService,
    BillingAuditService,
    ComplianceEventRequest,
    BusinessEventData,
    AuditContext,
)

class EFacturaAuditService:
    """Audit logging for e-Factura operations."""

    @staticmethod
    def log_xml_generated(invoice: Invoice, efactura_doc: EFacturaDocument):
        """Log XML generation event."""
        event_data = BusinessEventData(
            event_type='invoice_xml_generated',
            business_object=invoice,
            user=None,
            context=AuditContext(actor_type='system'),
            description=f"e-Factura XML generated for invoice {invoice.number}",
            metadata={
                'efactura_document_id': str(efactura_doc.id),
                'xml_hash': efactura_doc.xml_hash,
                'document_type': efactura_doc.document_type,
            }
        )
        BillingAuditService.log_invoice_event(event_data)

    @staticmethod
    def log_submission(invoice: Invoice, efactura_doc: EFacturaDocument, response: UploadResponse):
        """Log submission to ANAF."""
        compliance_request = ComplianceEventRequest(
            compliance_type='efactura_submission',
            reference_id=invoice.number,
            description=f"e-Factura submitted to ANAF: {invoice.number}",
            status='success' if response.success else 'failed',
            evidence={
                'upload_index': response.upload_index,
                'invoice_total': float(invoice.total),
                'customer_cui': invoice.bill_to_tax_id,
                'submission_timestamp': timezone.now().isoformat(),
            }
        )
        AuditService.log_compliance_event(compliance_request)

        # Also log as audit event
        event_data = BusinessEventData(
            event_type='efactura_submitted',
            business_object=invoice,
            user=None,
            context=AuditContext(actor_type='system'),
            description=f"e-Factura submitted: {invoice.number} → ANAF",
            metadata={
                'upload_index': response.upload_index,
                'environment': 'production' if 'prod' in str(efactura_doc.config.base_url) else 'test',
            }
        )
        BillingAuditService.log_invoice_event(event_data)

    @staticmethod
    def log_accepted(invoice: Invoice, efactura_doc: EFacturaDocument):
        """Log ANAF acceptance."""
        compliance_request = ComplianceEventRequest(
            compliance_type='efactura_submission',
            reference_id=invoice.number,
            description=f"e-Factura accepted by ANAF: {invoice.number}",
            status='success',
            evidence={
                'upload_index': efactura_doc.anaf_upload_index,
                'download_id': efactura_doc.anaf_download_id,
                'acceptance_timestamp': timezone.now().isoformat(),
            }
        )
        AuditService.log_compliance_event(compliance_request)

        event_data = BusinessEventData(
            event_type='efactura_accepted',
            business_object=invoice,
            user=None,
            context=AuditContext(actor_type='system'),
            description=f"e-Factura accepted: {invoice.number}",
        )
        BillingAuditService.log_invoice_event(event_data)

    @staticmethod
    def log_rejected(invoice: Invoice, efactura_doc: EFacturaDocument, errors: list):
        """Log ANAF rejection with error details."""
        compliance_request = ComplianceEventRequest(
            compliance_type='efactura_submission',
            reference_id=invoice.number,
            description=f"e-Factura rejected by ANAF: {invoice.number}",
            status='validation_failed',
            evidence={
                'upload_index': efactura_doc.anaf_upload_index,
                'errors': [{'code': e.code, 'message': e.message} for e in errors],
                'rejection_timestamp': timezone.now().isoformat(),
            }
        )
        AuditService.log_compliance_event(compliance_request)

        event_data = BusinessEventData(
            event_type='efactura_rejected',
            business_object=invoice,
            user=None,
            context=AuditContext(actor_type='system', severity='high'),
            description=f"e-Factura rejected: {invoice.number} - {len(errors)} errors",
            metadata={'errors': [e.message for e in errors]},
        )
        BillingAuditService.log_invoice_event(event_data)

        # Create audit alert for rejection
        from apps.audit.models import AuditAlert
        AuditAlert.objects.create(
            alert_type='compliance_violation',
            severity='high',
            title=f"e-Factura Rejected: {invoice.number}",
            description=f"ANAF rejected invoice {invoice.number}. Errors: {errors}",
            status='open',
        )
```

### 8.2 ComplianceLog Integration

```python
# Usage in e-Factura service

from apps.audit.models import ComplianceLog

def record_efactura_submission(invoice: Invoice, efactura_doc: EFacturaDocument):
    """Record e-Factura submission in ComplianceLog for regulatory reporting."""
    ComplianceLog.objects.create(
        compliance_type='efactura_submission',
        reference_id=invoice.number,
        status='submitted',
        description=f"Invoice {invoice.number} submitted to ANAF e-Factura",
        evidence={
            'invoice_id': str(invoice.id),
            'customer_cui': invoice.bill_to_tax_id,
            'total_amount': float(invoice.total),
            'currency': invoice.currency.code,
            'upload_index': efactura_doc.anaf_upload_index,
            'submission_deadline': (invoice.issued_at + timedelta(days=5)).isoformat(),
        }
    )
```

### 8.3 Integration with WebhookEvent

```python
# For tracking ANAF API responses as webhook events

from apps.integrations.models import WebhookEvent

def record_anaf_response(efactura_doc: EFacturaDocument, response_data: dict):
    """Record ANAF API response as webhook event for deduplication."""
    WebhookEvent.objects.create(
        source='efactura',
        event_id=efactura_doc.anaf_upload_index,
        event_type=f"efactura.{efactura_doc.status}",
        status='processed',
        payload=response_data,
        processed_at=timezone.now(),
    )
```

---

## 9. Error Handling & Retry Logic

### 9.1 Error Categories

| Category | Examples | Retry Strategy |
|----------|----------|----------------|
| **Authentication** | Token expired, invalid credentials | Refresh token, retry once |
| **Network** | Timeout, connection refused | Exponential backoff, max 5 retries |
| **Validation** | Invalid XML, missing fields | No retry, fix data |
| **Rate Limit** | Too many requests | Wait and retry with backoff |
| **Server Error** | ANAF 5xx errors | Exponential backoff, max 3 retries |

### 9.2 Retry Service

```python
# apps/billing/efactura/retry_service.py

class EFacturaRetryService:
    """Handle retry logic for e-Factura submissions."""

    RETRY_DELAYS = [300, 900, 3600, 7200, 21600]  # 5m, 15m, 1h, 2h, 6h
    MAX_RETRIES = 5

    @classmethod
    def should_retry(cls, efactura_doc: EFacturaDocument, error: Exception) -> bool:
        """Determine if submission should be retried."""
        if efactura_doc.retry_count >= cls.MAX_RETRIES:
            return False

        # Don't retry validation errors
        if isinstance(error, ValidationError):
            return False

        # Retry network and server errors
        if isinstance(error, (NetworkError, ServerError, AuthenticationError)):
            return True

        return False

    @classmethod
    def schedule_retry(cls, efactura_doc: EFacturaDocument, error: str):
        """Schedule next retry with exponential backoff."""
        delay_index = min(efactura_doc.retry_count, len(cls.RETRY_DELAYS) - 1)
        base_delay = cls.RETRY_DELAYS[delay_index]

        # Add jitter (80%-120%)
        import random
        jitter = random.uniform(0.8, 1.2)
        delay = int(base_delay * jitter)

        efactura_doc.retry_count += 1
        efactura_doc.next_retry_at = timezone.now() + timedelta(seconds=delay)
        efactura_doc.last_error = error
        efactura_doc.status = 'queued'
        efactura_doc.save()

        # Queue retry task
        from django_q.tasks import async_task
        async_task(
            'apps.billing.efactura.tasks.retry_submission',
            str(efactura_doc.id),
            schedule=efactura_doc.next_retry_at,
        )
```

### 9.3 Alert System

```python
# apps/billing/efactura/alerts.py

class EFacturaAlertService:
    """Generate alerts for e-Factura issues."""

    @staticmethod
    def alert_submission_failure(efactura_doc: EFacturaDocument):
        """Alert on repeated submission failures."""
        if efactura_doc.retry_count >= 3:
            from apps.notifications.services import EmailService

            EmailService.send_template_email(
                template_key='efactura_submission_failure',
                recipient='billing@pragmatichost.com',
                context={
                    'invoice': efactura_doc.invoice,
                    'error': efactura_doc.last_error,
                    'retry_count': efactura_doc.retry_count,
                },
                priority='high',
            )

    @staticmethod
    def alert_deadline_approaching(invoice: Invoice):
        """Alert when 5-day submission deadline is approaching."""
        if invoice.issued_at:
            deadline = invoice.issued_at + timedelta(days=5)
            days_remaining = (deadline - timezone.now()).days

            if days_remaining <= 1 and not invoice.efactura_sent:
                from apps.audit.models import AuditAlert
                AuditAlert.objects.create(
                    alert_type='compliance_violation',
                    severity='critical',
                    title=f"e-Factura Deadline: {invoice.number}",
                    description=f"Invoice {invoice.number} must be submitted within {days_remaining} days",
                    status='open',
                )
```

---

## 10. Testing Strategy

### 10.1 Unit Tests

```python
# tests/billing/efactura/test_xml_builder.py

class TestUBLInvoiceBuilder(TestCase):
    """Test UBL 2.1 XML generation."""

    def test_generates_valid_xml_structure(self):
        invoice = InvoiceFactory.create(
            bill_to_country='RO',
            bill_to_tax_id='RO12345678',
        )
        builder = UBLInvoiceBuilder(invoice)
        xml = builder.build()

        # Parse and validate structure
        doc = etree.fromstring(xml.encode())
        assert doc.tag.endswith('Invoice')
        assert doc.find('.//{*}CustomizationID').text == CIUS_RO_CUSTOMIZATION

    def test_includes_all_required_fields(self):
        """Verify all mandatory CIUS-RO fields are present."""
        ...

    def test_handles_special_characters(self):
        """Test Romanian characters (ă, î, ș, ț) are properly encoded."""
        ...

    def test_credit_note_references_original_invoice(self):
        """Test credit note includes BillingReference."""
        ...
```

### 10.2 Integration Tests (ANAF Sandbox)

```python
# tests/billing/efactura/test_anaf_integration.py

@pytest.mark.integration
class TestANAFIntegration(TestCase):
    """Integration tests against ANAF test environment."""

    @pytest.fixture
    def anaf_client(self):
        config = EFacturaConfig(
            client_id=settings.EFACTURA_CLIENT_ID,
            client_secret=settings.EFACTURA_CLIENT_SECRET,
            company_cui=settings.EFACTURA_COMPANY_CUI,
            environment=EFacturaEnvironment.TEST,
        )
        return EFacturaClient(config)

    async def test_upload_and_status_check(self, anaf_client):
        """Test full upload → status → download flow."""
        invoice = InvoiceFactory.create()
        xml = UBLInvoiceBuilder(invoice).build()

        # Upload
        upload_response = await anaf_client.upload_invoice(xml)
        assert upload_response.success
        assert upload_response.upload_index

        # Wait for processing
        await asyncio.sleep(5)

        # Check status
        status = await anaf_client.get_upload_status(upload_response.upload_index)
        assert status.status in ['in processing', 'ok', 'nok']
```

### 10.3 E2E Tests

```python
# tests/e2e/test_efactura_workflow.py

class TestEFacturaWorkflow(StaticLiveServerTestCase):
    """End-to-end tests for e-Factura workflow."""

    def test_invoice_issued_triggers_efactura_submission(self):
        """Test that issuing invoice automatically submits to e-Factura."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            bill_to_country='RO',
            bill_to_tax_id='RO12345678',
            status='draft',
        )

        # Issue invoice
        invoice.status = 'issued'
        invoice.save()

        # Verify e-Factura document created
        assert EFacturaDocument.objects.filter(invoice=invoice).exists()
        efactura_doc = invoice.efactura_document
        assert efactura_doc.status in ['queued', 'submitted']
```

---

## 11. Security Considerations

### 11.1 Credential Management

```python
# Use CredentialVault for storing ANAF credentials

from apps.common.credential_vault import get_credential_vault

def get_efactura_credentials() -> dict:
    """Retrieve e-Factura credentials from secure vault."""
    vault = get_credential_vault()
    return {
        'client_id': vault.get_credential('efactura_client_id'),
        'client_secret': vault.get_credential('efactura_client_secret'),
        'certificate_path': vault.get_credential('efactura_certificate_path'),
    }
```

### 11.2 XML Security

- Validate all XML against schema before submission
- Sanitize customer input to prevent XML injection
- Use secure XML parser (defusedxml or lxml with secure settings)
- Hash XML content for integrity verification

### 11.3 Token Management

- Store access tokens encrypted
- Implement token refresh before expiry
- Never log tokens or credentials
- Use short-lived tokens where possible

---

## 12. Deployment & Rollout

### 12.1 Deployment Checklist

- [ ] ANAF developer account registered
- [ ] Digital certificate installed and registered with SPV
- [ ] Client ID and secret obtained from ANAF
- [ ] Test environment validated
- [ ] Credential vault configured
- [ ] Settings configured in admin
- [ ] Django-Q2 worker running
- [ ] Scheduled tasks configured (status polling)
- [ ] Monitoring and alerting configured
- [ ] Rollback plan documented

### 12.2 Rollout Strategy

1. **Phase 1**: Deploy to staging with test ANAF environment
2. **Phase 2**: Manual submission for select invoices
3. **Phase 3**: Automatic submission for new B2B invoices
4. **Phase 4**: Enable B2C submission (January 2025)
5. **Phase 5**: Full automatic submission for all eligible invoices

### 12.3 Monitoring

```python
# Prometheus metrics for e-Factura

EFACTURA_SUBMISSIONS = Counter(
    'efactura_submissions_total',
    'Total e-Factura submissions',
    ['status', 'document_type']
)

EFACTURA_PROCESSING_TIME = Histogram(
    'efactura_processing_seconds',
    'Time from submission to acceptance',
)

EFACTURA_ERRORS = Counter(
    'efactura_errors_total',
    'e-Factura errors by type',
    ['error_type']
)
```

---

## Appendix A: ANAF Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| BR-07 | Buyer CIF not identified | Set `extern=DA` for foreign buyers |
| BR-RO-100 | Invalid seller CUI | Verify company CUI in settings |
| BR-RO-160 | Missing mandatory field | Check XML completeness |
| BR-RO-200 | Invalid VAT calculation | Verify tax amounts |

---

## Appendix B: Environment Variables

```bash
# .env additions

# e-Factura API Configuration
EFACTURA_CLIENT_ID=your-client-id
EFACTURA_CLIENT_SECRET=your-client-secret
EFACTURA_COMPANY_CUI=12345678
EFACTURA_ENVIRONMENT=test  # or 'production'
EFACTURA_CERTIFICATE_PATH=/path/to/certificate.p12
EFACTURA_CERTIFICATE_PASSWORD=certificate-password

# Feature flags
EFACTURA_ENABLED=true
EFACTURA_AUTO_SUBMIT=true
EFACTURA_B2C_ENABLED=true
```

---

## Appendix C: References

### Official Documentation

- [ANAF e-Factura Technical Info](https://mfinante.gov.ro/en/web/efactura/informatii-tehnice)
- [ANAF OAuth2 Registration](https://static.anaf.ro/static/10/Anaf/Informatii_R/API/Oauth_procedura_inregistrare_aplicatii_portal_ANAF.pdf)
- [CIUS-RO Specification](https://mfinante.gov.ro/web/efactura/informatii-tehnice) (Validation artifacts v1.0.9)
- [UBL 2.1 XSD Schema](https://docs.oasis-open.org/ubl/os-UBL-2.1/xsd/maindoc/UBL-Invoice-2.1.xsd)

### Third-Party Resources

- [TypeScript SDK](https://github.com/florin-szilagyi/efactura-anaf-ts-sdk)
- [PHP ANAF Client](https://github.com/andalisolutions/anaf-php)
- [Django E-Factura Project](https://github.com/letconex/DjangoE-factura)

### Legal References

- Emergency Ordinance No. 138/2024 (B2C/Simplified invoices)
- Emergency Ordinance No. 69/2024 (B2C extension)
- Romanian Fiscal Code - Invoice requirements

---

**Document Version**: 1.0
**Last Updated**: December 2024
**Author**: PRAHO Development Team
