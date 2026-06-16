# ANAF e-Factura response fixtures — provenance

These fixtures back the contract-fixture tests for the e-Factura client (#123). They let us
verify request construction and response parsing WITHOUT live ANAF credentials. A finding is
"contract-fixture verified" here; it is only "live verified" once the sandbox smoke test passes.

| File | Endpoint | Bytes | Source |
|------|----------|-------|--------|
| `anaf_upload_ok.xml` | `/upload`, `/uploadb2c` success | **SYNTHESIZED** | Hand-authored from the documented `respUploadFisier` schema: root `<header>` with `ExecutionStatus="0"` + `index_incarcare`. |
| `anaf_upload_error.xml` | `/upload` validation error | **SYNTHESIZED** | Hand-authored: `<header ExecutionStatus="1">` with a `<Errors errorMessage="..."/>` child (typical CIF-mismatch message). |

Documented format references (as of 2026-06):
- ANAF OAuth + API procedure: https://static.anaf.ro/static/10/Anaf/Informatii_R/API/Oauth_procedura_inregistrare_aplicatii_portal_ANAF.pdf
- MF e-Factura technical info: https://mfinante.gov.ro/web/efactura/informatii-tehnice

**SYNTHESIZED** = hand-authored from the published schema/spec, NOT captured from a live call.
Replace with EXACT captured bytes once a sandbox account exists; the live smoke test is the final arbiter.
