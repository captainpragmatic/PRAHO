# Pinned ANAF D390 v3 inputs

Downloaded from the [official ANAF D390 catalogue](https://static.anaf.ro/static/10/Anaf/Declaratii_R/390.html) on 2026-09-12. The original files are retained byte for byte.

The local Git attributes disable text conversion for the XSD. Its exact path is excluded from whitespace/EOF hooks to preserve the published CRLF and trailing whitespace; runtime checksum validation detects any change.

| File | Published version | Source | SHA-256 |
| --- | --- | --- | --- |
| `d390_12022021.xsd` | schema 1.02, catalogue updated 2021-02-12 | [ANAF XSD](https://static.anaf.ro/static/10/Anaf/Declaratii_R/AplicatiiDec/d390_12022021.xsd) | `7f95c80866051edec98fb71bed7b2de6957583f35a69fdd8a4ce4f6973487090` |
| `structura_D390_2020_300424.pdf` | annex dated 2024-04-30, catalogue updated 2024-05-07 | [ANAF validation annex](https://static.anaf.ro/static/10/Anaf/Declaratii_R/AplicatiiDec/structura_D390_2020_300424.pdf) | `83ff54cee3c1a636e29a9a8556a92d06ef515f9f2424c36eb20c8d17d3f5ffec` |

`billing.d390.compatibility_schema()` checks both hashes, parses the original XSD without network access, and changes exactly one attribute in memory: the `cos` element receives `minOccurs="0"`. The annex specifies 0–n stock-transfer sections, while the XSD omits `minOccurs` and thereby requires one. No other schema restriction is changed and no stock-transfer row is fabricated.

The local validator also checks service/initial scope, required names, allowed characters, VAT checksums, unique partners, nonzero positive bases, numeric limits, the reporting-period range, summary amounts and the control sum. The annex permits negative bases for initial declarations; this narrower feature rejects them because fiscal adjustments are deferred. `nr_pag=1` represents one logical XML annex; the export does not generate or certify ANAF's physical PDF pagination.

**Services-only draft for accountant review.** Passing this compatibility schema and the implemented annex rules is local validation. It is not validation by ANAF's assistance software, proof of VAT registration, acceptance of a filing, or confirmation of the operator's obligations. The accountant must review/import the draft using ANAF's current assistance workflow.

To update a pin, retain provenance, compare the full schema/annex changes, review the single compatibility adjustment, update the checksums and extend the XML regression tests. Runtime exports never download these files.
