# Recorded fixtures

## ANAF PlatitorTvaRest v9

Recorded 2026-10-15 from the official endpoint, `POST https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva`,
unedited apart from indentation. The data is ANAF's public register of companies.

- `anaf_v9_found.json`: request `[{"cui": 14399840, "data": "2026-10-15"}, {"cui": 99999992, "data": "2026-10-15"}]`.
  HTTP 200; one company found, one CUI (valid check digit, not registered) in `notFound`.
- `anaf_v9_not_found.json`: request `[{"cui": 99999992, "data": "2026-10-15"}]`.
  HTTP **404** with the same JSON shape: ANAF answers a request in which nothing was found with 404,
  so a 404 carrying this body is an answer, not an outage.
