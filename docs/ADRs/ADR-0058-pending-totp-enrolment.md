# ADR-0058: A TOTP Secret Waiting for Its First Code Lives in Its Own Row

- Status: Accepted
- Date: 2026-10-13
- Authors: PRAHO maintainers
- Related: #689, ADR-0040 (row-bound encrypted fields), ADR-0055 (portal sessions)

## Context

Setting up an authenticator shows a secret, then waits for a code from the app to prove it was scanned. Until #689 the two setup paths kept that secret in different places.
- **Staff web setup kept it in the session.** The session row lives in the database for as long as the session does, so an abandoned setup left a plaintext secret there until logout or expiry.
- **The API the Portal calls wrote it onto the user row**, in the column that holds the enabled secret, and made a new one on every call. Each Portal error path showed the setup page again, which called setup again, so one mistyped code replaced the secret the customer had just scanned. The app could then never be verified.
- **New recovery codes also waited in the session** (`new_backup_codes`, and the Portal's `new_mfa_backup_codes`) until the next page showed them.

## Decision

A secret shown but not yet confirmed lives in `PendingTOTPEnrolment` (`apps/users/pending_totp.py`), one row per person. Both setup paths use it.
- **Encrypted and bound to its row.** AES-256-GCM with the row's table, column and id as associated data, as ADR-0040 binds other fields. Ciphertext copied to another row does not decrypt.
- **Offered again while fresh.** `get_or_create_pending` returns the same secret until it is confirmed or expires, and each showing extends its life (`users.totp_enrolment_ttl_minutes`, default 15). Someone who scans and is slow to type is never handed a different secret. Starting over is explicit (`restart`).
- **Confirmed in one transaction.** `complete_enrolment` locks the user row, then the pending row; checks expiry, the current password and the code on the locked rows; enables 2FA with that secret; and deletes the row. A wrong password and a wrong code get one answer and leave the row in place. An expired row has its own answer.
- **Discarded by credential changes.** A password reset or change, disabling 2FA, an administrator's reset and anonymisation drop it, so a secret shown before them cannot be confirmed after.
- **Lock order is the user row, then this row**, everywhere, so two first visits create one row and an enrolment never races its own restart.
- **Recovery codes are shown once, in the response that made them,** with `Cache-Control: no-store`, and stored nowhere. Refreshing that page does not show them again.
- **Not audited per showing.** The row is listed in `scripts/audit_model_allowlist.txt`; confirming it logs `2fa_enabled`. An audit row per page view would record nothing useful.

## Consequences

- The user row holds a TOTP secret only once 2FA is enabled.
- No session holds a TOTP secret or recovery codes.
- The Portal shows its setup page again after a wrong code with the same QR code, by calling setup again; nothing is kept on the Portal side.
- A person who closes the page with their codes unsaved has to regenerate them. The page tells them to save the codes before leaving.
