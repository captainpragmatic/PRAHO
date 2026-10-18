# ADR-0057: Media Lives on the Filesystem, or in a Private Bucket on Container Platforms

- Status: Accepted
- Date: 2026-10-12
- Amended: 2026-10-18 (media is never served directly, on any storage)
- Authors: PRAHO maintainers
- Related: ADR-0040 (row-bound encrypted fields), ADR-0054 (supported deployment paths)

## Context

Media is what the database cannot rebuild: issued invoice PDFs, ANAF's e-Factura XML and response archives, ticket attachments and GDPR exports.
- **Every stack but one has a media directory.** Native installs use `/opt/praho/media`; the Docker single-server and platform-only stacks mount the `media_files` volume into both the platform and the task worker. Backups archive it next to each dump.
- **The container-service stack has none.** The platform and task-worker containers share no volume, and a container's disk is lost when the container is replaced. A PDF the worker generates is invisible to the platform, and everything is gone at the next deploy.
- **Media code already goes through Django's storage API**, except the staff ticket-attachment download, which opened `attachment.file.path` directly.

## Decision

Media storage is chosen by `MEDIA_STORAGE` in production and staging settings (`config/settings/storage.py`).
- **`filesystem` (the default, also when unset)** keeps today's behaviour on every stack.
- **`s3`** stores media in an S3-compatible bucket through django-storages, under the `media/` prefix:
  - **Private.** Block Public Access and bucket-owner-enforced ownership. PRAHO sends no object ACLs (`default_acl=None`), because such buckets reject them.
  - **Read through Django only.** No template or view links to media. A URL the storage could mint is signed and expires in 300 s; `custom_domain` stays unset, since it would produce unsigned URLs.
  - **Never overwritten.** `file_overwrite=False`: a clashing name gets a suffix, so an archived document is never replaced in place.
  - **Its own credentials** (`MEDIA_S3_*`), not the SES key. The endpoint must be `https://`; `MEDIA_S3_SERVER_SIDE_ENCRYPTION` optionally requests `AES256` or `aws:kms` (the account's AWS-managed `aws/s3` key; no customer-managed key id is sent).
  - **Fails closed.** A missing bucket or key, an unknown choice or a plain-HTTP endpoint is `ImproperlyConfigured` at startup, never a silent fallback to the container's disk.
- **No local paths.** Media code reads and writes through the storage (`FieldFile.open()`, `default_storage`). A test scans `apps/` for `.path` on media fields, `storage.path(` and `settings.MEDIA_ROOT`; another runs the ticket download and the GDPR export lifecycle on a storage whose `path()` raises, the S3 contract.

### Backups and erasure

With `s3`, the bucket's versioning and a lifecycle rule that expires noncurrent versions are the media backup; the backup scripts' media archive is then empty. Deleting a file (GDPR erasure, export cleanup) removes the current version only, so the noncurrent-version expiry also bounds how long a deleted file survives. It plays the role the dump retention plays for the database.

The orphaned-media sweep (`apps/common/media_sweep.py`) deletes ticket attachments and GDPR exports that no row names, a day after they were written. Like any delete, on `s3` it removes the current version only, so sweeping alone does not prove a file, or anything encrypted under a retired key, is gone until the noncurrent versions expire. A restore pauses the sweep for seven days, because files written since the backup have no row.

### Why not the alternatives

| Option | Why not |
|---|---|
| A shared network volume (NFS, EFS) on the container platform | Not offered by every provider, and it reintroduces the volume the container-service topology avoids. |
| Public bucket or public-read objects, served by a CDN | Media holds invoices and personal data; nothing about it is public. |
| Signed URLs handed to browsers | Moves authorization out of Django into a URL anyone holding it can use for its lifetime. Reads stay inside the views that check access. |
| `s3` as the default | Every current deployment has a filesystem it backs up; a bucket is an opt-in for the one stack that lacks it. |

## Consequences

- The container-service stack can keep media across deploys and between its containers.
- Other stacks are unchanged, except that media is no longer served directly on any of them (see the amendment below).
- `django-storages[s3]` joins the platform dependency group. The portal stores no media and doesn't get it.
- Reading a file now costs a bucket round trip on `s3`. Downloads are staff- or customer-initiated and small, so this is acceptable without caching.

## Amendment (2026-10-18): media is never served directly

The filesystem stacks used to keep a staff-network `/media/` route in Caddy, which served any stored file with a day-long public cache, no access check and no record. Stored names could be guessed (attachments kept the uploader's filename, invoice PDFs are named by their sequential number), so anyone on the staff network could read them.

- **No route serves media**, on any storage. Every Caddyfile variant has lost its `/media/` handler, and the compose stacks no longer mount the media volume into Caddy. Production Django has no media URL either (`static()` adds one only under `DEBUG`).
- **Every read goes through a Django view** that checks who is asking, answers `private, no-store`, and records ticket-attachment and e-Factura file downloads in the audit log. The e-Factura XML and ANAF archive are checked against their recorded SHA-256 before they are served.
- **New attachments get random stored names** (`tickets/attachments/ticket_<time>_<random>.<ext>`); the name they were uploaded with is kept only for display. Rows stored before keep their names and stay readable.
- A staff request at the edge is capped at 62 MiB, derived from the upper bounds of what one staff reply may carry: 5 files of at most 10 MiB, the non-file fields up to Django's `DATA_UPLOAD_MAX_MEMORY_SIZE` (10 MiB), and 2 MiB of multipart headroom. Caddy cannot read settings, so a test derives the same total from them. Django enforces the values in effect.
