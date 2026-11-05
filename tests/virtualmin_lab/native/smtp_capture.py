#!/usr/bin/env python3
"""Owned foreground loopback SMTP acceptance for an explicit private native VM run."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "services/platform"))

from apps.infrastructure.native_lab import native_authority  # noqa: E402 -- Explicit repository CLI bootstrap.
from apps.infrastructure.native_smtp import NativeSMTPCapture, verify_email_logs  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "verify"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--smtp-manifest", type=Path, required=True)
    parser.add_argument("--lifetime-seconds", type=int, default=3600)
    parser.add_argument("--email-log-id", action="append", default=[])
    args = parser.parse_args()
    try:
        authority = native_authority(args.manifest.absolute())
        if args.action == "serve":
            if args.email_log_id:
                raise ValueError("EmailLog IDs belong to the verify action")
            stop = threading.Event()

            def shutdown(_signum: int, _frame: object) -> None:
                stop.set()

            signal.signal(signal.SIGINT, shutdown)
            signal.signal(signal.SIGTERM, shutdown)
            with NativeSMTPCapture(authority, args.smtp_manifest, lifetime_seconds=args.lifetime_seconds) as capture:
                print("Owned loopback SMTP capture ready; acceptance does not prove inbox delivery.", flush=True)
                while capture.current() and not stop.wait(0.5):
                    pass
            print("Owned SMTP capture closed; private acceptance evidence retained.", flush=True)
        else:
            if not args.email_log_id:
                raise ValueError("Verify requires explicit stored EmailLog IDs from the actual public operation")
            if os.environ.get("DJANGO_SETTINGS_MODULE", "config.settings.native") != "config.settings.native":
                raise ValueError("Verification requires the isolated native settings and database")
            if os.environ.get("NATIVE_VM_MANIFEST", str(authority.path)) != str(authority.path):
                raise ValueError("Verification must use this exact native VM authority")
            os.environ["NATIVE_VM_MANIFEST"] = str(authority.path)
            os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings.native"
            # This action only reads evidence: an already-closed sink must not prevent inspection.
            os.environ.pop("PRAHO_NATIVE_SMTP_MANIFEST", None)
            import django  # noqa: PLC0415 -- Serve is deliberately independent of Django and any database.

            django.setup()
            print(json.dumps(verify_email_logs(authority, args.smtp_manifest, args.email_log_id), sort_keys=True))
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, "Native SMTP acceptance refused: " + str(error) + "\n")


if __name__ == "__main__":
    main()
