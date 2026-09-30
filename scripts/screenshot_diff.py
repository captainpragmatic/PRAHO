#!/usr/bin/env python3
"""A visual-regression control for template fixes, built per the systematic-debugging discipline:
prove the harness reports ZERO on an unchanged page, and reports NON-ZERO on a page it knows was
changed, before trusting it to judge a real template fix.

Usage:
    python scripts/screenshot_diff.py control --url http://localhost:8701/services/1/
    python scripts/screenshot_diff.py positive-control --url http://localhost:8701/services/1/
    python scripts/screenshot_diff.py capture --url ... --out before.png
    python scripts/screenshot_diff.py diff --before before.png --after after.png [--out diff.png]

Auth: logs in once via the portal login form using the first E2E fixture customer
(logs/e2e-fixtures.json, seeded by `make dev-e2e-bg`) and asserts the post-login redirect
actually lands on /dashboard/ - a failed login that silently redirects back to the login page
would otherwise screenshot the login form twice and report a false-clean zero diff.

RESTART THE STACK between a BEFORE and an AFTER capture. `engines['django'].engine.
template_loaders` under config.settings.e2e shows Django installs `cached.Loader` even with
DEBUG=True when no explicit OPTIONS.loaders is set, so a compiled template stays cached in
memory for the life of the runserver process - editing the .html file has no effect until a
fresh process recompiles it. `make stop-e2e && VENV_DIR=.venv-darwin make dev-e2e-bg` between
captures; two captures of the same unchanged page within one process (the `control` command)
will not catch this, since neither one ever needed the cache to be busted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "logs" / "e2e-fixtures.json"
DEFAULT_OUT_DIR = ROOT / "output" / "screenshot-diff"
PORTAL_BASE_URL = "http://localhost:8701"
VIEWPORT = {"width": 1280, "height": 900}
LOGIN_PASSWORD = "test123"  # noqa: S105 - e2e fixture credential, seeded by make dev-e2e-bg, not a secret


def _customer_email() -> str:
    data = json.loads(FIXTURES.read_text())
    return str(data["customers"][0]["email"])


def _login_and_get_context(playwright_browser):
    context = playwright_browser.new_context(viewport=VIEWPORT, reduced_motion="reduce")
    page = context.new_page()
    page.goto(f"{PORTAL_BASE_URL}/login/", timeout=10000)
    page.fill('input[name="email"]', _customer_email())
    page.fill('input[name="password"]', LOGIN_PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle", timeout=10000)
    landed = urlparse(page.url).path
    if landed != "/dashboard/":
        page.close()
        context.close()
        raise RuntimeError(
            f"login did not reach /dashboard/ - landed on {landed!r} instead. "
            "A capture taken from here would screenshot the login page, not the target page, "
            "and two such captures would wrongly report a zero diff."
        )
    return context


def _navigate_and_validate(page: Page, url: str) -> None:
    """Shared by every capture path: the response must be a real 2xx for THIS url, and the
    final URL must still be the one requested. Either check alone is not enough - a 500 error
    page can still "land" on the requested path, and a redirect to a 200 page is not an error."""
    response = page.goto(url, timeout=15000)
    page.wait_for_load_state("networkidle", timeout=10000)
    if response is None or not response.ok:
        status = response.status if response is not None else "no response"
        raise RuntimeError(f"navigating to {url!r} returned status {status} - not a valid page to screenshot.")
    landed = urlparse(page.url).path
    target_path = urlparse(url).path
    if landed != target_path:
        raise RuntimeError(
            f"navigating to {target_path!r} ended on {landed!r} instead - likely a redirect "
            "(permission denied, missing object) rather than the intended page."
        )


def capture(url: str, out: Path, mask_selectors: list[str]) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = _login_and_get_context(browser)
            page = context.new_page()
            _navigate_and_validate(page, url)
            mask = [page.locator(sel) for sel in mask_selectors] if mask_selectors else None
            page.screenshot(path=str(out), full_page=True, mask=mask)
        finally:
            browser.close()
    print(f"captured {out}")


def capture_with_mutation(url: str, out: Path, mask_selectors: list[str]) -> None:
    """Like `capture`, but paints a visible marker before the screenshot - the positive control
    that proves the harness can see a real change, not just fail to see a missing one.

    A style-only mutation (outline + background), not a text change: swapping textContent on a
    landmark element can reflow the page (a longer string wraps, height changes), which the
    first version of this script tripped on - the mutated capture came back a different
    document height, size mismatch, and a real detection got reported as -1 differing pixels."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = _login_and_get_context(browser)
            page = context.new_page()
            _navigate_and_validate(page, url)
            page.evaluate(
                """() => {
                    const el = document.body;
                    el.style.outline = '12px solid magenta';
                    el.style.outlineOffset = '-12px';
                }"""
            )
            mask = [page.locator(sel) for sel in mask_selectors] if mask_selectors else None
            page.screenshot(path=str(out), full_page=True, mask=mask)
        finally:
            browser.close()
    print(f"captured (mutated) {out}")


def _slug(url: str) -> str:
    """`/company/addresses/add/` -> `company_addresses_add-<hash>.png`. The path alone is not
    unique - `/billing/invoices/?page=1` and `?page=2` both reduce to the same path, and
    `/a/b/` collides with the literal segment `/a_b/` once `/` and `_` both become `_`. The
    hash covers the full URL (path + query), so any real distinction between two URLs survives
    even though the human-readable prefix does not."""
    path = urlparse(url).path.strip("/")
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", path) or "root"
    digest = hashlib.sha256(url.encode()).hexdigest()[:8]
    return f"{safe}-{digest}.png"


def capture_many(urls: list[str], out_dir: Path, mask_selectors: list[str]) -> dict[str, Path]:
    """Log in once, capture every URL, return {url: png_path}. One login per batch, not one per
    URL - 32 files times their pages would otherwise mean a login per capture.

    Removes any pre-existing file at the target path before attempting the capture: a URL that
    fails this run (redirect, non-2xx) must not leave behind a PNG from some earlier, different
    run at the same out_dir - batch_diff() has no way to tell a stale success from a fresh one."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Path] = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = _login_and_get_context(browser)
            for url in urls:
                out = out_dir / _slug(url)
                out.unlink(missing_ok=True)
                page = context.new_page()
                try:
                    _navigate_and_validate(page, url)
                except RuntimeError as exc:
                    page.close()
                    print(f"⚠️  SKIPPED {url}: {exc}")
                    continue
                mask = [page.locator(sel) for sel in mask_selectors] if mask_selectors else None
                page.screenshot(path=str(out), full_page=True, mask=mask)
                page.close()
                results[url] = out
                print(f"captured {url} -> {out}")
        finally:
            browser.close()
    return results


def batch_diff(before_dir: Path, after_dir: Path, out_dir: Path | None) -> tuple[dict[str, int | None], set[str]]:
    """Diff every PNG in before_dir against its same-named counterpart in after_dir. Returns
    ({filename: differing_pixels_or_None}, {filenames missing a counterpart in either
    direction}). A file present in only one directory is reported, not silently ignored - a
    missing AFTER capture is a broken run, not a zero diff, and the caller must be able to
    fail on it rather than just print a warning nobody's exit code reflects."""
    results: dict[str, int | None] = {}
    missing: set[str] = set()
    before_files = sorted(before_dir.glob("*.png"))
    before_names = {p.name for p in before_files}
    for before_path in before_files:
        after_path = after_dir / before_path.name
        if not after_path.exists():
            print(f"⚠️  {before_path.name}: no matching AFTER capture at {after_path}")
            missing.add(before_path.name)
            continue
        out = (out_dir / f"diff_{before_path.name}") if out_dir else None
        differing = diff(before_path, after_path, out)
        results[before_path.name] = differing
    after_only = {p.name for p in after_dir.glob("*.png")} - before_names
    for name in sorted(after_only):
        print(f"⚠️  {name}: no matching BEFORE capture")
        missing.add(name)
    return results, missing


def diff(before: Path, after: Path, out: Path | None) -> int | None:
    """Returns the count of differing pixels, or None if the two images cannot be compared
    pixel-for-pixel (different dimensions). None is a distinct signal from 0, never coerced to a
    number - a page whose height itself changed is a real difference, not the absence of one, and
    printing it as "-1 differing pixels" previously buried that distinction in a fake count."""
    from PIL import Image, ImageChops

    img_before = Image.open(before).convert("RGB")
    img_after = Image.open(after).convert("RGB")
    if img_before.size != img_after.size:
        print(f"SIZE MISMATCH: {img_before.size} vs {img_after.size} — cannot compare pixel-for-pixel")
        return None

    delta = ImageChops.difference(img_before, img_after)
    bbox = delta.getbbox()
    if bbox is None:
        differing = 0
    else:
        # Count pixels with ANY channel difference, not just the bounding box area. tobytes(), not
        # getdata() - the latter is deprecated for removal in Pillow 14 (2027-10-15).
        raw = delta.tobytes()
        differing = sum(1 for i in range(0, len(raw), 3) if raw[i : i + 3] != b"\x00\x00\x00")

    if out and bbox is not None:
        delta.save(out)

    return differing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    control = sub.add_parser("control", help="Screenshot the same page twice; diff must be zero.")
    control.add_argument("--url", required=True)
    control.add_argument("--mask", action="append", default=[], help="CSS selector to mask (repeatable)")
    control.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)

    positive = sub.add_parser(
        "positive-control",
        help="Screenshot the page, then again with one element's text mutated; diff must be NON-zero.",
    )
    positive.add_argument("--url", required=True)
    positive.add_argument("--mask", action="append", default=[], help="CSS selector to mask (repeatable)")
    positive.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)

    cap = sub.add_parser("capture", help="Screenshot one page to a file.")
    cap.add_argument("--url", required=True)
    cap.add_argument("--out", required=True, type=Path)
    cap.add_argument("--mask", action="append", default=[], help="CSS selector to mask (repeatable)")

    d = sub.add_parser("diff", help="Compare two screenshots.")
    d.add_argument("--before", required=True, type=Path)
    d.add_argument("--after", required=True, type=Path)
    d.add_argument("--out", type=Path, help="Write the visual diff image here if non-zero.")

    bcap = sub.add_parser("batch-capture", help="Log in once, capture every URL in a directory.")
    bcap.add_argument("--url", action="append", default=[], dest="urls", help="Repeatable.")
    bcap.add_argument("--urls-file", type=Path, help="One URL per line, blank lines and # comments skipped.")
    bcap.add_argument("--out-dir", type=Path, required=True)
    bcap.add_argument("--mask", action="append", default=[], help="CSS selector to mask (repeatable)")

    bdiff = sub.add_parser("batch-diff", help="Diff every same-named PNG across two directories.")
    bdiff.add_argument("--before-dir", type=Path, required=True)
    bdiff.add_argument("--after-dir", type=Path, required=True)
    bdiff.add_argument("--out-dir", type=Path, help="Write per-file visual diffs here.")

    args = parser.parse_args()

    if args.command == "control":
        args.out_dir.mkdir(parents=True, exist_ok=True)
        cap_a = args.out_dir / "_control_a.png"
        cap_b = args.out_dir / "_control_b.png"
        capture(args.url, cap_a, args.mask)
        capture(args.url, cap_b, args.mask)
        differing = diff(cap_a, cap_b, args.out_dir / "_control_diff.png")
        if differing is None:
            print("❌ CONTROL FAILED: the page's own dimensions differ between two captures of the")
            print("   same commit - something dynamic (a banner, a growing list) is changing layout.")
            return 1
        print(f"differing pixels: {differing}")
        if differing != 0:
            print("❌ CONTROL FAILED: the harness cannot distinguish 'unchanged' from 'changed' yet.")
            print(f"   See {args.out_dir / '_control_diff.png'} for what varied.")
            return 1
        print("✅ CONTROL PASSED: two captures of the same page, same commit, are pixel-identical.")
        return 0

    if args.command == "positive-control":
        args.out_dir.mkdir(parents=True, exist_ok=True)
        cap_a = args.out_dir / "_positive_a.png"
        cap_b = args.out_dir / "_positive_b.png"
        capture(args.url, cap_a, args.mask)
        capture_with_mutation(args.url, cap_b, args.mask)
        differing = diff(cap_a, cap_b, args.out_dir / "_positive_diff.png")
        if differing == 0:
            print("❌ POSITIVE CONTROL FAILED: a known, deliberate content change produced a zero diff.")
            print("   The mask list is hiding real content, or the capture is not landing on the target page.")
            return 1
        if differing is None:
            print("✅ POSITIVE CONTROL PASSED: the deliberate change altered the page's own dimensions.")
            return 0
        print(f"✅ POSITIVE CONTROL PASSED: a deliberate change was detected ({differing} differing pixels).")
        return 0

    if args.command == "batch-capture":
        urls = list(args.urls)
        if args.urls_file:
            for line in args.urls_file.read_text().splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    urls.append(stripped)
        if not urls:
            print("❌ no URLs given (use --url, repeatable, or --urls-file)")
            return 1
        results = capture_many(urls, args.out_dir, args.mask)
        print(f"\n{len(results)}/{len(urls)} captured into {args.out_dir}")
        return 0 if len(results) == len(urls) else 1

    if args.command == "batch-diff":
        if not args.before_dir.is_dir():
            print(f"❌ before-dir does not exist: {args.before_dir}")
            return 1
        if not args.after_dir.is_dir():
            print(f"❌ after-dir does not exist: {args.after_dir}")
            return 1
        if args.out_dir:
            args.out_dir.mkdir(parents=True, exist_ok=True)
        results, missing = batch_diff(args.before_dir, args.after_dir, args.out_dir)
        if not results and not missing:
            print(f"❌ nothing to compare: no PNGs found in {args.before_dir} or {args.after_dir}")
            return 1
        changed = {name: count for name, count in results.items() if count != 0}
        for name, count in sorted(results.items()):
            marker = "≡" if count == 0 else "≠"
            print(f"  {marker} {name}: {count if count is not None else 'SIZE MISMATCH'}")
        for name in sorted(missing):
            print(f"  ⚠️  {name}: missing counterpart")
        print(f"\n{len(results)} compared, {len(changed)} changed, {len(missing)} missing a counterpart.")
        return 0 if not changed and not missing else 1

    if args.command == "capture":
        capture(args.url, args.out, args.mask)
        return 0

    if args.command == "diff":
        differing = diff(args.before, args.after, args.out)
        if differing is None:
            return 1
        print(f"differing pixels: {differing}")
        return 0 if differing == 0 else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
