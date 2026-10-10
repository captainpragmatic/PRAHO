"""One customer waiting on Platform does not make every other customer wait (ADR-0056).

Real gunicorn, the shipped gunicorn.conf.py and production settings, against a stub Platform whose
logins are held open. Run with ``make test-portal-server``; the default portal run deselects them.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor

import pytest
import requests

from tests.server.harness import Portal, StubPlatform, running_portal

pytestmark = pytest.mark.server

# A probe that is not stuck behind a held login answers well inside this.
FAST_SECONDS = 2.0
# What the login page says once the stub releases a held login: Platform's answer reached the view.
REJECTED = "Invalid email address or password"


@pytest.fixture
def platform() -> Iterator[StubPlatform]:
    with StubPlatform() as stub:
        yield stub


def _hold_logins(
    portal: Portal, platform: StubPlatform, pool: ThreadPoolExecutor, count: int
) -> list[Future[requests.Response]]:
    # Each login comes from its own address, so the per-address login limit never answers early.
    held = [pool.submit(portal.login, f"198.51.100.{index + 1}") for index in range(count)]
    platform.wait_for_held(count)
    return held


def _assert_still_held(held: list[Future[requests.Response]]) -> None:
    # A login that already finished (a timeout freed its thread) would make the probes prove nothing.
    assert not any(login.done() for login in held), [login.result() for login in held if login.done()]


def _assert_rejected(login: Future[requests.Response]) -> None:
    response = login.result(timeout=30)
    assert response.status_code == 200
    assert REJECTED in response.text, response.text[:500]


def _probe(portal: Portal) -> float:
    started = time.monotonic()
    response = requests.get(f"{portal.base_url}/status/", timeout=FAST_SECONDS * 5)
    assert response.status_code == 200, response.text
    return time.monotonic() - started


def test_a_threaded_worker_serves_others_while_logins_wait(platform: StubPlatform) -> None:
    with running_portal(
        platform.url, PORTAL_GUNICORN_WORKER_CLASS="gthread", PORTAL_GUNICORN_WORKERS="1", PORTAL_GUNICORN_THREADS="4"
    ) as portal:
        assert "Using worker: gthread" in portal.log_text()
        with ThreadPoolExecutor(max_workers=3) as pool:
            held = _hold_logins(portal, platform, pool, 3)
            assert _probe(portal) < FAST_SECONDS
            _assert_still_held(held)
            platform.release.set()
            for login in held:
                _assert_rejected(login)


def test_a_full_worker_leaves_new_requests_to_its_sibling(platform: StubPlatform) -> None:
    # Seven of eight threads held: every probe must find the one free thread, wherever it is. With
    # gunicorn's default worker_connections a full worker would keep accepting and queue them.
    with (
        running_portal(
            platform.url,
            PORTAL_GUNICORN_WORKER_CLASS="gthread",
            PORTAL_GUNICORN_WORKERS="2",
            PORTAL_GUNICORN_THREADS="4",
        ) as portal,
        ThreadPoolExecutor(max_workers=7) as pool,
    ):
        held = _hold_logins(portal, platform, pool, 7)
        slow = [seconds for seconds in (_probe(portal) for _ in range(10)) if seconds >= FAST_SECONDS]
        assert slow == [], slow
        _assert_still_held(held)
        platform.release.set()
        for login in held:
            _assert_rejected(login)


def test_a_sync_worker_makes_everyone_wait(platform: StubPlatform) -> None:
    # The rollback setting really is one request at a time: this is what threads fix.
    with running_portal(
        platform.url, PORTAL_GUNICORN_WORKER_CLASS="sync", PORTAL_GUNICORN_WORKERS="1", PORTAL_GUNICORN_THREADS="4"
    ) as portal:
        assert "Using worker: sync" in portal.log_text()
        with ThreadPoolExecutor(max_workers=2) as pool:
            held = _hold_logins(portal, platform, pool, 1)
            probe = pool.submit(_probe, portal)
            time.sleep(FAST_SECONDS)
            assert not probe.done()
            _assert_still_held(held)
            platform.release.set()
            _assert_rejected(held[0])
            assert probe.result(timeout=30) >= FAST_SECONDS


def test_held_requests_finish_and_each_connection_closes(platform: StubPlatform) -> None:
    with running_portal(
        platform.url, PORTAL_GUNICORN_WORKER_CLASS="gthread", PORTAL_GUNICORN_WORKERS="2", PORTAL_GUNICORN_THREADS="4"
    ) as portal:
        with ThreadPoolExecutor(max_workers=4) as pool:
            held = _hold_logins(portal, platform, pool, 4)
            platform.release.set()
            for login in held:
                response = login.result(timeout=30)
                assert response.status_code == 200
                assert response.headers.get("Connection", "").lower() == "close"
        assert _probe(portal) < FAST_SECONDS
