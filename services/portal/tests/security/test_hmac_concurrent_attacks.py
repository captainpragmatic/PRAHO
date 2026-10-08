"""
🔐 HMAC Concurrent Attack Scenario Tests

Comprehensive tests for concurrent attack scenarios against HMAC authentication:
- Concurrent brute force attacks
- Nonce exhaustion attacks
- Race condition exploitation
- Cache poisoning attempts
- Resource exhaustion attacks
- Distributed attack simulation

These tests ensure HMAC authentication remains secure under concurrent
load and sophisticated coordinated attacks.
"""

import base64
import concurrent.futures
import contextlib
import hashlib
import hmac
import threading
import time
import urllib.parse
from typing import Any
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings
from django.utils.encoding import escape_uri_path

from apps.api_client.services import PlatformAPIClient, PlatformAPIError


class HMACConcurrentAttackTestCase(SimpleTestCase):
    """🔐 Concurrent attack scenario testing for HMAC authentication"""

    def setUp(self):
        """Set up concurrent attack test environment"""
        self.test_secret = "concurrent-attack-test-secret-key"
        self.portal_id = "concurrent-attack-portal"

        # Note: No cache operations needed for SimpleTestCase

        # Thread-safe result collection
        self.attack_results = []
        self.result_lock = threading.Lock()

    def _record_result(self, result: dict[str, Any]) -> None:
        """Thread-safe result recording"""
        with self.result_lock:
            self.attack_results.append(result)

    def _is_genuine(self, request: dict[str, Any]) -> bool:
        """Verify a request the way Platform's middleware does (newline-joined canonical)."""
        headers = request.get('headers', {})
        body = request.get('data') or b''
        if isinstance(body, str):
            body = body.encode()
        parsed = urllib.parse.urlsplit(request.get('url', ''))
        body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode('ascii')
        canonical = "\n".join(
            [
                request.get('method', ''),
                escape_uri_path(urllib.parse.unquote(parsed.path)),
                'application/json',
                body_hash,
                headers.get('X-Portal-Id', ''),
                headers.get('X-Nonce', ''),
                headers.get('X-Timestamp', ''),
            ]
        )
        expected = hmac.new(self.test_secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        return headers.get('X-Body-Hash') == body_hash and hmac.compare_digest(headers.get('X-Signature', ''), expected)

    def test_concurrent_brute_force_signature_attack(self):
        """🔐 Forged signatures are all refused under concurrency; genuine ones still pass.

        The fake Platform verifies the same newline-joined canonical the real middleware checks
        (method, path, content type, body hash, portal id, nonce, timestamp). Attackers sign real
        requests with the real client and corrupt one hex digit of the result; a control worker
        does not. Exact counts on both sides keep the test from passing vacuously: a fake that
        accepted everything, or rejected everything, fails it.
        """
        counts_lock = threading.Lock()
        counts = {'requests': 0, 'accepted': 0, 'rejected': 0}

        def verifying_platform(*args, **kwargs):
            genuine = self._is_genuine(kwargs)
            with counts_lock:
                counts['requests'] += 1
                counts['accepted' if genuine else 'rejected'] += 1
            mock_response = Mock()
            if genuine:
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'user': {'id': 7, 'customer_id': 3}}
            else:
                mock_response.status_code = 401
                mock_response.json.return_value = {'error': 'HMAC authentication failed'}
            return mock_response

        def worker(worker_id: int, corrupt_at: int | None) -> dict[str, int]:
            client = PlatformAPIClient()
            sign = client._generate_hmac_headers

            def forged(*args: Any, **kwargs: Any) -> dict[str, str]:
                headers = sign(*args, **kwargs)
                if corrupt_at is not None:
                    signature = headers['X-Signature']
                    flipped = format(int(signature[corrupt_at], 16) ^ 0x1, 'x')
                    headers['X-Signature'] = signature[:corrupt_at] + flipped + signature[corrupt_at + 1:]
                return headers

            outcome = {'authenticated': 0, 'refused': 0}
            with patch.object(client, '_generate_hmac_headers', side_effect=forged):
                for _i in range(10):
                    try:
                        result = client.authenticate_customer(f'attacker{worker_id}@example.com', 'password123')
                    except PlatformAPIError as error:
                        # Platform's signature refusal is an outage to the Portal, never a login.
                        self.assertTrue(error.is_unavailable)
                        outcome['refused'] += 1
                    else:
                        self.assertIsNotNone(result)
                        outcome['authenticated'] += 1
            return outcome

        attackers = {0: 0, 1: 17, 2: 31, 3: 48, 4: 63}  # worker -> hex position corrupted
        with (
            override_settings(
                PLATFORM_API_SECRET=self.test_secret,
                PORTAL_ID=self.portal_id,
                PLATFORM_API_BASE_URL="http://localhost:8000/api",
            ),
            patch('apps.common.outbound_http._session.request', new=verifying_platform),
            concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor,
        ):
            attack = [executor.submit(worker, i, position) for i, position in attackers.items()]
            control = executor.submit(worker, 99, None)
            attack_results = [future.result() for future in attack]
            control_result = control.result()

        self.assertEqual(sum(r['authenticated'] for r in attack_results), 0)
        self.assertEqual(sum(r['refused'] for r in attack_results), 50)
        self.assertEqual(control_result, {'authenticated': 10, 'refused': 0})
        self.assertEqual(counts, {'requests': 60, 'accepted': 10, 'rejected': 50})

    def test_nonce_exhaustion_attack(self):
        """🔐 Test resistance to nonce exhaustion attacks"""
        # Shared, lock-protected nonce tracking across ALL workers — a cross-worker uniqueness
        # check (stricter than the old per-worker sets). Global-state managers entered once.
        nonce_lock = threading.Lock()
        used_nonces: set[str] = set()
        nonce_state = {'unique': 0, 'collisions': 0}

        def mock_nonce_tracking(*args, **kwargs):
            headers = kwargs.get('headers', {})
            nonce = headers.get('X-Nonce', '')
            with nonce_lock:
                if nonce in used_nonces:
                    nonce_state['collisions'] += 1
                    collided = True
                else:
                    used_nonces.add(nonce)
                    nonce_state['unique'] += 1
                    collided = False

            mock_response = Mock()
            if collided:
                mock_response.status_code = 401
                mock_response.json.return_value = {'error': 'Nonce already used'}
            else:
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'authenticated': True}
            return mock_response

        def nonce_exhaustion_worker(worker_id: int) -> dict[str, Any]:
            client = PlatformAPIClient()
            for _i in range(50):
                with contextlib.suppress(PlatformAPIError):
                    client.authenticate_customer(f'nonce_attacker{worker_id}@example.com', 'password123')
            return {'worker_id': worker_id}

        with (
            override_settings(
                PLATFORM_API_SECRET=self.test_secret,
                PORTAL_ID=self.portal_id,
            ),
            patch('apps.common.outbound_http._session.request', new=mock_nonce_tracking),
            concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor,
        ):
            futures = [executor.submit(nonce_exhaustion_worker, i) for i in range(8)]
            for future in concurrent.futures.as_completed(futures):
                future.result()  # propagate any worker exception

        total_nonces = nonce_state['unique']
        total_cache_hits = nonce_state['collisions']

        # Load floor: 8 workers x 50 iterations = 400 nonce-bearing requests must actually reach
        # the mock. Without this, a broken patch (0 observed requests) yields collision_rate=0 and
        # the test would pass while exercising nothing.
        observed = total_nonces + total_cache_hits
        self.assertGreaterEqual(observed, 360, f"nonce path barely exercised: only {observed}/400 requests reached the mock")

        # With cryptographically secure nonces, collisions should be extremely rare
        collision_rate = total_cache_hits / (total_nonces + total_cache_hits) if (total_nonces + total_cache_hits) > 0 else 0

        self.assertLess(collision_rate, 0.01,
                       f"Nonce collision rate too high: {collision_rate:.3%} "
                       f"(Total nonces: {total_nonces}, Collisions: {total_cache_hits})")

    def test_distributed_coordinated_attack_simulation(self):
        """🔐 Test resistance to distributed coordinated attacks"""
        # Shared, lock-protected request counter drives the rate-limit simulation. Its
        # threshold (20) is well BELOW the asserted load floor (total_attempts > 100), so a
        # 429 reliably fires — decoupled from the old `len(self.attack_results) > 100` that
        # shared the magic 100 with the load assertion and was itself latently flaky. The
        # global-state managers are entered once around the whole concurrent section.
        load_lock = threading.Lock()
        load_state = {'requests': 0}

        def mock_coordinated_defense(*args, **kwargs):
            """Mock Platform with coordinated attack defense (rate-limits under load)."""
            with load_lock:
                load_state['requests'] += 1
                request_rate = load_state['requests']

            mock_response = Mock()
            if request_rate > 20:  # Load detected — rate limit (well below the asserted load)
                mock_response.status_code = 429
                mock_response.json.return_value = {
                    'error': 'Rate limited - coordinated attack detected',
                    'retry_after': 60,
                }
            else:
                # Normal validation (still fails — invalid credentials)
                mock_response.status_code = 401
                mock_response.json.return_value = {'error': 'HMAC authentication failed'}
            return mock_response

        def coordinated_attack_worker(worker_id: int, coordination_data: dict[str, Any]) -> dict[str, Any]:
            """Worker simulating part of coordinated attack (own client; global patch active)."""
            attack_start_time = coordination_data['start_time']
            attack_duration = coordination_data['duration']
            worker_attack_type = coordination_data['attack_types'][worker_id % len(coordination_data['attack_types'])]

            # Wait for coordinated start
            while time.time() < attack_start_time:
                time.sleep(0.01)

            attack_results = {
                'worker_id': worker_id,
                'attack_type': worker_attack_type,
                'attempts': 0,
                'successes': 0,
                'rate_limited_responses': 0,
            }
            client = PlatformAPIClient()
            end_time = attack_start_time + attack_duration

            while time.time() < end_time:
                attack_results['attempts'] += 1
                try:
                    result = client.authenticate_customer(
                        f'coordinated_attacker{worker_id}@example.com', 'password123'
                    )
                    if result:
                        attack_results['successes'] += 1
                except PlatformAPIError as exc:
                    if exc.is_rate_limited:
                        attack_results['rate_limited_responses'] += 1

                # Brief pause to avoid overwhelming the test environment
                time.sleep(0.01)

            return attack_results

        coordination_data = {
            'start_time': time.time() + 1,  # Start in 1 second
            'duration': 5,  # 5 second attack
            'attack_types': ['brute_force', 'nonce_flood', 'timestamp_manipulation', 'portal_spoofing'],
        }

        num_workers = 20
        with (
            override_settings(
                PLATFORM_API_SECRET=self.test_secret,
                PORTAL_ID=self.portal_id,
            ),
            patch('apps.common.outbound_http._session.request', new=mock_coordinated_defense),
            concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor,
        ):
            futures = [
                executor.submit(coordinated_attack_worker, i, coordination_data)
                for i in range(num_workers)
            ]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        # Analysis
        total_attempts = sum(r['attempts'] for r in results)
        total_successes = sum(r['successes'] for r in results)
        total_rate_limited = sum(r['rate_limited_responses'] for r in results)

        # Coordinated attack should be largely unsuccessful
        success_rate = total_successes / total_attempts if total_attempts > 0 else 0
        self.assertLess(success_rate, 0.01,
                       f"Coordinated attack success rate too high: {success_rate:.3%}")

        # Rate limiting should have been triggered
        self.assertGreater(total_rate_limited, 0,
                          "Rate limiting should have been triggered during coordinated attack")

        # System should maintain reasonable performance under attack
        self.assertGreater(total_attempts, 100,
                          "Attack should have generated significant load for testing")
