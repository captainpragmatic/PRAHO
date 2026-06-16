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

import concurrent.futures
import contextlib
import hashlib
import hmac
import threading
import time
from typing import Any
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

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

    def test_concurrent_brute_force_signature_attack(self):
        """🔐 Test resistance to concurrent brute force signature attacks"""
        # Shared, lock-protected attempt counter. The global-state context managers
        # (override_settings + the _session.request patch) are entered ONCE around the whole
        # concurrent section below — never per-thread — so no worker's teardown can strip
        # another worker's patch/settings mid-flight (that was the flake). Per-client
        # _generate_hmac_headers patching stays inside the worker (instance-scoped, safe).
        attempts_lock = threading.Lock()
        attempts_state = {'count': 0}

        def mock_brute_force_validation(*args, **kwargs):
            with attempts_lock:
                attempts_state['count'] += 1

            headers = kwargs.get('headers', {})
            signature = headers.get('X-Signature', '')

            # Only the correct-secret signature is accepted; all corrupted ones fail (401).
            method = kwargs.get('method', 'POST')
            url = kwargs.get('url', '')
            path = url.replace('http://localhost:8000', '') if url else '/api/test/'
            body = kwargs.get('data', b'{}')
            if isinstance(body, str):
                body = body.encode()

            portal_id = headers.get('X-Portal-Id', '')
            nonce = headers.get('X-Nonce', '')
            timestamp = headers.get('X-Timestamp', '')
            canonical = f"{method}|{path}|{body.decode()}|{portal_id}|{nonce}|{timestamp}"
            expected_signature = hmac.new(
                self.test_secret.encode(), canonical.encode(), hashlib.sha256
            ).hexdigest()

            mock_response = Mock()
            if signature == expected_signature:
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'authenticated': True}
            else:
                # Always 401: this test asserts nothing about rate limiting, and a 429 on
                # /users/login/ would raise PlatformAPIError through the (unguarded) worker.
                mock_response.status_code = 401
                mock_response.json.return_value = {'error': 'HMAC authentication failed'}
            return mock_response

        def brute_force_worker(worker_id: int, signature_prefix: str) -> dict[str, Any]:
            """Worker thread for brute force attack (own client; global patch already active)."""
            client = PlatformAPIClient()
            successful_auths = 0
            for _i in range(10):
                # Per-client header patch (instance-scoped — not a shared-global race).
                with patch.object(client, '_generate_hmac_headers') as mock_headers:
                    headers = client._generate_hmac_headers('POST', '/api/test/', b'{}')
                    headers['X-Signature'] = signature_prefix + headers['X-Signature'][len(signature_prefix):]
                    mock_headers.return_value = headers

                    result = client.authenticate_customer(f'attacker{worker_id}@example.com', 'password123')
                    if result:
                        successful_auths += 1

            return {
                'worker_id': worker_id,
                'successful_auths': successful_auths,
                'signature_prefix': signature_prefix,
            }

        signature_prefixes = ['aaaa', 'bbbb', 'cccc', 'dddd', 'eeee']

        # Global-state managers entered ONCE (reverse-order exit joins the executor BEFORE the
        # patch/settings are restored); new=fn (not side_effect=) avoids a MagicMock whose call
        # history would itself be mutated by every thread.
        with (
            override_settings(
                PLATFORM_API_SECRET=self.test_secret,
                PORTAL_ID=self.portal_id,
                PLATFORM_API_BASE_URL="http://localhost:8000",
            ),
            patch('apps.common.outbound_http._session.request', new=mock_brute_force_validation),
            concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor,
        ):
            futures = [
                executor.submit(brute_force_worker, i, prefix)
                for i, prefix in enumerate(signature_prefixes)
            ]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        # Read the shared counter after all workers have joined (lock-free, deterministic).
        total_attempts = attempts_state['count']
        total_successes = sum(r['successful_auths'] for r in results)

        # No brute force attempts should succeed
        self.assertEqual(total_successes, 0,
                        f"Brute force attack succeeded {total_successes}/{total_attempts} times")

        # Should have attempted reasonable number of brute force tries (5 workers x 10 iterations)
        self.assertGreaterEqual(total_attempts, 45, "Should have attempted multiple brute force tries")

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
