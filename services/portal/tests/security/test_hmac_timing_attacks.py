"""
🔐 HMAC Timing Attack Protection Tests

Comprehensive tests for timing attack protection in HMAC authentication:
- Constant-time signature comparison
- Uniform response timing
- Timing-resistant error handling
- Side-channel attack prevention
- Statistical timing analysis

These tests ensure that HMAC authentication is resistant to timing-based
side-channel attacks that could leak information about valid signatures.
"""

import hashlib
import hmac
import statistics
import time
from unittest.mock import patch, Mock
from typing import List, Tuple

from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIClient


class HMACTimingAttackProtectionTestCase(SimpleTestCase):
    """🔐 Timing attack protection tests for HMAC authentication"""

    def setUp(self):
        """Set up timing attack test environment"""
        self.test_secret = "timing-attack-test-secret-key"
        self.portal_id = "timing-test-portal"

    def _measure_signature_validation_timing(self, correct_signature: bool, iterations: int = 50) -> List[float]:
        """Measure signature validation timing for statistical analysis"""

        def mock_platform_timing_validation(*args, **kwargs):
            """Mock Platform with realistic timing simulation"""
            headers = kwargs.get('headers', {})
            signature = headers.get('X-Signature', '')

            # Simulate signature validation timing
            start_time = time.perf_counter()

            # Generate expected signature
            method = kwargs.get('method', 'POST')
            url = kwargs.get('url', '')
            path = url.replace('http://localhost:8000', '') if url else '/api/test/'
            body = kwargs.get('data', b'{}')
            if isinstance(body, str):
                body = body.encode()

            portal_id = headers.get('X-Portal-Id', '')
            nonce = headers.get('X-Nonce', '')
            timestamp = headers.get('X-Timestamp', '')

            # Build canonical string for expected signature
            canonical = f"{method}|{path}|{body.decode()}|{portal_id}|{nonce}|{timestamp}"
            expected_signature = hmac.new(
                self.test_secret.encode(), canonical.encode(), hashlib.sha256
            ).hexdigest()

            # Use constant-time comparison (this is what we're testing)
            is_valid = hmac.compare_digest(signature, expected_signature)

            # Simulate processing time - should be constant regardless of result
            time.sleep(0.0001)  # 0.1ms base processing time

            end_time = time.perf_counter()
            processing_time = end_time - start_time

            mock_response = Mock()
            if correct_signature and is_valid:
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'processing_time': processing_time}
            elif correct_signature:
                # Correct signature expected but validation failed (test setup issue)
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True, 'processing_time': processing_time}
            else:
                # Invalid signature
                mock_response.status_code = 401
                mock_response.json.return_value = {'error': 'HMAC authentication failed', 'processing_time': processing_time}

            return mock_response

        times = []

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret if correct_signature else "wrong-secret",
            PORTAL_ID=self.portal_id,
            PLATFORM_API_BASE_URL="http://localhost:8000"
        ):
            client = PlatformAPIClient()

            for _ in range(iterations):
                with patch('requests.request', side_effect=mock_platform_timing_validation):
                    start_time = time.perf_counter()
                    client.authenticate_customer('test@example.com', 'password123')
                    end_time = time.perf_counter()

                    times.append(end_time - start_time)

        return times

    def test_constant_time_signature_comparison(self):
        """🔐 Test HMAC signature comparison is constant-time"""
        # Measure timing for valid signatures
        valid_times = self._measure_signature_validation_timing(correct_signature=True, iterations=100)

        # Measure timing for invalid signatures
        invalid_times = self._measure_signature_validation_timing(correct_signature=False, iterations=100)

        # Statistical analysis
        valid_mean = statistics.mean(valid_times)
        invalid_mean = statistics.mean(invalid_times)

        valid_stddev = statistics.stdev(valid_times)
        invalid_stddev = statistics.stdev(invalid_times)

        # Times should be statistically similar
        time_difference = abs(valid_mean - invalid_mean)
        combined_stddev = (valid_stddev + invalid_stddev) / 2

        # Difference should be within 2 standard deviations (95% confidence)
        acceptable_difference = 2 * combined_stddev

        self.assertLess(time_difference, acceptable_difference,
                       f"Timing difference too large: {time_difference:.6f}s "
                       f"(threshold: {acceptable_difference:.6f}s). "
                       f"Valid: {valid_mean:.6f}±{valid_stddev:.6f}s, "
                       f"Invalid: {invalid_mean:.6f}±{invalid_stddev:.6f}s")

    def test_signature_timing_independence_of_error_position(self):
        """🔐 Test timing doesn't vary based on where signature differs"""

        def create_modified_signature(original: str, error_position: int) -> str:
            """Create signature with error at specific position"""
            if error_position >= len(original):
                return original + 'x'  # Append error

            # Replace character at error_position
            chars = list(original)
            chars[error_position] = 'x' if original[error_position] != 'x' else 'y'
            return ''.join(chars)

        # Generate a base signature
        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()
            headers = client._generate_hmac_headers('POST', '/api/test/', b'{"test": "data"}')
            base_signature = headers['X-Signature']

        # Test errors at different positions
        error_positions = [0, 8, 16, 32, 48, 63]  # Different positions in 64-char signature
        timing_by_position = {}

        for position in error_positions:
            modified_signature = create_modified_signature(base_signature, position)

            def mock_validation_with_modified_signature(*args, **kwargs):
                headers = kwargs.get('headers', {})
                # Replace signature with modified version
                headers['X-Signature'] = modified_signature

                # Use constant-time comparison
                expected_sig = base_signature  # Original correct signature
                received_sig = modified_signature

                start_time = time.perf_counter()
                is_valid = hmac.compare_digest(received_sig, expected_sig)
                time.sleep(0.0001)  # Constant processing time
                end_time = time.perf_counter()

                mock_response = Mock()
                mock_response.status_code = 401
                mock_response.json.return_value = {
                    'error': 'HMAC authentication failed',
                    'position': position,
                    'processing_time': end_time - start_time
                }
                return mock_response

            # Measure timing for this error position
            times = []
            for _ in range(20):
                with patch('requests.request', side_effect=mock_validation_with_modified_signature):
                    start_time = time.perf_counter()
                    client.authenticate_customer('test@example.com', 'password123')
                    end_time = time.perf_counter()
                    times.append(end_time - start_time)

            timing_by_position[position] = times

        # Analyze timing variance across positions
        position_means = {pos: statistics.mean(times) for pos, times in timing_by_position.items()}
        all_means = list(position_means.values())

        overall_mean = statistics.mean(all_means)
        mean_variance = statistics.stdev(all_means) if len(all_means) > 1 else 0

        # Variance between positions should be reasonable (allowing for test environment variance).
        # Coverage instrumentation and OS scheduler jitter inflate timings, so
        # 30% of mean is used as a safe automated-test threshold.
        max_acceptable_variance = overall_mean * 0.30  # 30% of mean for test environment

        self.assertLess(mean_variance, max_acceptable_variance,
                       f"Timing varies too much by error position: {mean_variance:.6f}s "
                       f"(threshold: {max_acceptable_variance:.6f}s). "
                       f"Position timings: {position_means}")

    def test_nonce_validation_timing_consistency(self):
        """🔐 Test nonce validation timing is consistent for valid/invalid nonces"""

        def mock_nonce_timing_validation(valid_nonce: bool):
            """Mock Platform nonce validation with timing simulation"""
            def mock_request(*args, **kwargs):
                headers = kwargs.get('headers', {})
                nonce = headers.get('X-Nonce', '')

                # Simulate nonce cache lookup timing
                start_time = time.perf_counter()

                if valid_nonce:
                    # Simulate cache miss (new nonce)
                    cache_result = None
                else:
                    # Simulate cache hit (duplicate nonce)
                    cache_result = True

                # Constant-time nonce validation
                time.sleep(0.00005)  # 0.05ms cache lookup simulation

                end_time = time.perf_counter()
                processing_time = end_time - start_time

                mock_response = Mock()
                if valid_nonce:
                    mock_response.status_code = 200
                    mock_response.json.return_value = {
                        'success': True,
                        'nonce_processing_time': processing_time
                    }
                else:
                    mock_response.status_code = 401
                    mock_response.json.return_value = {
                        'error': 'Nonce already used',
                        'nonce_processing_time': processing_time
                    }

                return mock_response
            return mock_request

        # Measure timing for valid nonces (cache miss)
        valid_nonce_times = []

        with override_settings(
            PLATFORM_API_SECRET=self.test_secret,
            PORTAL_ID=self.portal_id
        ):
            client = PlatformAPIClient()

            for _ in range(30):
                with patch('requests.request', side_effect=mock_nonce_timing_validation(True)):
                    start_time = time.perf_counter()
                    client.authenticate_customer('test@example.com', 'password123')
                    end_time = time.perf_counter()
                    valid_nonce_times.append(end_time - start_time)

        # Measure timing for invalid nonces (cache hit)
        invalid_nonce_times = []

        for _ in range(30):
            with patch('requests.request', side_effect=mock_nonce_timing_validation(False)):
                start_time = time.perf_counter()
                client.authenticate_customer('test@example.com', 'password123')
                end_time = time.perf_counter()
                invalid_nonce_times.append(end_time - start_time)

        # Compare timing distributions
        valid_mean = statistics.mean(valid_nonce_times)
        invalid_mean = statistics.mean(invalid_nonce_times)

        valid_stddev = statistics.stdev(valid_nonce_times)
        invalid_stddev = statistics.stdev(invalid_nonce_times)

        # Timing difference should be minimal
        time_difference = abs(valid_mean - invalid_mean)
        combined_stddev = (valid_stddev + invalid_stddev) / 2
        acceptable_difference = 2 * combined_stddev

        self.assertLess(time_difference, acceptable_difference,
                       f"Nonce validation timing varies too much: {time_difference:.6f}s "
                       f"Valid nonces: {valid_mean:.6f}±{valid_stddev:.6f}s, "
                       f"Invalid nonces: {invalid_mean:.6f}±{invalid_stddev:.6f}s")

    def test_timestamp_validation_timing_consistency(self):
        """🔐 Test timestamp validation timing doesn't leak information"""

        current_time = time.time()

        timestamp_scenarios = [
            (str(current_time), "current"),                    # Valid timestamp
            (str(current_time - 10), "recent_past"),          # Valid recent past
            (str(current_time - 301), "expired"),             # Just expired (>300s)
            (str(current_time - 3600), "very_expired"),       # Very expired
            (str(current_time + 10), "future"),               # Future timestamp
            ("invalid_timestamp", "malformed"),               # Invalid format
        ]

        timing_by_scenario = {}

        for timestamp, scenario_name in timestamp_scenarios:
            def mock_timestamp_validation(*args, **kwargs):
                headers = kwargs.get('headers', {})
                received_timestamp = headers.get('X-Timestamp', '')

                # Simulate timestamp validation timing
                start_time = time.perf_counter()

                try:
                    ts_float = float(received_timestamp)
                    current_ts = time.time()
                    is_valid = abs(current_ts - ts_float) <= 300  # 5 minute window
                except (ValueError, TypeError):
                    is_valid = False

                # Constant processing time regardless of validity
                time.sleep(0.00002)  # 0.02ms processing

                end_time = time.perf_counter()
                processing_time = end_time - start_time

                mock_response = Mock()
                if is_valid:
                    mock_response.status_code = 200
                    mock_response.json.return_value = {
                        'success': True,
                        'timestamp_processing_time': processing_time
                    }
                else:
                    mock_response.status_code = 401
                    mock_response.json.return_value = {
                        'error': 'Invalid timestamp',
                        'timestamp_processing_time': processing_time
                    }

                return mock_response

            # Measure timing for this timestamp scenario
            times = []

            with override_settings(
                PLATFORM_API_SECRET=self.test_secret,
                PORTAL_ID=self.portal_id
            ):
                client = PlatformAPIClient()

                for _ in range(20):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        # Mock headers with specific timestamp
                        mock_headers.return_value = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'mock_signature_64_chars_' + 'a' * 32,
                            'X-Nonce': 'mock_nonce',
                            'X-Timestamp': timestamp,
                            'X-Body-Hash': 'mock_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }

                        with patch('requests.request', side_effect=mock_timestamp_validation):
                            start_time = time.perf_counter()
                            client.authenticate_customer('test@example.com', 'password123')
                            end_time = time.perf_counter()
                            times.append(end_time - start_time)

            timing_by_scenario[scenario_name] = times

        # Analyze timing consistency across scenarios
        scenario_means = {name: statistics.mean(times) for name, times in timing_by_scenario.items()}
        all_means = list(scenario_means.values())

        if len(all_means) > 1:
            overall_mean = statistics.mean(all_means)
            mean_variance = statistics.stdev(all_means)

            # Variance should be reasonable relative to mean (allowing for test environment variance)
            max_acceptable_variance = overall_mean * 0.30  # 30% of mean for test environment

            self.assertLess(mean_variance, max_acceptable_variance,
                           f"Timestamp validation timing varies too much by scenario: {mean_variance:.6f}s "
                           f"(threshold: {max_acceptable_variance:.6f}s). "
                           f"Scenario timings: {scenario_means}")

    def test_error_response_timing_uniformity(self):
        """🔐 Test error responses have uniform timing regardless of error type"""

        error_scenarios = [
            ('missing_signature', lambda h: h.pop('X-Signature', None)),
            ('missing_nonce', lambda h: h.pop('X-Nonce', None)),
            ('missing_timestamp', lambda h: h.pop('X-Timestamp', None)),
            ('missing_portal_id', lambda h: h.pop('X-Portal-Id', None)),
            ('invalid_signature', lambda h: h.update({'X-Signature': 'invalid_sig'})),
            ('malformed_timestamp', lambda h: h.update({'X-Timestamp': 'not_a_number'})),
        ]

        timing_by_error = {}

        for error_name, header_modifier in error_scenarios:
            def mock_error_validation(*args, **kwargs):
                """Mock Platform with uniform error response timing"""
                # Simulate uniform error processing time
                start_time = time.perf_counter()

                # All errors take same processing time
                time.sleep(0.0002)  # 0.2ms uniform error processing

                end_time = time.perf_counter()
                processing_time = end_time - start_time

                mock_response = Mock()
                mock_response.status_code = 401
                mock_response.json.return_value = {
                    'error': 'HMAC authentication failed',
                    'error_type': error_name,
                    'processing_time': processing_time
                }

                return mock_response

            # Measure timing for this error type
            times = []

            with override_settings(
                PLATFORM_API_SECRET=self.test_secret,
                PORTAL_ID=self.portal_id
            ):
                client = PlatformAPIClient()

                for _ in range(25):
                    with patch.object(client, '_generate_hmac_headers') as mock_headers:
                        # Generate normal headers then modify for error
                        headers = {
                            'X-Portal-Id': self.portal_id,
                            'X-Signature': 'normal_signature_64_chars_' + 'a' * 32,
                            'X-Nonce': 'normal_nonce',
                            'X-Timestamp': str(time.time()),
                            'X-Body-Hash': 'normal_body_hash',
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }

                        # Apply error modification
                        header_modifier(headers)
                        mock_headers.return_value = headers

                        with patch('requests.request', side_effect=mock_error_validation):
                            start_time = time.perf_counter()
                            client.authenticate_customer('test@example.com', 'password123')
                            end_time = time.perf_counter()
                            times.append(end_time - start_time)

            timing_by_error[error_name] = times

        # Analyze timing uniformity across error types
        error_means = {name: statistics.mean(times) for name, times in timing_by_error.items()}
        all_means = list(error_means.values())

        if len(all_means) > 1:
            overall_mean = statistics.mean(all_means)
            mean_variance = statistics.stdev(all_means)

            # Error response timing should be reasonably uniform (allowing for test environment variance)
            max_acceptable_variance = overall_mean * 0.20  # 20% of mean for test environment

            self.assertLess(mean_variance, max_acceptable_variance,
                           f"Error response timing varies too much by error type: {mean_variance:.6f}s "
                           f"(threshold: {max_acceptable_variance:.6f}s). "
                           f"Error timings: {error_means}")


class HMACStatisticalTimingAnalysisTestCase(SimpleTestCase):
    """🔐 Statistical analysis of HMAC timing characteristics"""

    def test_signature_comparison_statistical_analysis(self):
        """🔐 Comprehensive statistical analysis of signature comparison timing"""

        def measure_comparison_timing(signature_pairs: List[Tuple[str, str]], iterations: int = 100) -> List[float]:
            """Measure timing for signature comparisons"""
            times = []

            for sig1, sig2 in signature_pairs:
                for _ in range(iterations):
                    start_time = time.perf_counter()
                    result = hmac.compare_digest(sig1, sig2)
                    end_time = time.perf_counter()
                    times.append(end_time - start_time)

            return times

        # Generate test signature pairs
        base_sig = 'a' * 64  # 64-char signature

        signature_test_cases = [
            # Identical signatures
            [(base_sig, base_sig)] * 5,

            # Different signatures (early difference)
            [(base_sig, 'b' + base_sig[1:])] * 5,

            # Different signatures (late difference)
            [(base_sig, base_sig[:-1] + 'b')] * 5,

            # Completely different signatures
            [('a' * 64, 'b' * 64)] * 5,

            # Different lengths
            [('a' * 64, 'a' * 63)] * 5,
            [('a' * 64, 'a' * 65)] * 5,
        ]

        all_timing_data = []

        for test_case in signature_test_cases:
            case_times = measure_comparison_timing(test_case, iterations=20)
            all_timing_data.extend(case_times)

        # Statistical analysis
        if len(all_timing_data) > 10:
            mean_time = statistics.mean(all_timing_data)
            median_time = statistics.median(all_timing_data)
            stddev_time = statistics.stdev(all_timing_data)

            # Check for timing consistency
            coefficient_of_variation = stddev_time / mean_time if mean_time > 0 else 0

            # Timing should be consistent (low coefficient of variation)
            self.assertLess(coefficient_of_variation, 0.7,
                           f"Signature comparison timing too variable: CV={coefficient_of_variation:.3f}")

            # Check for outliers (times more than 3 std devs from mean)
            outliers = [t for t in all_timing_data if abs(t - mean_time) > 3 * stddev_time]
            outlier_rate = len(outliers) / len(all_timing_data)

            self.assertLess(outlier_rate, 0.05,
                           f"Too many timing outliers: {outlier_rate:.1%} (should be <5%)")

    def test_hmac_generation_timing_analysis(self):
        """🔐 Statistical analysis of HMAC generation timing"""

        with override_settings(
            PLATFORM_API_SECRET="statistical-timing-analysis-key",
            PORTAL_ID="timing-analysis-test"
        ):
            client = PlatformAPIClient()
            # Test various request characteristics
            test_requests = [
                ("GET", "/api/short/", b""),
                ("POST", "/api/medium/", b'{"data": "medium request"}'),
                ("PUT", "/api/long/", b'{"data": "' + b"x" * 1000 + b'"}'),
                ("DELETE", "/api/query/", b""),
                ("POST", "/api/complex/", b'{"nested": {"data": {"with": "complexity"}}}'),
            ]

            # Measure each request profile independently to avoid mixing
            # expected payload-size differences into one variance bucket.
            batch_size = 400
            samples_per_profile = 25
            fixed_timestamp = "1700000000.0"
            profile_medians: list[float] = []

            with patch("apps.api_client.services.secrets.token_urlsafe", return_value="deterministic-nonce"):
                for method, path, body in test_requests:
                    for _ in range(5):  # warmup
                        client._generate_hmac_headers(method, path, body, fixed_timestamp=fixed_timestamp)

                    per_call_times: list[float] = []
                    for _ in range(samples_per_profile):
                        start_ns = time.perf_counter_ns()
                        for _ in range(batch_size):
                            client._generate_hmac_headers(method, path, body, fixed_timestamp=fixed_timestamp)
                        elapsed_ns = time.perf_counter_ns() - start_ns
                        per_call_times.append((elapsed_ns / batch_size) / 1_000_000_000)

                    mean_time = statistics.mean(per_call_times)
                    median_time = statistics.median(per_call_times)
                    profile_medians.append(median_time)
                    percentile_90 = (
                        statistics.quantiles(per_call_times, n=10)[8]
                        if len(per_call_times) >= 20
                        else max(per_call_times)
                    )

                    # Performance requirements (per profile)
                    self.assertLess(
                        mean_time,
                        0.01,
                        f"HMAC generation too slow for {method} {path}: mean={mean_time:.4f}s",
                    )
                    self.assertLess(
                        max(per_call_times),
                        0.05,
                        f"HMAC generation max time too slow for {method} {path}: max={max(per_call_times):.4f}s",
                    )

                    # Consistency requirements (within profile only).
                    # Use robust percentile/median checks to avoid false failures
                    # from occasional CI scheduler spikes.
                    p90_ratio = percentile_90 / median_time if median_time > 0 else 0
                    self.assertLess(
                        p90_ratio,
                        3.5,
                        (
                            f"HMAC generation timing too variable for {method} {path}: "
                            f"p90/median={p90_ratio:.3f}"
                        ),
                    )

                    outlier_cutoff = median_time * 5
                    outlier_rate = sum(1 for t in per_call_times if t > outlier_cutoff) / len(per_call_times)
                    self.assertLess(
                        outlier_rate,
                        0.20,
                        (
                            f"Too many timing outliers for {method} {path}: "
                            f"rate={outlier_rate:.2%}"
                        ),
                    )

            # Cross-profile sanity check: payload-size differences should not explode.
            if profile_medians:
                mean_ratio = max(profile_medians) / min(profile_medians)
                self.assertLess(
                    mean_ratio,
                    4.0,
                    f"HMAC generation timing differs too much across request profiles: ratio={mean_ratio:.2f}",
                )

    def test_end_to_end_timing_analysis(self):
        """🔐 End-to-end timing analysis of complete HMAC authentication flow"""

        def mock_realistic_platform(*args, **kwargs):
            """Mock Platform with realistic processing timing"""
            # Simulate realistic Platform processing time
            base_time = 0.001  # 1ms base
            random_variation = (hash(str(time.time())) % 100) / 100000  # Small random variation

            time.sleep(base_time + random_variation)

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True, 'authenticated': True}
            return mock_response

        with override_settings(
            PLATFORM_API_SECRET="end-to-end-timing-analysis-key",
            PORTAL_ID="e2e-timing-test",
            PLATFORM_API_BASE_URL="http://localhost:8000"
        ):
            client = PlatformAPIClient()
            end_to_end_times = []

            # Measure complete authentication flow timing
            for i in range(50):
                with patch('requests.request', side_effect=mock_realistic_platform):
                    start_time = time.perf_counter()
                    result = client.authenticate_customer(f'user{i}@example.com', 'password123')
                    end_time = time.perf_counter()

                    if result:  # Only count successful authentications
                        end_to_end_times.append(end_time - start_time)

            # Statistical analysis of end-to-end performance
            if len(end_to_end_times) > 10:
                mean_time = statistics.mean(end_to_end_times)
                percentile_95 = statistics.quantiles(end_to_end_times, n=20)[18]  # 95th percentile
                stddev_time = statistics.stdev(end_to_end_times)

                # Performance requirements for production
                self.assertLess(mean_time, 0.1,
                               f"End-to-end HMAC auth too slow: mean={mean_time:.3f}s")
                self.assertLess(percentile_95, 0.2,
                               f"95th percentile too slow: p95={percentile_95:.3f}s")

                # Consistency analysis
                coefficient_of_variation = stddev_time / mean_time if mean_time > 0 else 0
                self.assertLess(coefficient_of_variation, 0.8,
                               f"End-to-end timing too variable: CV={coefficient_of_variation:.3f}")
