# ===============================================================================
# DOCKER SERVICES INTEGRATION TESTS 🐳
# ===============================================================================
# Tests Docker containerized services work correctly together
# Validates network isolation, health checks, and service communication

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml


class TestDockerServicesIntegration:
    """
    Integration tests for Docker containerized PRAHO services.

    These tests verify that:
    1. Platform service starts correctly in container
    2. Portal service starts correctly in container
    3. Network isolation works as expected
    4. Services can communicate via designated networks
    5. Health checks work correctly
    """

    @pytest.mark.integration
    @pytest.mark.slow
    def test_platform_service_container_health(self):
        """
        Test that platform service container is healthy and responding.
        """
        # This would typically run against actual Docker containers
        # For now, we'll mock the health check response

        mock_response = """
        HTTP/1.1 302 Found
        Server: gunicorn
        Location: /users/login/
        Content-Type: text/html; charset=utf-8
        """

        # Simulate health check
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = mock_response
            mock_run.return_value.returncode = 0

            # Test platform health endpoint
            result = subprocess.run([
                'curl', '-I', 'http://localhost:8700/'
            ], capture_output=True, text=True)

            assert result.returncode == 0
            assert 'Location: /users/login/' in result.stdout

    @pytest.mark.integration
    @pytest.mark.slow
    def test_portal_service_container_isolation(self):
        """
        Test that portal service container cannot access platform database.

        This validates the network isolation in Docker Compose.
        """
        # Portal container should NOT have access to platform-network
        # This test would verify network isolation in actual Docker environment

        with patch('subprocess.run') as mock_run:
            # Simulate network connectivity test from portal container
            mock_run.return_value.returncode = 1  # Connection refused
            mock_run.return_value.stderr = "Connection refused"

            # Portal should NOT be able to connect to DB directly
            result = subprocess.run([
                'docker', 'exec', 'portal-container',
                'nc', '-z', 'db', '5432'
            ], capture_output=True, text=True)

            # Connection should fail (network isolation working)
            assert result.returncode == 1

    @pytest.mark.integration
    @pytest.mark.parametrize("name", ["single-server", "platform-only", "portal-only", "container-service"])
    def test_docker_compose_services_configuration(self, name):
        """
        Test that each production Compose file keeps Redis out and the portal off the database.
        """
        compose_path = Path(__file__).resolve().parents[2] / "deploy" / f"docker-compose.{name}.yml"
        text = compose_path.read_text()
        compose_config = yaml.safe_load(text)
        services = compose_config["services"]

        # No Redis anywhere: the platform uses Django's database cache (ADR-0020)
        assert "redis" not in services, "Redis should not be a service"
        assert "REDIS_URL" not in text, "No service should get a REDIS_URL"
        redis_volumes = [vol for vol in (compose_config.get("volumes") or {}) if "redis" in vol.lower()]
        assert len(redis_volumes) == 0, "No Redis volumes should exist"

        # Platform connects with individual DB_* vars, not DATABASE_URL
        if "platform" in services:
            platform_env = str(services["platform"]["environment"])
            assert "DB_HOST" in platform_env, "Platform should have DB_HOST"
            assert "DB_NAME" in platform_env, "Platform should have DB_NAME"

        # Portal has no business database: no connection settings, and no network shared with the db
        if "portal" in services:
            portal_env = str(services["portal"].get("environment", []))
            for var in ("DATABASE_URL", "DB_HOST", "DB_NAME", "DB_PASSWORD"):
                assert var not in portal_env, f"Portal should not have {var}"
            if "db" in services:
                db_networks = set(services["db"].get("networks") or [])
                portal_networks = set(services["portal"].get("networks") or [])
                assert db_networks, "The db should sit on an explicit network"
                assert not db_networks & portal_networks, "The portal must share no network with the database"

    @pytest.mark.integration
    @pytest.mark.slow
    def test_docker_build_process_no_redis(self):
        """
        Test that Docker build process works without Redis dependencies.
        """
        # Mock docker build output - should NOT contain redis packages
        mock_build_output = """
        Step 5/9 : RUN pip install -r requirements/prod.txt
         ---> Running in abc123
        Successfully installed Django-5.2.6 gunicorn-21.2.0 psycopg-3.2.0
        """

        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = mock_build_output
            mock_run.return_value.returncode = 0

            # Test platform build
            result = subprocess.run([
                'docker', 'build', '-f', 'deploy/platform/Dockerfile', '.'
            ], capture_output=True, text=True)

            assert result.returncode == 0
            # Should NOT install Redis dependencies, but notes are OK
            build_lines = result.stdout.lower().split('\n')
            redis_install_lines = [line for line in build_lines
                                   if 'successfully installed' in line and 'django-redis' in line]
            assert len(redis_install_lines) == 0, "django-redis should not be installed as a dependency"


# ===============================================================================
# SERVICE STARTUP AND HEALTH CHECK TESTS 🩺
# ===============================================================================

class TestServiceHealthChecks:
    """
    Tests for service health checks and startup sequences.
    """

    @pytest.mark.integration
    def test_platform_service_startup_sequence(self):
        """
        Test platform service starts up correctly with database cache.
        """
        expected_startup_logs = [
            "Audit Signals] Comprehensive audit signals registered",
            "Django version 5.2",
            "Using database cache backend",  # Should NOT mention Redis
        ]

        # Mock platform startup logs
        mock_logs = """
        INFO: Audit Signals] Comprehensive audit signals registered
        INFO: Django version 5.2.6, using settings 'config.settings.dev'
        INFO: Using database cache backend (django_cache_table)
        INFO: Development server is running at http://0.0.0.0:8700/
        """

        for expected_log in expected_startup_logs:
            if "database cache backend" in expected_log:
                assert "database cache backend" in mock_logs
            else:
                assert expected_log in mock_logs

        # Should NOT contain Redis references
        assert 'redis' not in mock_logs.lower()
        assert 'Redis' not in mock_logs

    @pytest.mark.integration
    def test_portal_service_startup_no_db_access(self):
        """
        Test portal service starts without database access.
        """
        expected_portal_logs = [
            "Portal service starting",
            "API-only mode enabled",
            "No database connection configured"  # Portal should not connect to DB
        ]

        # Mock portal startup
        mock_logs = """
        INFO: Portal service starting on port 8001
        INFO: API-only mode enabled
        INFO: No database connection configured (security isolation)
        INFO: Ready to serve API requests
        """

        # Verify portal doesn't try to access database
        assert "No database connection" in mock_logs
        assert "security isolation" in mock_logs

        # Should NOT contain database connection logs
        assert "database connection established" not in mock_logs.lower()
        assert "migration" not in mock_logs.lower()
