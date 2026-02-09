"""
Connection Pooling for External Services

Provides efficient connection management for:
- HTTP connections to external APIs
- Database connections (via Django settings)
- SSH connections for Virtualmin
- Webhook delivery connections
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlparse

from django.conf import settings

logger = logging.getLogger(__name__)

# Try to import requests with urllib3 for connection pooling
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None  # type: ignore[assignment]


class ConnectionPool:
    """
    Generic connection pool with configurable size and timeout.
    Thread-safe implementation using threading.Semaphore.
    """

    def __init__(
        self,
        max_connections: int = 10,
        connection_timeout: float = 30.0,
        idle_timeout: float = 300.0,
    ) -> None:
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.idle_timeout = idle_timeout

        self._semaphore = threading.Semaphore(max_connections)
        self._connections: list[tuple[Any, float]] = []
        self._lock = threading.Lock()

    @contextmanager
    def acquire(self) -> Iterator[None]:
        """Acquire a connection slot from the pool."""
        acquired = self._semaphore.acquire(timeout=self.connection_timeout)
        if not acquired:
            raise ConnectionError(
                f"Could not acquire connection within {self.connection_timeout}s timeout"
            )

        try:
            yield
        finally:
            self._semaphore.release()

    def get_stats(self) -> dict[str, Any]:
        """Get pool statistics."""
        with self._lock:
            return {
                "max_connections": self.max_connections,
                "available": self._semaphore._value,
                "in_use": self.max_connections - self._semaphore._value,
            }


class HTTPConnectionPool:
    """
    HTTP connection pool using requests library with proper pooling.
    Supports retry logic and connection reuse.
    """

    _instances: dict[str, "HTTPConnectionPool"] = {}
    _lock = threading.Lock()

    def __init__(
        self,
        base_url: str,
        pool_connections: int = 10,
        pool_maxsize: int = 10,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        timeout: tuple[float, float] = (10.0, 30.0),  # (connect, read)
    ) -> None:
        if not HAS_REQUESTS:
            raise ImportError("requests library is required for HTTPConnectionPool")

        self.base_url = base_url
        self.timeout = timeout

        # Create session with connection pooling
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
        )

        # Configure HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
        )

        # Mount adapter for both HTTP and HTTPS
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        logger.debug(
            f"HTTPConnectionPool initialized for {base_url} "
            f"(pool_size={pool_maxsize}, retries={max_retries})"
        )

    @classmethod
    def get_pool(
        cls,
        base_url: str,
        **kwargs: Any,
    ) -> "HTTPConnectionPool":
        """Get or create a connection pool for a base URL."""
        parsed = urlparse(base_url)
        pool_key = f"{parsed.scheme}://{parsed.netloc}"

        with cls._lock:
            if pool_key not in cls._instances:
                cls._instances[pool_key] = cls(base_url, **kwargs)
            return cls._instances[pool_key]

    def get(self, path: str, **kwargs: Any) -> "requests.Response":
        """Make a GET request."""
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        kwargs.setdefault("timeout", self.timeout)
        return self.session.get(url, **kwargs)

    def post(self, path: str, **kwargs: Any) -> "requests.Response":
        """Make a POST request."""
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(url, **kwargs)

    def put(self, path: str, **kwargs: Any) -> "requests.Response":
        """Make a PUT request."""
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        kwargs.setdefault("timeout", self.timeout)
        return self.session.put(url, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> "requests.Response":
        """Make a DELETE request."""
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        kwargs.setdefault("timeout", self.timeout)
        return self.session.delete(url, **kwargs)

    def close(self) -> None:
        """Close the session and release connections."""
        self.session.close()

    def __enter__(self) -> "HTTPConnectionPool":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class ExternalServicePool:
    """
    Manages connection pools for multiple external services.
    Singleton pattern for application-wide pool management.
    """

    _instance: "ExternalServicePool | None" = None
    _lock = threading.Lock()

    # Default configuration for known services
    SERVICE_CONFIGS = {
        "virtualmin": {
            "pool_connections": 5,
            "pool_maxsize": 10,
            "max_retries": 3,
            "timeout": (15.0, 60.0),
        },
        "stripe": {
            "pool_connections": 10,
            "pool_maxsize": 20,
            "max_retries": 3,
            "timeout": (10.0, 30.0),
        },
        "efactura": {
            "pool_connections": 3,
            "pool_maxsize": 5,
            "max_retries": 2,
            "timeout": (10.0, 60.0),
        },
        "default": {
            "pool_connections": 5,
            "pool_maxsize": 10,
            "max_retries": 3,
            "timeout": (10.0, 30.0),
        },
    }

    def __new__(cls) -> "ExternalServicePool":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._pools = {}
                cls._instance._pool_lock = threading.Lock()
            return cls._instance

    def get_pool(self, service_name: str, base_url: str) -> HTTPConnectionPool:
        """Get or create a connection pool for a service."""
        pool_key = f"{service_name}:{base_url}"

        with self._pool_lock:
            if pool_key not in self._pools:
                config = self.SERVICE_CONFIGS.get(
                    service_name,
                    self.SERVICE_CONFIGS["default"],
                )
                self._pools[pool_key] = HTTPConnectionPool(base_url, **config)
                logger.info(f"Created connection pool for {service_name}: {base_url}")

            return self._pools[pool_key]

    def close_all(self) -> None:
        """Close all connection pools."""
        with self._pool_lock:
            for pool in self._pools.values():
                pool.close()
            self._pools.clear()
            logger.info("All connection pools closed")

    def get_stats(self) -> dict[str, Any]:
        """Get statistics for all pools."""
        with self._pool_lock:
            return {
                name: pool.session.adapters.get("https://", None)
                for name, pool in self._pools.items()
            }


def get_http_session(
    service_name: str | None = None,
    base_url: str | None = None,
) -> HTTPConnectionPool:
    """
    Get a connection-pooled HTTP session for external service calls.

    Usage:
        # For Virtualmin API calls
        session = get_http_session("virtualmin", "https://server.example.com:10000")
        response = session.get("/api/endpoint")

        # For generic HTTP calls
        session = get_http_session(base_url="https://api.example.com")
        response = session.post("/resource", json=data)
    """
    if not HAS_REQUESTS:
        raise ImportError("requests library is required for HTTP connection pooling")

    if not base_url:
        raise ValueError("base_url is required")

    service = service_name or "default"
    pool_manager = ExternalServicePool()
    return pool_manager.get_pool(service, base_url)


# Database connection pooling configuration helpers

def get_database_pool_config(environment: str = "production") -> dict[str, Any]:
    """
    Get recommended database connection pool configuration.
    Returns settings suitable for Django's CONN_MAX_AGE and psycopg pool settings.
    """
    configs = {
        "development": {
            "CONN_MAX_AGE": 60,
            "CONN_HEALTH_CHECKS": False,
            "OPTIONS": {
                "MAX_CONNS": 5,
                "connect_timeout": 10,
            },
        },
        "staging": {
            "CONN_MAX_AGE": 300,
            "CONN_HEALTH_CHECKS": True,
            "OPTIONS": {
                "MAX_CONNS": 10,
                "connect_timeout": 10,
                "keepalives": 1,
                "keepalives_idle": 30,
                "keepalives_interval": 10,
                "keepalives_count": 5,
            },
        },
        "production": {
            "CONN_MAX_AGE": 600,
            "CONN_HEALTH_CHECKS": True,
            "OPTIONS": {
                "MAX_CONNS": 20,
                "connect_timeout": 10,
                "keepalives": 1,
                "keepalives_idle": 30,
                "keepalives_interval": 10,
                "keepalives_count": 5,
                "sslmode": "require",
            },
        },
    }

    return configs.get(environment, configs["production"])


# Cleanup on application shutdown

def cleanup_pools() -> None:
    """Clean up all connection pools on application shutdown."""
    try:
        pool_manager = ExternalServicePool()
        pool_manager.close_all()
    except Exception as e:
        logger.warning(f"Error cleaning up connection pools: {e}")


# SSH connection pool for Virtualmin (optional)

class SSHConnectionPool:
    """
    Connection pool for SSH connections to Virtualmin servers.
    Uses paramiko if available.
    """

    def __init__(
        self,
        max_connections: int = 5,
        idle_timeout: float = 300.0,
    ) -> None:
        try:
            import paramiko
            self._paramiko = paramiko
        except ImportError:
            self._paramiko = None
            logger.warning("paramiko not available, SSH pooling disabled")
            return

        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self._connections: dict[str, list[tuple[Any, float]]] = {}
        self._lock = threading.Lock()

    def get_connection(
        self,
        hostname: str,
        username: str,
        password: str | None = None,
        key_filename: str | None = None,
    ) -> Any:
        """Get or create an SSH connection."""
        if self._paramiko is None:
            raise ImportError("paramiko is required for SSH connections")

        conn_key = f"{username}@{hostname}"

        with self._lock:
            # Check for existing connection
            if conn_key in self._connections:
                connections = self._connections[conn_key]
                now = time.time()

                # Find a valid connection
                while connections:
                    conn, last_used = connections.pop(0)
                    if now - last_used < self.idle_timeout:
                        # Test connection is still alive
                        try:
                            conn.get_transport().send_ignore()
                            return conn
                        except Exception:
                            conn.close()

            # Create new connection
            client = self._paramiko.SSHClient()
            client.set_missing_host_key_policy(self._paramiko.AutoAddPolicy())

            connect_kwargs: dict[str, Any] = {
                "hostname": hostname,
                "username": username,
                "timeout": 30,
            }

            if password:
                connect_kwargs["password"] = password
            if key_filename:
                connect_kwargs["key_filename"] = key_filename

            client.connect(**connect_kwargs)
            logger.debug(f"SSH connection established to {hostname}")

            return client

    def return_connection(self, hostname: str, username: str, connection: Any) -> None:
        """Return a connection to the pool."""
        conn_key = f"{username}@{hostname}"

        with self._lock:
            if conn_key not in self._connections:
                self._connections[conn_key] = []

            if len(self._connections[conn_key]) < self.max_connections:
                self._connections[conn_key].append((connection, time.time()))
            else:
                connection.close()

    def close_all(self) -> None:
        """Close all connections in the pool."""
        with self._lock:
            for connections in self._connections.values():
                for conn, _ in connections:
                    try:
                        conn.close()
                    except OSError:
                        logger.debug("Connection close failed during pool shutdown")
            self._connections.clear()
