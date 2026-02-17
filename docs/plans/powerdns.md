# PowerDNS Integration Architecture for PRAHO Platform

## Executive Summary

This document outlines the architectural approach for integrating multiple PowerDNS servers into the PRAHO platform for DNS-based traffic management and failover. PRAHO will act as the **single source of truth** for all DNS data, managing multiple PowerDNS instances as stateless, replaceable infrastructure following the "cattle, not pets" philosophy.

**Key Decision**: PowerDNS provides the ideal balance of modern HTTP API integration, production scalability, and operational simplicity for Romanian hosting providers.

## Research Findings

### PowerDNS Strengths for PRAHO Integration

**Modern HTTP API:**
- RESTful API with JSON payloads - perfect for Django integration
- Comprehensive endpoints for zones, records, and RRsets management
- X-API-Key authentication model aligns with security best practices
- Built-in Prometheus metrics endpoint for monitoring

**Production-Ready Architecture:**
- Database backend using PostgreSQL (same as PRAHO)
- Native database replication for high availability
- Handles millions of queries per server
- Docker containerization support
- DNSSEC support when required

**Operational Benefits:**
- Separation of DNS data (database) from DNS service (PowerDNS instances)
- Multiple deployment strategies: single-server, master/slave, multi-master
- Health monitoring via API endpoints and control commands
- Bulk operations support for efficient record management

## Architectural Integration Strategy

### 1. PRAHO as DNS Source of Truth

**Design Principle**: PRAHO database holds authoritative DNS data. PowerDNS servers are stateless workers that serve DNS queries from shared database backend.

```python
# apps/dns/models.py
class DNSZone(BaseModel):
    """PRAHO's authoritative DNS zone data"""
    name = models.CharField(max_length=255)  # example.com.
    kind = models.CharField(max_length=20, choices=[
        ('Native', 'Native'),
        ('Master', 'Master'),
        ('Slave', 'Slave')
    ], default='Native')

    # PowerDNS zones table compatibility
    account = models.CharField(max_length=100, blank=True)
    last_check = models.DateTimeField(null=True, blank=True)
    notified_serial = models.BigIntegerField(null=True, blank=True)

    # PRAHO-specific metadata
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    hosting_service = models.ForeignKey(Service, on_delete=models.SET_NULL, null=True)
    created_by_praho = models.BooleanField(default=True)

    class Meta:
        db_table = 'domains'  # PowerDNS domains table
        unique_together = ['name']

class DNSRecord(BaseModel):
    """DNS records - shared between PRAHO and PowerDNS"""
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)  # www.example.com.
    type = models.CharField(max_length=10)   # A, AAAA, CNAME, MX, etc.
    content = models.TextField()             # 192.168.1.1
    ttl = models.IntegerField(default=300)
    prio = models.IntegerField(default=0)    # Priority for MX, SRV records
    disabled = models.BooleanField(default=False)

    # PRAHO-specific tracking
    managed_by_praho = models.BooleanField(default=True)
    virtualmin_server = models.ForeignKey('provisioning.VirtualminServer',
                                        on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = 'records'  # PowerDNS records table
        indexes = [
            models.Index(fields=['zone', 'name', 'type']),
            models.Index(fields=['name', 'type'])
        ]
```

### 2. Multi-Server PowerDNS Architecture

```python
# apps/dns/models.py
class PowerDNSServer(BaseModel):
    """PowerDNS server instances managed by PRAHO"""
    name = models.CharField(max_length=100)
    hostname = models.CharField(max_length=200)
    ip_address = models.GenericIPAddressField()
    api_port = models.IntegerField(default=8081)
    api_key = models.CharField(max_length=200)

    # Geographic and capacity information
    location = models.CharField(max_length=100)  # Bucharest, Cluj-Napoca, Timișoara
    capacity_queries_per_second = models.IntegerField(default=10000)
    current_load_percentage = models.FloatField(default=0.0)

    # Database connection for this PowerDNS instance
    database_host = models.CharField(max_length=200)
    database_port = models.IntegerField(default=5432)
    database_name = models.CharField(max_length=100)
    database_user = models.CharField(max_length=100)

    # Server status and health
    status = models.CharField(max_length=20, choices=[
        ('healthy', 'Healthy'),
        ('degraded', 'Degraded'),
        ('unavailable', 'Unavailable'),
        ('maintenance', 'Maintenance')
    ], default='healthy')

    last_health_check = models.DateTimeField(null=True, blank=True)
    version = models.CharField(max_length=50, blank=True)
    uptime_seconds = models.IntegerField(default=0)

    # Deployment and management
    deployed_by_praho = models.BooleanField(default=False)
    docker_container_id = models.CharField(max_length=100, blank=True)
    deployment_config = models.JSONField(default=dict)

    class Meta:
        unique_together = ['hostname', 'api_port']
        ordering = ['location', 'name']

class PowerDNSServerMetrics(BaseModel):
    """Store PowerDNS server metrics for monitoring"""
    server = models.ForeignKey(PowerDNSServer, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    # Query metrics
    queries_per_second = models.FloatField(default=0)
    cache_hit_rate = models.FloatField(default=0)
    response_time_ms = models.FloatField(default=0)

    # System metrics
    cpu_usage_percent = models.FloatField(default=0)
    memory_usage_mb = models.IntegerField(default=0)

    # DNS-specific metrics
    zones_count = models.IntegerField(default=0)
    records_count = models.IntegerField(default=0)

    class Meta:
        indexes = [
            models.Index(fields=['server', 'timestamp']),
        ]
        # Keep only last 30 days of metrics
        constraints = [
            models.CheckConstraint(
                check=models.Q(timestamp__gte=timezone.now() - timedelta(days=30)),
                name='metrics_retention_30_days'
            )
        ]
```

### 3. PowerDNS Gateway Implementation

```python
# apps/dns/gateways.py
import requests
import time
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from django.conf import settings
import logging

logger = logging.getLogger('praho.powerdns.api')

@dataclass
class PowerDNSResult:
    """Standardized response from PowerDNS API calls"""
    success: bool
    status_code: int
    message: str
    data: Optional[Union[dict, list]] = None
    error_type: Optional[str] = None
    duration_ms: Optional[float] = None

class PowerDNSError(Exception):
    """Base exception for PowerDNS operations"""
    pass

class PowerDNSAuthError(PowerDNSError):
    """Authentication failed - invalid API key"""
    pass

class PowerDNSRateLimited(PowerDNSError):
    """Rate limit exceeded"""
    pass

class PowerDNSZoneExists(PowerDNSError):
    """Zone already exists"""
    pass

class PowerDNSZoneNotFound(PowerDNSError):
    """Zone not found"""
    pass

class PowerDNSTransientError(PowerDNSError):
    """Temporary failure - retry with backoff"""
    pass

class PowerDNSGateway:
    """Production-ready PowerDNS HTTP API gateway with enterprise patterns"""

    def __init__(self, server: PowerDNSServer):
        self.server = server
        self.base_url = f"http://{server.hostname}:{server.api_port}"
        self.api_key = server.api_key
        self.session = self._create_session()

        # Rate limiting and circuit breaking
        self.rate_limiter = TokenBucketLimiter(max_calls=100, time_window=60)  # Conservative
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)

    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper configuration"""
        session = requests.Session()
        session.headers.update({
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json'
        })

        # Connection pooling and timeouts
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=urllib3.util.Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        session.mount('http://', adapter)
        return session

    def _call_api(self, method: str, endpoint: str, data: Optional[dict] = None) -> PowerDNSResult:
        """Core API call method with comprehensive error handling"""
        correlation_id = str(uuid.uuid4())[:8]

        # Apply rate limiting and circuit breaker
        self.rate_limiter.wait_if_needed()
        if not self.circuit_breaker.can_call():
            raise PowerDNSRateLimited("Circuit breaker is open")

        url = f"{self.base_url}{endpoint}"
        start_time = time.time()

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                timeout=30
            )

            duration_ms = (time.time() - start_time) * 1000

            # Handle different response scenarios
            if response.status_code == 200 or response.status_code == 201:
                self.circuit_breaker.record_success()
                result_data = response.json() if response.content else None

                logger.info(
                    f"PowerDNS API success - {method} {endpoint}",
                    extra={
                        'server': self.server.hostname,
                        'method': method,
                        'endpoint': endpoint,
                        'correlation_id': correlation_id,
                        'duration_ms': duration_ms,
                        'status_code': response.status_code
                    }
                )

                return PowerDNSResult(
                    success=True,
                    status_code=response.status_code,
                    message="Success",
                    data=result_data,
                    duration_ms=duration_ms
                )

            elif response.status_code == 204:  # No Content - successful deletion/modification
                self.circuit_breaker.record_success()
                return PowerDNSResult(
                    success=True,
                    status_code=204,
                    message="Operation completed successfully",
                    duration_ms=duration_ms
                )

            else:
                self.circuit_breaker.record_failure()
                error_message = self._extract_error_message(response)
                error_type = self._classify_error(response.status_code, error_message)

                logger.error(
                    f"PowerDNS API error - {method} {endpoint}: {error_message}",
                    extra={
                        'server': self.server.hostname,
                        'method': method,
                        'endpoint': endpoint,
                        'correlation_id': correlation_id,
                        'duration_ms': duration_ms,
                        'status_code': response.status_code,
                        'error_type': error_type
                    }
                )

                # Raise specific exceptions based on error type
                if response.status_code == 401:
                    raise PowerDNSAuthError(f"Authentication failed: {error_message}")
                elif response.status_code == 409:
                    raise PowerDNSZoneExists(f"Zone already exists: {error_message}")
                elif response.status_code == 404:
                    raise PowerDNSZoneNotFound(f"Zone not found: {error_message}")
                elif response.status_code >= 500:
                    raise PowerDNSTransientError(f"Server error: {error_message}")
                else:
                    raise PowerDNSError(f"API error: {error_message}")

        except requests.RequestException as e:
            duration_ms = (time.time() - start_time) * 1000
            self.circuit_breaker.record_failure()

            logger.error(
                f"PowerDNS API request failed - {method} {endpoint}: {str(e)}",
                extra={
                    'server': self.server.hostname,
                    'method': method,
                    'endpoint': endpoint,
                    'correlation_id': correlation_id,
                    'duration_ms': duration_ms,
                    'error_type': 'RequestException'
                }
            )

            raise PowerDNSTransientError(f"Request failed: {str(e)}")

    def _extract_error_message(self, response: requests.Response) -> str:
        """Extract meaningful error message from response"""
        try:
            error_data = response.json()
            return error_data.get('error', f'HTTP {response.status_code}')
        except:
            return response.text[:200] if response.text else f'HTTP {response.status_code}'

    def _classify_error(self, status_code: int, message: str) -> str:
        """Classify error type for monitoring and metrics"""
        if status_code == 401:
            return 'AuthError'
        elif status_code == 404:
            return 'NotFound'
        elif status_code == 409:
            return 'Conflict'
        elif status_code >= 500:
            return 'ServerError'
        elif 'rate limit' in message.lower():
            return 'RateLimit'
        else:
            return 'ClientError'

    # Zone Management Methods
    def list_zones(self) -> List[dict]:
        """List all zones on this PowerDNS server"""
        result = self._call_api('GET', '/api/v1/servers/localhost/zones')
        return result.data if result.success else []

    def get_zone(self, zone_name: str) -> Optional[dict]:
        """Get detailed information about a specific zone"""
        try:
            result = self._call_api('GET', f'/api/v1/servers/localhost/zones/{zone_name}')
            return result.data if result.success else None
        except PowerDNSZoneNotFound:
            return None

    def create_zone(self, zone_name: str, nameservers: List[str], zone_kind: str = 'Native') -> PowerDNSResult:
        """Create a new DNS zone"""
        zone_data = {
            'name': zone_name,
            'kind': zone_kind,
            'nameservers': nameservers,
            'masters': [],  # Empty for Native zones
            'dnssec': False  # Can be enabled later if needed
        }

        return self._call_api('POST', '/api/v1/servers/localhost/zones', zone_data)

    def delete_zone(self, zone_name: str) -> PowerDNSResult:
        """Delete a DNS zone and all its records"""
        return self._call_api('DELETE', f'/api/v1/servers/localhost/zones/{zone_name}')

    def update_records(self, zone_name: str, rrsets: List[dict]) -> PowerDNSResult:
        """Update DNS records in a zone using RRsets"""
        update_data = {'rrsets': rrsets}
        return self._call_api('PATCH', f'/api/v1/servers/localhost/zones/{zone_name}', update_data)

    def replace_a_record(self, zone_name: str, record_name: str, ip_address: str, ttl: int = 300) -> PowerDNSResult:
        """Replace A record - common operation for failover"""
        rrsets = [{
            'name': record_name,
            'type': 'A',
            'changetype': 'REPLACE',
            'records': [{
                'content': ip_address,
                'disabled': False
            }],
            'ttl': ttl
        }]
        return self.update_records(zone_name, rrsets)

    def bulk_update_records(self, zone_records_map: Dict[str, List[dict]]) -> Dict[str, PowerDNSResult]:
        """Efficiently update records across multiple zones"""
        results = {}
        for zone_name, rrsets in zone_records_map.items():
            try:
                results[zone_name] = self.update_records(zone_name, rrsets)
            except Exception as e:
                results[zone_name] = PowerDNSResult(
                    success=False,
                    status_code=0,
                    message=str(e),
                    error_type=type(e).__name__
                )
        return results

    # Health and Monitoring Methods
    def health_check(self) -> Dict[str, any]:
        """Comprehensive health check of PowerDNS server"""
        health_status = {
            'server_name': self.server.name,
            'hostname': self.server.hostname,
            'healthy': False,
            'checks': {},
            'metrics': {},
            'timestamp': timezone.now().isoformat()
        }

        try:
            # Check 1: API accessibility
            start_time = time.time()
            result = self._call_api('GET', '/api/v1/servers/localhost')
            api_response_time = (time.time() - start_time) * 1000

            if result.success:
                health_status['checks']['api_accessible'] = True
                health_status['metrics']['api_response_time_ms'] = api_response_time
                health_status['version'] = result.data.get('version', 'unknown')
            else:
                health_status['checks']['api_accessible'] = False
                return health_status

            # Check 2: Statistics endpoint
            stats_result = self._call_api('GET', '/api/v1/servers/localhost/statistics')
            if stats_result.success:
                health_status['checks']['statistics_available'] = True
                # Extract key metrics
                for stat in stats_result.data:
                    name = stat['name']
                    value = stat['value']
                    if name in ['uptime', 'qsize-q', 'cache-hit-rate', 'servfail-answers']:
                        health_status['metrics'][name.replace('-', '_')] = value

            # Check 3: Zone count verification
            zones = self.list_zones()
            health_status['checks']['zones_accessible'] = True
            health_status['metrics']['zones_count'] = len(zones)

            # Overall health determination
            critical_checks = ['api_accessible', 'statistics_available', 'zones_accessible']
            health_status['healthy'] = all(health_status['checks'].get(check, False) for check in critical_checks)

        except Exception as e:
            health_status['checks']['error'] = str(e)
            health_status['healthy'] = False

        return health_status
```

### 4. DNS Management Service

```python
# apps/dns/services.py
from typing import List, Dict, Optional
from django.db import transaction
from django.utils import timezone

class PowerDNSService:
    """High-level service for managing DNS operations across multiple PowerDNS servers"""

    def __init__(self):
        self.active_servers = PowerDNSServer.objects.filter(status='healthy')
        self.gateways = {server.id: PowerDNSGateway(server) for server in self.active_servers}

    def create_zone_on_all_servers(self, zone_name: str, nameservers: List[str],
                                  customer: 'Customer' = None) -> Dict[str, PowerDNSResult]:
        """Create zone on all healthy PowerDNS servers"""
        results = {}

        # Create zone in PRAHO database first
        with transaction.atomic():
            zone, created = DNSZone.objects.get_or_create(
                name=zone_name,
                defaults={
                    'kind': 'Native',
                    'customer': customer,
                    'created_by_praho': True
                }
            )

            if not created:
                # Zone already exists in PRAHO
                for server_id in self.gateways.keys():
                    results[f'server_{server_id}'] = PowerDNSResult(
                        success=True,
                        status_code=200,
                        message="Zone already exists in PRAHO database"
                    )
                return results

            # Create initial NS records
            for ns in nameservers:
                DNSRecord.objects.create(
                    zone=zone,
                    name=zone_name,
                    type='NS',
                    content=ns,
                    ttl=86400,
                    managed_by_praho=True
                )

            # Create SOA record
            soa_content = f"ns1.{zone_name} admin.{zone_name} {int(time.time())} 3600 1800 604800 300"
            DNSRecord.objects.create(
                zone=zone,
                name=zone_name,
                type='SOA',
                content=soa_content,
                ttl=86400,
                managed_by_praho=True
            )

        # Create zone on all PowerDNS servers
        for server_id, gateway in self.gateways.items():
            try:
                result = gateway.create_zone(zone_name, nameservers)
                results[f'server_{server_id}'] = result

                if result.success:
                    logger.info(f"Zone {zone_name} created successfully on server {server_id}")
                else:
                    logger.error(f"Failed to create zone {zone_name} on server {server_id}: {result.message}")

            except PowerDNSZoneExists:
                # Zone exists on server but was created in PRAHO - this is OK
                results[f'server_{server_id}'] = PowerDNSResult(
                    success=True,
                    status_code=200,
                    message="Zone already exists on server"
                )
            except Exception as e:
                logger.error(f"Error creating zone {zone_name} on server {server_id}: {str(e)}")
                results[f'server_{server_id}'] = PowerDNSResult(
                    success=False,
                    status_code=0,
                    message=str(e),
                    error_type=type(e).__name__
                )

        return results

    def update_a_record_all_servers(self, zone_name: str, record_name: str,
                                   new_ip: str, ttl: int = 300) -> Dict[str, PowerDNSResult]:
        """Update A record on all servers - primary use case for Virtualmin failover"""
        results = {}

        # Update in PRAHO database first
        with transaction.atomic():
            try:
                zone = DNSZone.objects.get(name=zone_name)
                record, created = DNSRecord.objects.update_or_create(
                    zone=zone,
                    name=record_name,
                    type='A',
                    defaults={
                        'content': new_ip,
                        'ttl': ttl,
                        'managed_by_praho': True
                    }
                )
                logger.info(f"Updated A record {record_name} -> {new_ip} in PRAHO database")

            except DNSZone.DoesNotExist:
                logger.error(f"Zone {zone_name} not found in PRAHO database")
                return {'error': 'Zone not found in PRAHO database'}

        # Update on all PowerDNS servers
        for server_id, gateway in self.gateways.items():
            try:
                result = gateway.replace_a_record(zone_name, record_name, new_ip, ttl)
                results[f'server_{server_id}'] = result

                if result.success:
                    logger.info(f"A record updated successfully on server {server_id}: {record_name} -> {new_ip}")
                else:
                    logger.error(f"Failed to update A record on server {server_id}: {result.message}")

            except Exception as e:
                logger.error(f"Error updating A record on server {server_id}: {str(e)}")
                results[f'server_{server_id}'] = PowerDNSResult(
                    success=False,
                    status_code=0,
                    message=str(e),
                    error_type=type(e).__name__
                )

        return results

    def health_check_all_servers(self) -> Dict[str, Dict]:
        """Perform health checks on all PowerDNS servers"""
        health_results = {}

        for server in PowerDNSServer.objects.all():
            try:
                gateway = PowerDNSGateway(server)
                health_status = gateway.health_check()
                health_results[server.name] = health_status

                # Update server status based on health check
                new_status = 'healthy' if health_status['healthy'] else 'degraded'
                if server.status != new_status:
                    server.status = new_status
                    server.last_health_check = timezone.now()
                    server.save()

                    logger.info(f"Server {server.name} status changed to {new_status}")

            except Exception as e:
                logger.error(f"Health check failed for server {server.name}: {str(e)}")
                health_results[server.name] = {
                    'healthy': False,
                    'error': str(e),
                    'timestamp': timezone.now().isoformat()
                }

                # Mark server as unavailable
                if server.status != 'unavailable':
                    server.status = 'unavailable'
                    server.last_health_check = timezone.now()
                    server.save()

        return health_results

    def sync_zone_to_servers(self, zone_name: str) -> Dict[str, PowerDNSResult]:
        """Sync a zone from PRAHO database to all PowerDNS servers"""
        try:
            zone = DNSZone.objects.get(name=zone_name)
            records = DNSRecord.objects.filter(zone=zone, managed_by_praho=True)

            # Group records by type for efficient RRset operations
            rrsets = {}
            for record in records:
                key = (record.name, record.type)
                if key not in rrsets:
                    rrsets[key] = {
                        'name': record.name,
                        'type': record.type,
                        'changetype': 'REPLACE',
                        'records': [],
                        'ttl': record.ttl
                    }

                rrsets[key]['records'].append({
                    'content': record.content,
                    'disabled': record.disabled
                })

            # Convert to list for API
            rrsets_list = list(rrsets.values())

            # Apply to all servers
            results = {}
            for server_id, gateway in self.gateways.items():
                try:
                    result = gateway.update_records(zone_name, rrsets_list)
                    results[f'server_{server_id}'] = result
                except Exception as e:
                    results[f'server_{server_id}'] = PowerDNSResult(
                        success=False,
                        status_code=0,
                        message=str(e),
                        error_type=type(e).__name__
                    )

            return results

        except DNSZone.DoesNotExist:
            return {'error': f'Zone {zone_name} not found in PRAHO database'}
```

### 5. Server Deployment and Lifecycle Management

```python
# apps/dns/deployment.py
import docker
import paramiko
from typing import Dict, List
from django.conf import settings

class PowerDNSDeployment:
    """Deploy and manage PowerDNS server instances"""

    def __init__(self):
        self.docker_client = docker.from_env()

    def deploy_powerdns_server(self, server_config: Dict) -> Dict[str, any]:
        """Deploy PowerDNS server using Docker"""
        deployment_result = {
            'success': False,
            'server_id': None,
            'container_id': None,
            'error': None,
            'warnings': []
        }

        try:
            # Create PowerDNS server record
            server = PowerDNSServer.objects.create(
                name=server_config['name'],
                hostname=server_config['hostname'],
                ip_address=server_config['ip_address'],
                location=server_config['location'],
                api_key=server_config['api_key'],
                database_host=server_config['database_host'],
                database_name=server_config['database_name'],
                database_user=server_config['database_user'],
                deployed_by_praho=True,
                deployment_config=server_config
            )

            # Docker container configuration
            container_config = {
                'image': 'powerdns/pdns-auth-48:latest',
                'name': f"powerdns-{server.name}",
                'ports': {
                    '53/udp': 53,
                    '53/tcp': 53,
                    '8081/tcp': 8081
                },
                'environment': {
                    'PDNS_api_key': server.api_key,
                    'PDNS_webserver': 'yes',
                    'PDNS_webserver_address': '0.0.0.0',
                    'PDNS_webserver_port': '8081',
                    'PDNS_webserver_allow_from': '0.0.0.0/0',
                    'PDNS_launch': 'gpgsql',
                    'PDNS_gpgsql_host': server.database_host,
                    'PDNS_gpgsql_port': server.database_port,
                    'PDNS_gpgsql_dbname': server.database_name,
                    'PDNS_gpgsql_user': server.database_user,
                    'PDNS_gpgsql_password': server_config['database_password'],
                    'PDNS_version_string': 'powerdns',
                    'PDNS_default_ttl': '300',
                    'PDNS_soa_minimum_ttl': '300',
                    'PDNS_disable_axfr': 'yes'
                },
                'restart_policy': {'Name': 'unless-stopped'},
                'healthcheck': {
                    'test': ['CMD-SHELL', 'pdns_control rping || exit 1'],
                    'interval': 30000000000,  # 30 seconds in nanoseconds
                    'timeout': 10000000000,   # 10 seconds
                    'retries': 3,
                    'start_period': 40000000000  # 40 seconds
                }
            }

            # Deploy container
            container = self.docker_client.containers.run(
                detach=True,
                **container_config
            )

            # Update server record
            server.docker_container_id = container.id
            server.status = 'healthy'
            server.save()

            deployment_result.update({
                'success': True,
                'server_id': server.id,
                'container_id': container.id
            })

            logger.info(f"PowerDNS server {server.name} deployed successfully")

            # Wait for container to be healthy
            self._wait_for_container_health(container, timeout=120)

        except Exception as e:
            logger.error(f"Failed to deploy PowerDNS server: {str(e)}")
            deployment_result['error'] = str(e)

            # Cleanup on failure
            if 'server' in locals():
                server.delete()

        return deployment_result

    def _wait_for_container_health(self, container, timeout: int = 120):
        """Wait for container to become healthy"""
        import time
        start_time = time.time()

        while time.time() - start_time < timeout:
            container.reload()
            health = container.attrs.get('State', {}).get('Health', {})
            status = health.get('Status', 'starting')

            if status == 'healthy':
                logger.info(f"Container {container.name} is healthy")
                return True
            elif status == 'unhealthy':
                logger.error(f"Container {container.name} is unhealthy")
                return False

            time.sleep(5)

        logger.warning(f"Container {container.name} health check timeout")
        return False

    def scale_powerdns_servers(self, target_count: int, locations: List[str]) -> Dict:
        """Scale PowerDNS servers to target count across locations"""
        current_servers = PowerDNSServer.objects.filter(deployed_by_praho=True)
        current_count = current_servers.count()

        scaling_result = {
            'current_count': current_count,
            'target_count': target_count,
            'deployed': [],
            'errors': []
        }

        if target_count > current_count:
            # Scale up
            servers_to_add = target_count - current_count
            for i in range(servers_to_add):
                location = locations[i % len(locations)]

                server_config = {
                    'name': f'powerdns-{location.lower()}-{i+current_count+1}',
                    'hostname': f'ns{i+current_count+1}.praho-dns.ro',
                    'ip_address': self._allocate_ip_address(location),
                    'location': location,
                    'api_key': self._generate_api_key(),
                    'database_host': settings.DNS_DATABASE_HOST,
                    'database_name': settings.DNS_DATABASE_NAME,
                    'database_user': settings.DNS_DATABASE_USER,
                    'database_password': settings.DNS_DATABASE_PASSWORD
                }

                result = self.deploy_powerdns_server(server_config)
                if result['success']:
                    scaling_result['deployed'].append(result['server_id'])
                else:
                    scaling_result['errors'].append(result['error'])

        elif target_count < current_count:
            # Scale down
            servers_to_remove = current_count - target_count
            servers_to_delete = current_servers.order_by('-last_health_check')[:servers_to_remove]

            for server in servers_to_delete:
                try:
                    if server.docker_container_id:
                        container = self.docker_client.containers.get(server.docker_container_id)
                        container.stop()
                        container.remove()

                    server.delete()
                    logger.info(f"Removed PowerDNS server {server.name}")

                except Exception as e:
                    scaling_result['errors'].append(f"Failed to remove server {server.name}: {str(e)}")

        return scaling_result

    def _allocate_ip_address(self, location: str) -> str:
        """Allocate IP address for new server based on location"""
        # This would integrate with your IP management system
        ip_pools = {
            'Bucharest': '10.1.0.',
            'Cluj-Napoca': '10.2.0.',
            'Timișoara': '10.3.0.'
        }

        base_ip = ip_pools.get(location, '10.0.0.')
        # Find next available IP in range
        for i in range(10, 250):
            candidate_ip = f"{base_ip}{i}"
            if not PowerDNSServer.objects.filter(ip_address=candidate_ip).exists():
                return candidate_ip

        raise Exception(f"No available IP addresses in {location}")

    def _generate_api_key(self) -> str:
        """Generate secure API key for PowerDNS"""
        import secrets
        return secrets.token_urlsafe(32)
```

### 6. Health Monitoring and Metrics Collection

```python
# apps/dns/monitoring.py
from django.utils import timezone
from datetime import timedelta
import requests
import logging

logger = logging.getLogger('praho.powerdns.monitoring')

class PowerDNSHealthMonitor:
    """Comprehensive health monitoring for PowerDNS servers"""

    def __init__(self):
        self.dns_service = PowerDNSService()

    def monitor_all_servers(self) -> Dict[str, Dict]:
        """Perform comprehensive monitoring of all PowerDNS servers"""
        monitoring_results = {}

        for server in PowerDNSServer.objects.all():
            try:
                monitor_result = self._monitor_single_server(server)
                monitoring_results[server.name] = monitor_result

                # Update server metrics
                self._store_server_metrics(server, monitor_result)

            except Exception as e:
                logger.error(f"Monitoring failed for server {server.name}: {str(e)}")
                monitoring_results[server.name] = {
                    'healthy': False,
                    'error': str(e),
                    'timestamp': timezone.now().isoformat()
                }

        return monitoring_results

    def _monitor_single_server(self, server: PowerDNSServer) -> Dict:
        """Detailed monitoring of single PowerDNS server"""
        gateway = PowerDNSGateway(server)
        monitor_result = {
            'server_name': server.name,
            'hostname': server.hostname,
            'healthy': False,
            'checks': {},
            'metrics': {},
            'alerts': [],
            'timestamp': timezone.now().isoformat()
        }

        # Check 1: Basic health check via API
        try:
            health_status = gateway.health_check()
            monitor_result['checks'].update(health_status['checks'])
            monitor_result['metrics'].update(health_status['metrics'])
            monitor_result['healthy'] = health_status['healthy']
        except Exception as e:
            monitor_result['checks']['health_check_error'] = str(e)
            monitor_result['alerts'].append(f"Health check failed: {str(e)}")

        # Check 2: DNS query response test
        try:
            response_time = self._test_dns_query(server)
            monitor_result['checks']['dns_query_test'] = response_time is not None
            if response_time:
                monitor_result['metrics']['dns_query_response_time_ms'] = response_time
            else:
                monitor_result['alerts'].append("DNS query test failed")
        except Exception as e:
            monitor_result['checks']['dns_query_test'] = False
            monitor_result['alerts'].append(f"DNS query test error: {str(e)}")

        # Check 3: Zone consistency check
        try:
            consistency_result = self._check_zone_consistency(server)
            monitor_result['checks']['zone_consistency'] = consistency_result['consistent']
            monitor_result['metrics']['zones_in_sync'] = consistency_result['zones_in_sync']
            monitor_result['metrics']['zones_out_of_sync'] = consistency_result['zones_out_of_sync']

            if consistency_result['zones_out_of_sync'] > 0:
                monitor_result['alerts'].append(f"{consistency_result['zones_out_of_sync']} zones out of sync")
        except Exception as e:
            monitor_result['checks']['zone_consistency'] = False
            monitor_result['alerts'].append(f"Zone consistency check failed: {str(e)}")

        # Check 4: Resource utilization (if available)
        try:
            resource_metrics = self._get_resource_metrics(server)
            monitor_result['metrics'].update(resource_metrics)

            # Check for resource alerts
            if resource_metrics.get('memory_usage_percent', 0) > 90:
                monitor_result['alerts'].append("High memory usage (>90%)")
            if resource_metrics.get('cpu_usage_percent', 0) > 80:
                monitor_result['alerts'].append("High CPU usage (>80%)")

        except Exception as e:
            monitor_result['alerts'].append(f"Resource monitoring failed: {str(e)}")

        # Overall health determination
        critical_checks = ['api_accessible', 'dns_query_test', 'zone_consistency']
        monitor_result['healthy'] = all(
            monitor_result['checks'].get(check, False)
            for check in critical_checks
        )

        return monitor_result

    def _test_dns_query(self, server: PowerDNSServer, test_domain: str = 'test.praho.ro') -> Optional[float]:
        """Test DNS query response time"""
        import dns.resolver
        import time

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server.ip_address]
            resolver.timeout = 5

            start_time = time.time()
            answer = resolver.resolve(test_domain, 'A')
            response_time = (time.time() - start_time) * 1000

            return response_time if answer else None

        except Exception:
            return None

    def _check_zone_consistency(self, server: PowerDNSServer) -> Dict:
        """Check if server zones are consistent with PRAHO database"""
        gateway = PowerDNSGateway(server)

        # Get zones from PRAHO database
        praho_zones = set(DNSZone.objects.values_list('name', flat=True))

        # Get zones from PowerDNS server
        try:
            server_zones = set(zone['name'] for zone in gateway.list_zones())
        except Exception:
            return {'consistent': False, 'zones_in_sync': 0, 'zones_out_of_sync': 0}

        zones_in_sync = len(praho_zones.intersection(server_zones))
        zones_out_of_sync = len(praho_zones.symmetric_difference(server_zones))

        return {
            'consistent': zones_out_of_sync == 0,
            'zones_in_sync': zones_in_sync,
            'zones_out_of_sync': zones_out_of_sync,
            'missing_on_server': list(praho_zones - server_zones),
            'extra_on_server': list(server_zones - praho_zones)
        }

    def _get_resource_metrics(self, server: PowerDNSServer) -> Dict:
        """Get resource utilization metrics from server"""
        # This would integrate with your monitoring system (Prometheus, etc.)
        # For now, return mock data
        return {
            'memory_usage_percent': 45.2,
            'cpu_usage_percent': 23.1,
            'disk_usage_percent': 67.8,
            'network_connections': 1234
        }

    def _store_server_metrics(self, server: PowerDNSServer, monitor_result: Dict):
        """Store monitoring results as metrics"""
        try:
            PowerDNSServerMetrics.objects.create(
                server=server,
                queries_per_second=monitor_result['metrics'].get('qsize_q', 0),
                cache_hit_rate=monitor_result['metrics'].get('cache_hit_rate', 0),
                response_time_ms=monitor_result['metrics'].get('dns_query_response_time_ms', 0),
                cpu_usage_percent=monitor_result['metrics'].get('cpu_usage_percent', 0),
                memory_usage_mb=monitor_result['metrics'].get('memory_usage_mb', 0),
                zones_count=monitor_result['metrics'].get('zones_count', 0),
                records_count=monitor_result['metrics'].get('records_count', 0)
            )
        except Exception as e:
            logger.error(f"Failed to store metrics for server {server.name}: {str(e)}")

# Celery task for periodic monitoring
@shared_task
def monitor_powerdns_servers():
    """Periodic monitoring task"""
    monitor = PowerDNSHealthMonitor()
    results = monitor.monitor_all_servers()

    # Log summary
    healthy_count = sum(1 for result in results.values() if result.get('healthy', False))
    total_count = len(results)

    logger.info(f"PowerDNS monitoring completed: {healthy_count}/{total_count} servers healthy")

    # Send alerts for unhealthy servers
    for server_name, result in results.items():
        if not result.get('healthy', False) and result.get('alerts'):
            send_powerdns_alert.delay(server_name, result['alerts'])

    return results

@shared_task
def send_powerdns_alert(server_name: str, alerts: List[str]):
    """Send alert notifications for PowerDNS issues"""
    # Integrate with your notification system
    logger.warning(f"PowerDNS alerts for {server_name}: {', '.join(alerts)}")
```

### 7. Integration with Virtualmin Traffic Management

```python
# apps/dns/virtualmin_integration.py
from apps.provisioning.models import VirtualminAccount, VirtualminServer

class VirtualminDNSIntegration:
    """Integration between PowerDNS and Virtualmin for traffic management"""

    def __init__(self):
        self.powerdns_service = PowerDNSService()

    def handle_virtualmin_server_failover(self, failed_server: VirtualminServer,
                                        replacement_server: VirtualminServer) -> Dict:
        """Update DNS records when Virtualmin server fails over"""
        affected_accounts = VirtualminAccount.objects.filter(
            virtualmin_server=failed_server,
            status='active'
        )

        dns_updates = {}
        for account in affected_accounts:
            domain = account.virtualmin_domain
            new_ip = replacement_server.ip_address

            # Update A records for domain and www subdomain
            results = self.powerdns_service.update_a_record_all_servers(
                zone_name=f"{domain}.",
                record_name=f"{domain}.",
                new_ip=new_ip,
                ttl=300  # Short TTL for faster failover
            )
            dns_updates[domain] = results

            # Also update www record
            www_results = self.powerdns_service.update_a_record_all_servers(
                zone_name=f"{domain}.",
                record_name=f"www.{domain}.",
                new_ip=new_ip,
                ttl=300
            )
            dns_updates[f"www.{domain}"] = www_results

            logger.info(f"Updated DNS for {domain} -> {new_ip} during Virtualmin failover")

        return {
            'affected_domains': len(affected_accounts),
            'dns_updates': dns_updates,
            'failed_server': failed_server.hostname,
            'replacement_server': replacement_server.hostname
        }

    def provision_domain_dns(self, account: VirtualminAccount) -> Dict:
        """Provision DNS for new Virtualmin account"""
        domain = account.virtualmin_domain
        server_ip = account.virtualmin_server.ip_address

        # Create zone if it doesn't exist
        nameservers = [
            'ns1.praho-hosting.ro.',
            'ns2.praho-hosting.ro.'
        ]

        zone_results = self.powerdns_service.create_zone_on_all_servers(
            zone_name=f"{domain}.",
            nameservers=nameservers,
            customer=account.service.customer
        )

        # Create A records
        a_record_results = self.powerdns_service.update_a_record_all_servers(
            zone_name=f"{domain}.",
            record_name=f"{domain}.",
            new_ip=server_ip,
            ttl=300
        )

        www_record_results = self.powerdns_service.update_a_record_all_servers(
            zone_name=f"{domain}.",
            record_name=f"www.{domain}.",
            new_ip=server_ip,
            ttl=300
        )

        return {
            'zone_creation': zone_results,
            'a_record_creation': a_record_results,
            'www_record_creation': www_record_results
        }
```

### 8. Production Configuration

```python
# config/settings/production.py

# PowerDNS Configuration
POWERDNS_CONFIG = {
    'DATABASE_CONFIG': {
        'HOST': env('DNS_DATABASE_HOST', default='localhost'),
        'PORT': env('DNS_DATABASE_PORT', default=5432),
        'NAME': env('DNS_DATABASE_NAME', default='powerdns'),
        'USER': env('DNS_DATABASE_USER', default='powerdns'),
        'PASSWORD': env('DNS_DATABASE_PASSWORD'),
    },
    'DEFAULT_NAMESERVERS': [
        'ns1.praho-hosting.ro.',
        'ns2.praho-hosting.ro.',
        'ns3.praho-hosting.ro.'
    ],
    'MONITORING': {
        'HEALTH_CHECK_INTERVAL': 300,  # 5 minutes
        'METRICS_RETENTION_DAYS': 30,
        'ALERT_THRESHOLDS': {
            'RESPONSE_TIME_MS': 5000,
            'MEMORY_USAGE_PERCENT': 90,
            'CPU_USAGE_PERCENT': 80,
            'ZONES_OUT_OF_SYNC': 0
        }
    },
    'DEPLOYMENT': {
        'DOCKER_IMAGE': 'powerdns/pdns-auth-48:latest',
        'DEFAULT_LOCATIONS': ['Bucharest', 'Cluj-Napoca', 'Timișoara'],
        'MIN_SERVERS': 2,
        'MAX_SERVERS': 10
    },
    'API_SETTINGS': {
        'REQUEST_TIMEOUT': 30,
        'MAX_RETRIES': 3,
        'RATE_LIMIT_QPS': 100,  # Conservative for production
        'CIRCUIT_BREAKER_THRESHOLD': 5
    }
}

# Celery configuration for PowerDNS tasks
CELERY_ROUTES.update({
    'apps.dns.monitoring.monitor_powerdns_servers': {'queue': 'powerdns_monitoring'},
    'apps.dns.monitoring.send_powerdns_alert': {'queue': 'powerdns_alerts'},
    'apps.dns.services.sync_zone_to_servers': {'queue': 'powerdns_sync'},
})

# Database configuration for PowerDNS shared database
DATABASES['powerdns'] = {
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': POWERDNS_CONFIG['DATABASE_CONFIG']['NAME'],
    'USER': POWERDNS_CONFIG['DATABASE_CONFIG']['USER'],
    'PASSWORD': POWERDNS_CONFIG['DATABASE_CONFIG']['PASSWORD'],
    'HOST': POWERDNS_CONFIG['DATABASE_CONFIG']['HOST'],
    'PORT': POWERDNS_CONFIG['DATABASE_CONFIG']['PORT'],
    'OPTIONS': {
        'connect_timeout': 10,
    }
}

# Database routing for PowerDNS models
class PowerDNSDatabaseRouter:
    """Route PowerDNS models to separate database"""

    route_app_labels = ['dns']

    def db_for_read(self, model, **hints):
        if model._app_label in self.route_app_labels:
            return 'powerdns'
        return None

    def db_for_write(self, model, **hints):
        if model._app_label in self.route_app_labels:
            return 'powerdns'
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in self.route_app_labels:
            return db == 'powerdns'
        elif db == 'powerdns':
            return False
        return None

DATABASE_ROUTERS = ['config.settings.production.PowerDNSDatabaseRouter']
```

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
1. **Database Setup**: Create PowerDNS database schema compatible with PRAHO models
2. **Basic Gateway**: Implement PowerDNSGateway with essential API calls
3. **Health Monitoring**: Basic health check functionality
4. **Unit Tests**: Comprehensive test suite for gateway and models

### Phase 2: Core Integration (Weeks 3-4)
1. **Multi-Server Management**: Deploy multiple PowerDNS instances
2. **DNS Service**: Complete PowerDNSService with zone/record management
3. **Database Replication**: Set up PostgreSQL replication for high availability
4. **Monitoring System**: Full health monitoring with metrics collection

### Phase 3: Advanced Features (Weeks 5-6)
1. **Virtualmin Integration**: DNS updates during Virtualmin failover
2. **Auto-Deployment**: Automated PowerDNS server deployment
3. **Performance Optimization**: Bulk operations and connection pooling
4. **Production Hardening**: Security, monitoring, and error handling

### Phase 4: CloudFlare Integration (Weeks 7-8)
1. **CloudFlare Gateway**: Implement CloudFlare API integration
2. **Hybrid DNS Management**: PowerDNS + CloudFlare coordination
3. **Customer Choice**: Allow customers to choose DNS provider
4. **Migration Tools**: Migrate existing DNS to PowerDNS/CloudFlare

## Success Metrics

- **DNS Response Time**: < 50ms average for PowerDNS servers
- **Availability**: 99.9% uptime for DNS infrastructure
- **Failover Speed**: < 5 minutes for complete DNS propagation during Virtualmin failover
- **Scalability**: Handle 1M+ queries per day across server cluster
- **Management Efficiency**: 90% reduction in manual DNS management tasks

## Conclusion

This PowerDNS integration provides PRAHO with enterprise-grade DNS management capabilities while maintaining the "cattle, not pets" philosophy. The architecture supports Romanian hosting providers' needs for cost-effective, scalable, and reliable DNS infrastructure.

The combination of modern HTTP APIs, database-driven architecture, and comprehensive monitoring creates a robust foundation for DNS-based traffic management and failover scenarios with Virtualmin servers.

---

*Document created by: Senior Technical Architecture Team*
*Last updated: 2024-09-01*
*Next review: 2024-10-01*
*Integration Target: PowerDNS Authoritative Server*
*Market Focus: Romanian hosting providers*
*Architecture: Multi-server, database-driven, API-first*
