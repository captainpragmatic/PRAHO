"""
Fixture factories for Virtualmin info (server info) responses.
"""

from __future__ import annotations

from typing import Any


def server_info(
    hostname: str = "server1.example.com",
    os_type: str = "Ubuntu Linux 22.04",
    webmin_version: str = "2.105",
    virtualmin_version: str = "7.10.0",
    load_average: str = "0.15 0.10 0.05",
    real_memory: str = "8192 MB total, 4096 MB used",
    virtual_memory: str = "4096 MB total, 512 MB used",
    disk_space: str = "500 GB total, 200 GB used",
    uptime: str = "45 days, 3:22",
) -> dict[str, Any]:
    """Successful server info response."""
    return {
        "command": "info",
        "status": "success",
        "data": {
            "hostname": hostname,
            "os_type": os_type,
            "webmin_version": webmin_version,
            "virtualmin_version": virtualmin_version,
            "load_averages": load_average,
            "real_memory": real_memory,
            "virtual_memory": virtual_memory,
            "local_disk_space": disk_space,
            "system_uptime": uptime,
        },
    }
