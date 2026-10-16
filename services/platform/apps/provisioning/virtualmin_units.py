"""Virtualmin quota units, shared by every call that sets a quota.

Virtualmin takes a disk quota in KiB and a bandwidth limit in bytes. PRAHO stores both in MiB.
Zero means unlimited, and the account's -1 bandwidth sentinel is unlimited too, so it is sent as 0
(Virtualmin would read a negative number as an invalid limit).
"""

from __future__ import annotations

_KIB_PER_MIB = 1024
_BYTES_PER_MIB = 1024 * 1024


def quota_parameters(disk_quota_mb: int | None, bandwidth_quota_mb: int | None) -> dict[str, str]:
    """The ``quota`` and ``bandwidth`` parameters for create-domain and modify-domain; unset quotas are omitted."""
    params: dict[str, str] = {}
    if disk_quota_mb is not None:
        params["quota"] = str(disk_quota_mb * _KIB_PER_MIB)
    if bandwidth_quota_mb is not None:
        params["bandwidth"] = str(max(0, bandwidth_quota_mb) * _BYTES_PER_MIB)
    return params


def modify_quota_parameters(disk_quota_mb: int | None, bandwidth_quota_mb: int | None) -> dict[str, str]:
    """The same quotas for modify-domain, which names the bandwidth limit ``bw``.

    create-domain takes ``--bandwidth``. modify-domain takes ``--bw`` and refuses ``--bandwidth``
    ("Unknown parameter", Virtualmin 8.3), which discards the disk quota sent alongside it too.
    """
    params = quota_parameters(disk_quota_mb, bandwidth_quota_mb)
    if "bandwidth" in params:
        params["bw"] = params.pop("bandwidth")
    return params
