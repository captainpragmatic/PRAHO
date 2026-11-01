#!/usr/bin/env python3
"""Qualify an explicitly prepared neutral source default without changing global bindings."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any


def _apache() -> Any:
    spec = importlib.util.spec_from_file_location(
        "component_default_bindings", Path(__file__).with_name("praho-apache-bindings.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("Source default frontend qualification is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


apache = _apache()
MAX_PROBE_OUTPUT = 1024
PREPARATION = (
    "Explicitly prepare and verify PRAHO's neutral default frontend and current Apache bindings before migration; "
    "unclaimed hostnames must return404 while named websites and retained services remain available."
)


def command(arguments: list[str]) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, check=True, timeout=10)  # noqa: S603 -- fixed local probes
    if len(result.stdout) > MAX_PROBE_OUTPUT:
        raise ValueError("Source default frontend proof exceeds its bound")
    return result.stdout


def qualify_default(
    root: Path = Path("/"),
    *,
    policy: Any = None,
    execute: Callable[[list[str]], str] = command,
) -> list[str]:
    bindings = policy if policy is not None else apache.ApacheBindings(root, owner_uid=os.geteuid())
    default = root / "etc/apache2/conf-enabled/praho-default-site.conf"
    try:
        target = default.resolve(strict=True)
        if target.parent not in {root / "etc/apache2/conf-enabled", root / "etc/apache2/conf-available"}:
            raise ValueError("The neutral source default is outside its protected native configuration directories")
        if b"ServerName praho-default.invalid" not in bindings.read(target, 0o644):
            raise ValueError("The native source has no prepared neutral default")
        groups = bindings.current()
        if groups != bindings.observed() or bindings.read(bindings.configuration, 0o644) != bindings.render(groups):
            raise ValueError("Source neutral bindings need explicit preparation before a component hold")
        probes = 0
        for scheme, port in (("http", "80"), ("https", "443")):
            addresses = bindings.probe_addresses(groups, port)
            if not addresses:
                raise ValueError("The prepared source default has no qualified local listener")
            for address in addresses:
                arguments = [
                    "/usr/bin/curl",
                    "--silent",
                    "--show-error",
                    "--noproxy",
                    "*",
                    "--connect-timeout",
                    "2",
                    "--max-time",
                    "5",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    "--header",
                    "Host: praho-unclaimed.invalid",
                ]
                if scheme == "https":
                    arguments.append("--insecure")  # The prepared neutral default uses the native snakeoil certificate.
                arguments.append(scheme + "://" + bindings.endpoint(address, port) + "/")
                if execute(arguments).strip() != "404":
                    raise ValueError("The prepared source default does not independently return404")
                probes += 1
        if not probes:
            raise ValueError("No actual default frontend proof was available")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return [PREPARATION]
    return []
