"""
Gunicorn configuration for the PRAHO Portal service.

Auto-loaded by gunicorn from the working directory when no ``-c`` /
``--config`` flag is passed. The Docker entrypoint
(``deploy/portal/entrypoint.sh``) and the Ansible systemd unit
(``deploy/ansible/roles/praho-native/templates/praho-portal.service.j2``)
both ``cd`` into ``services/portal/`` (or copy this file to ``/app/``)
before invoking gunicorn, so this module is auto-discovered.

Why this file exists
--------------------
``apps.common.outbound_http`` keeps a module-level ``requests.Session``
for HTTP keep-alive connection reuse against the Platform API.
Gunicorn's pre-fork model means the parent process loads the module
(creating the Session and any associated connection pools) before
forking workers — children inherit the Session object and the
underlying file descriptors, which can cause cross-worker socket
sharing if connections are established before the fork.

Today the portal does not issue any outbound HTTP at import time, so
no sockets are open at fork time. The ``post_fork`` hook below is
defense-in-depth: it resets ``_session`` per worker so that even if
a future warmup import opens connections, each worker starts with a
clean slate. PR #164 review M1.
"""

from __future__ import annotations

from typing import Any


def post_fork(server: Any, worker: Any) -> None:
    """Reset the shared requests.Session per worker post-fork.

    Clears cookies and re-mounts adapters so each worker holds its own
    connection pool. Headers (User-Agent) are preserved.

    The `server` and `worker` args are part of gunicorn's hook contract;
    the hook is invoked positionally so we accept them as Any.
    """
    del server, worker  # Unused — required by gunicorn's hook signature.
    # Lazy import: gunicorn.conf.py is loaded by the master before any
    # Django setup; importing apps.common.outbound_http here would force
    # Django to initialize in the master process. Doing it inside the
    # hook means it runs after the worker has been forked and Django
    # has been set up by gunicorn's WSGI loader.
    import requests  # noqa: PLC0415

    from apps.common import outbound_http  # noqa: PLC0415

    outbound_http._session.cookies.clear()
    outbound_http._session.adapters.clear()
    outbound_http._session.mount("http://", requests.adapters.HTTPAdapter())
    outbound_http._session.mount("https://", requests.adapters.HTTPAdapter())
