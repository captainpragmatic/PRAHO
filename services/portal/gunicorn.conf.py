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
``apps.common.outbound_http`` keeps one ``requests.Session`` per thread
for HTTP keep-alive connection reuse against the Platform API.
Gunicorn's pre-fork model means a Session created in the parent process
(and any sockets it pooled) would be inherited by every worker, which can
cause cross-worker socket sharing.

Today the portal does not issue any outbound HTTP before the fork, so no
sockets are open then. The ``post_fork`` hook below is defense-in-depth:
it forgets every Session in each new worker, so even if a future warmup
import opens connections, each worker starts with a clean slate.
PR #164 review M1.
"""

from __future__ import annotations

from typing import Any


def post_fork(server: Any, worker: Any) -> None:
    """Forget every outbound Session in the newly forked worker.

    The `server` and `worker` args are part of gunicorn's hook contract;
    the hook is invoked positionally so we accept them as Any.
    """
    del server, worker  # Unused — required by gunicorn's hook signature.
    # Lazy import, so the master never imports application code. post_fork runs
    # in the worker before gunicorn loads the WSGI app, so Django is not set up
    # yet; outbound_http only touches settings when a call is made.
    from apps.common import outbound_http  # noqa: PLC0415

    outbound_http.reset_after_fork()
