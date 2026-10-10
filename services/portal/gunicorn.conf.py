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

import os
from typing import Any

from config.server_settings import server_settings

# Server settings come from PORTAL_GUNICORN_* (config/server_settings.py). The launchers pass only
# the bind address, since a command-line flag would override these. gunicorn ignores a name it does
# not know, so tests/common/test_server_settings.py checks what gunicorn itself reads from here.
_settings = server_settings()
worker_class = _settings["worker_class"]
workers = _settings["workers"]
threads = _settings["threads"]
worker_connections = _settings["worker_connections"]
keepalive = _settings["keepalive"]
timeout = _settings["timeout"]
graceful_timeout = _settings["graceful_timeout"]
if os.access("/dev/shm", os.W_OK):  # noqa: S108  # a RAM-backed heartbeat file, as gunicorn recommends
    worker_tmp_dir = "/dev/shm"  # noqa: S108
# Access and error logs on stdout/stderr, for journald and docker logs alike.
accesslog = "-"
errorlog = "-"
# gunicorn's default line, plus the duration (%(D)s, microseconds), worker pid and request id. The
# request id is "-" on a response refused before the request-id middleware ran (an early 429, say).
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sus pid=%(p)s rid=%({x-request-id}o)s'
)


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
