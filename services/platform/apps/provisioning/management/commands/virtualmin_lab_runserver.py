"""Run the Platform development server against the Docker Virtualmin lab (lab only).

The lab nodes are published on 127.0.0.1 under distinct ports, so a bare `runserver` cannot reach them:
PRAHO's SSRF guard refuses a loopback API host, and Ansible and the SSH probes assume port 22. The
adaptations live in `lab_transport()`, which patches the running process. This command enters it and then
hands over to Django's own `runserver`, in the same process, so every request the server handles (a staff
action that calls a node, a health check, a backup job) goes through the lab transport.

    manage.py virtualmin_lab_runserver 127.0.0.1:8700 --noreload

The lab has no Django-Q cluster either: its worker processes are spawned and would lose the transport. A
worker thread inside this process takes the hosting tasks the server queues (a backup, a migration, a
suspension, a retry) from the ORM broker and runs them through `run_queued_once`, so a job started in the
browser really runs against the nodes and its status page moves on.

Refuses to run unless DJANGO_SETTINGS_MODULE=config.settings.lab and DEBUG (see `refuse_unless_lab_settings`).
"""

from __future__ import annotations

import logging
import os
import threading
from argparse import ArgumentParser
from typing import Any

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import close_old_connections

from apps.provisioning.management.commands._virtualmin_lab import (
    enable_lab_features,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
    run_queued_once,
)

logger = logging.getLogger(__name__)

WORKER_POLL_SECONDS = 1.0


def _work(stop: threading.Event) -> None:
    """Run queued hosting tasks until `stop` is set."""
    while not stop.is_set():
        try:
            run_queued_once()
        except Exception:  # A broken pass must not end the worker: the next poll tries again
            logger.exception("🔥 [VirtualminLab] worker pass failed")
        finally:
            close_old_connections()
        stop.wait(WORKER_POLL_SECONDS)


class Command(BaseCommand):
    help = "Run runserver inside the Virtualmin lab transport (lab settings only)"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("addrport", nargs="?", default="127.0.0.1:8700", help="Address and port, as for runserver")
        parser.add_argument("--noreload", action="store_true", help="Do not use the auto-reloader")
        parser.add_argument(
            "--features", action="store_true", help="Switch on migration, drain and differential backups first"
        )
        parser.add_argument("--no-worker", action="store_true", help="Do not run queued tasks in this process")

    def handle(self, *args: Any, **options: Any) -> None:
        refuse_unless_lab_settings()
        if options["features"]:
            enable_lab_features()
        runserver_args = [options["addrport"]]
        if options["noreload"]:
            runserver_args.append("--noreload")
        stop = threading.Event()
        # Under the auto-reloader the outer process only supervises: the serving child (RUN_MAIN) works the queue.
        serving = options["noreload"] or os.environ.get("RUN_MAIN") == "true"
        worker = None
        if serving and not options["no_worker"]:
            worker = threading.Thread(target=_work, args=(stop,), name="virtualmin-lab-worker", daemon=True)
        with lab_transport(load_state()):
            if worker is not None:
                worker.start()
            try:
                call_command("runserver", *runserver_args)
            finally:
                stop.set()
