"""What a contract test uses to talk to the lab node and to say what it expects.

A test sends PRAHO's own parameters through the production `VirtualminGateway` to the real node,
then checks the three things the rest of PRAHO decides on: `has_explicit_success`,
`explicit_rejection`, and the read-only replay classification (plus the retriability of a refusal).
Every exchange is also handed to the recorder, which writes the sanitised golden responses that
the platform tests replay (see `RecordedVirtualminGateway`).

Nothing here skips. A test that cannot reach the lab fails with the reason.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar
from unittest.mock import patch

import requests

from apps.common.types import Result, Retriability
from apps.provisioning.management.commands._virtualmin_lab import LabNode
from apps.provisioning.virtualmin_gateway import (
    VirtualminAPIError,
    VirtualminConfig,
    VirtualminGateway,
    VirtualminResponse,
    classify_virtualmin_application_error,
    explicit_rejection,
    has_explicit_success,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_validators import is_virtualmin_read_only_program
from tests.virtualmin_lab.sanitise import sanitise_body, sanitise_params, sanitise_value

F = TypeVar("F", bound=Callable[..., Any])
T = TypeVar("T")

SANDBOX_DOMAIN = "contract.praho.test"
SANDBOX_USER = "contract"
# Leftovers of an interrupted run are domains named like this and nothing else.
CONTRACT_DOMAIN = re.compile(r"^contract[a-z0-9-]*\.praho\.test$")
# The slowest commands get the budget production gives them (backup/restore: provisioning.migration_backup_timeout_seconds).
BACKUP_TIMEOUT = 1800
DELETE_TIMEOUT = 120


def covers(program: str) -> Callable[[F], F]:
    """Mark the test that holds the contract of one allowlisted program.

    The coverage guard (tests/integration/test_virtualmin_actions_covered.py) reads this decorator from the
    source, so the argument must be a string literal.
    """

    def mark(test: F) -> F:
        vars(test)["__virtualmin_program__"] = program
        return test

    return mark


@dataclass(frozen=True)
class Exchange:
    """One call through the gateway and what the node answered."""

    program: str
    params: dict[str, Any]
    result: Result[VirtualminResponse, VirtualminAPIError]
    http_status: int | None
    body: str

    @property
    def response(self) -> VirtualminResponse:
        assert self.result.is_ok(), f"{self.program}: no response, {self.result.unwrap_err()}"
        return self.result.unwrap()

    @property
    def rejection(self) -> str | None:
        """The text `explicit_rejection` extracts, exactly as the callers hand it the response."""
        return explicit_rejection(self.response.raw_response)

    @property
    def classification(self) -> dict[str, Any]:
        response = self.response
        return {
            "success": response.success,
            "explicit_success": has_explicit_success(response),
            "explicit_rejection": explicit_rejection(response.raw_response),
            "retriability": None if response.success else classify_virtualmin_application_error(response).value,
            "read_only": is_virtualmin_read_only_program(self.program),
        }


class RecordingGateway(VirtualminGateway):
    """The production gateway, with the HTTP answer of every call kept beside the parsed one.

    Only the transport seam is wrapped; parsing, normalisation, retries and rate limits are production's.
    """

    def __init__(self, config: VirtualminConfig) -> None:
        super().__init__(config)
        self.exchanges: list[Exchange] = []
        self._answers: list[requests.Response] = []

    def _execute_http_request(
        self,
        params: dict[str, Any],
        auth: tuple[str, str] | None = None,
        timeout_seconds: int | None = None,
        deadline: float | None = None,
    ) -> requests.Response:
        response = super()._execute_http_request(
            params, auth=auth, timeout_seconds=timeout_seconds, deadline=deadline
        )
        self._answers.append(response)
        return response

    def call(  # noqa: PLR0913  # The production signature, unchanged
        self,
        program: str,
        params: dict[str, Any] | None = None,
        response_format: str = "json",
        correlation_id: str = "",
        timeout_seconds: int | None = None,
        *,
        deadline: float | None = None,
    ) -> Result[VirtualminResponse, VirtualminAPIError]:
        mark = len(self._answers)
        result = super().call(
            program, params, response_format, correlation_id, timeout_seconds=timeout_seconds, deadline=deadline
        )
        answer = self._answers[-1] if len(self._answers) > mark else None
        self.exchanges.append(
            Exchange(
                program=program,
                params=dict(params or {}),
                result=result,
                http_status=answer.status_code if answer is not None else None,
                body=answer.text if answer is not None else "",
            )
        )
        return result


@dataclass
class Recorder:
    """Collects the exchanges tests mark for recording and writes one file per program."""

    version: str
    directory: Path | None
    cases: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)

    def add(self, exchange: Exchange, case: str, note: str) -> None:
        program_cases = self.cases.setdefault(exchange.program, {})
        assert case not in program_cases, f"{exchange.program}: case {case!r} recorded twice"
        body = sanitise_body(exchange.body)
        program_cases[case] = {
            "note": note,
            "params": sanitise_params(exchange.params),
            "http_status": exchange.http_status,
            "body_format": "json" if isinstance(body, dict) else "text",
            "body": body,
            "classification": sanitise_value(exchange.classification),
        }

    def write(self) -> list[Path]:
        if self.directory is None:
            return []
        target = self.directory / self.version
        target.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for program, cases in sorted(self.cases.items()):
            path = target / f"{program}.json"
            document = {"program": program, "virtualmin_version": self.version, "cases": cases}
            path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
            written.append(path)
        return written


class Lab:
    """The lab node as a contract test sees it."""

    def __init__(
        self, gateway: RecordingGateway, node: LabNode, server: VirtualminServer, recorder: Recorder, password: str
    ) -> None:
        self.gateway = gateway
        self.node = node
        self.server = server
        self.recorder = recorder
        self.password = password

    # ---------------------------------------------------------------- calls

    def call(
        self,
        program: str,
        params: dict[str, Any],
        *,
        case: str,
        note: str = "",
        timeout_seconds: int | None = None,
    ) -> Exchange:
        """Call the node as PRAHO does and record the answer under `case`."""
        exchange = self.quiet(program, params, timeout_seconds=timeout_seconds)
        self.recorder.add(exchange, case, note)
        return exchange

    def quiet(self, program: str, params: dict[str, Any], *, timeout_seconds: int | None = None) -> Exchange:
        """A call that is set-up or evidence, not a contract case: it is not recorded."""
        self.gateway.call(program, params, timeout_seconds=timeout_seconds)
        return self.gateway.exchanges[-1]

    def produced_by(self, gateway_class: str, run: Callable[[], object]) -> list[Exchange]:
        """Run PRAHO code that builds its own gateway, through this one, and return what it sent.

        `gateway_class` is the dotted name of the `VirtualminGateway` that module constructs. The code
        under test keeps its real parameter building; only the object it talks through is the lab's.
        """
        mark = len(self.gateway.exchanges)
        with patch(gateway_class, return_value=self.gateway):
            run()
        return self.gateway.exchanges[mark:]

    def observe(self, run: Callable[[RecordingGateway], T]) -> tuple[T, list[Exchange]]:
        """Run a production gateway method and return its value with the exchanges it made."""
        mark = len(self.gateway.exchanges)
        value = run(self.gateway)
        return value, self.gateway.exchanges[mark:]

    def record(self, exchange: Exchange, case: str, note: str = "") -> None:
        self.recorder.add(exchange, case, note)

    def exec(self, *argv: str) -> str:
        """Run a command on the lab node and return stdout; a failure is a failed test."""
        return self.exec_on(self.node.container, *argv)

    def exec_on(self, container: str, *argv: str) -> str:
        """Run a command in any lab container (the other node, for a transfer) and return stdout."""
        completed = subprocess.run(  # noqa: S603  # Fixed argv against a local lab container
            ["docker", "exec", container, *argv],  # noqa: S607  # docker from PATH, dev-only
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert completed.returncode == 0, f"{' '.join(argv)}: {completed.stderr.strip() or completed.stdout.strip()}"
        return completed.stdout

    # ---------------------------------------------------------- node state

    def domain_names(self) -> list[str]:
        listing = self.quiet("list-domains", {"name-only": ""})
        assert_accepted(listing)
        return [row["name"] for row in listing.response.data["data"]]

    def domain_exists(self, domain: str) -> bool:
        return domain in self.domain_names()

    def domain_values(self, domain: str) -> dict[str, Any]:
        """The `--multiline` attributes of one domain, as the gateway's own listing helpers read them."""
        listing = self.quiet("list-domains", {"domain": domain, "multiline": ""})
        assert_accepted(listing)
        rows = [row for row in listing.response.data["data"] if row.get("name") == domain]
        assert len(rows) == 1, f"{domain}: {rows}"
        values: dict[str, Any] = rows[0]["values"]
        return values

    def create_domain(self, domain: str, user: str) -> None:
        """A domain made with PRAHO's own create-domain parameters (set-up, not a contract case)."""
        from apps.provisioning.virtualmin_service import create_domain_params  # noqa: PLC0415

        created = self.quiet(
            "create-domain",
            create_domain_params(
                domain=domain,
                username=user,
                password=self.password,
                template="Default Settings",
                recovery_seed="contract-recovery-seed",
                disk_quota_mb=1024,
                bandwidth_quota_mb=10240,
            ),
        )
        assert_accepted(created)

    def remove_domain(self, domain: str) -> None:
        if self.domain_exists(domain):
            deleted = self.quiet("delete-domain", {"domain": domain}, timeout_seconds=DELETE_TIMEOUT)
            assert_accepted(deleted)

    def remove_leftovers(self) -> None:
        for name in self.domain_names():
            if CONTRACT_DOMAIN.match(name):
                self.remove_domain(name)

    @contextmanager
    def domain(self, name: str, user: str) -> Iterator[str]:
        """A scratch domain that exists inside the block and is gone after it, whatever the test did."""
        self.remove_domain(name)
        self.create_domain(name, user)
        try:
            yield name
        finally:
            self.remove_domain(name)

    def fingerprint(self) -> str:
        """The node state a read-only command must not change, as sanitised JSON."""
        state: dict[str, Any] = {}
        for label, program, params in (
            ("domains", "list-domains", {"multiline": ""}),
            ("users", "list-users", {"domain": SANDBOX_DOMAIN}),
            ("databases", "list-databases", {"domain": SANDBOX_DOMAIN, "name-only": ""}),
        ):
            exchange = self.quiet(program, params)
            state[label] = sanitise_body(exchange.body)
        return json.dumps(state, sort_keys=True)

    def prove_read_only(self, program: str, run: Callable[[], T]) -> T:
        """`program` is in the read-only set and `run` leaves the node exactly as it found it."""
        assert is_virtualmin_read_only_program(program), f"{program} is not in VIRTUALMIN_READ_ONLY_PROGRAMS"
        before = self.fingerprint()
        value = run()
        after = self.fingerprint()
        assert before == after, f"{program} changed the node state"
        return value


def assert_mutating(program: str) -> None:
    """`program` is not in the read-only set, so an ambiguous outcome is never replayed."""
    assert not is_virtualmin_read_only_program(program), f"{program} is in VIRTUALMIN_READ_ONLY_PROGRAMS"


def assert_accepted(exchange: Exchange) -> None:
    """The node ran the command and PRAHO sees an explicit synchronous success."""
    response = exchange.response
    assert exchange.http_status == 200, exchange.http_status
    assert response.success, exchange.body[:500]
    assert has_explicit_success(response), exchange.body[:500]
    assert explicit_rejection(response.raw_response) is None, exchange.body[:500]


def assert_refused(exchange: Exchange, *, error: str, retriability: Retriability, exact: bool = False) -> None:
    """The node refused the command, and PRAHO reads the refusal as a definite one.

    A refusal is HTTP 200 with a failure envelope: `success` is False, there is no explicit success,
    `explicit_rejection` carries Virtualmin's own text (the evidence callers need before they compensate),
    and the application error classifies as `retriability`.
    """
    response = exchange.response
    assert exchange.http_status == 200, exchange.http_status
    assert not response.success, exchange.body[:500]
    assert not has_explicit_success(response), exchange.body[:500]
    rejection = explicit_rejection(response.raw_response)
    assert rejection is not None, exchange.body[:500]
    assert (rejection == error) if exact else (error in rejection), rejection
    assert classify_virtualmin_application_error(response) is retriability, rejection


def assert_unavailable_command(exchange: Exchange) -> None:
    """The node has no such command: a status "error" envelope, a definite and permanent refusal."""
    assert_refused(
        exchange,
        error=f"Remote program {exchange.program} does not exist",
        retriability=Retriability.NOT_RETRIABLE,
        exact=True,
    )
    assert exchange.response.data["status"] == "error"
