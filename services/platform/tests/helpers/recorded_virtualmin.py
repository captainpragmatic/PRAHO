"""Replay of what a real Virtualmin node answered, recorded by the contract suite (`make test-virtualmin-contract`).

Tests that need a Virtualmin response should take it from here instead of writing a `{"status": "success"}`
body by hand: a hand-written body can drift from what the node says, a recorded one cannot, because the
contract run compares it with the live node (drift check) and re-records it.

- `recorded_payload(program, case)`: the recorded body as a dict (for tests that wrap it in their own transport).
- `recorded_http_response(program, case)`: the same as a `requests.Response`, status code included.
- `recorded_response(program, case)`: the `VirtualminResponse` the production gateway builds from it.
- `RecordedVirtualminGateway`: the production gateway with its transport replaced by the recordings.

Recordings live in `services/platform/tests/fixtures/virtualmin/<version>/<program>.json`, one file per program
with named cases ("success", "absent_domain", ...).
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import requests

from apps.common.types import Ok, Result
from apps.provisioning.virtualmin_gateway import (
    RateLimitOutcome,
    VirtualminConfig,
    VirtualminGateway,
    VirtualminResponse,
)

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "virtualmin"
RECORDED_HOST = "recorded.virtualmin.test"
# The domain the contract suite uses for "a domain that is not there"; replace it to ask about another.
RECORDED_ABSENT_DOMAIN = "contract-absent.praho.test"


def recorded_versions() -> list[str]:
    return sorted(path.name for path in FIXTURE_ROOT.iterdir() if path.is_dir() and path.name[:1].isdigit())


def latest_version() -> str:
    versions = recorded_versions()
    assert versions, f"no Virtualmin recordings under {FIXTURE_ROOT}"
    return max(versions, key=lambda version: tuple(int(part) for part in version.split(".") if part.isdigit()))


def load_cases(program: str, version: str | None = None) -> dict[str, dict[str, Any]]:
    path = FIXTURE_ROOT / (version or latest_version()) / f"{program}.json"
    cases: dict[str, dict[str, Any]] = json.loads(path.read_text())["cases"]
    return cases


def _case(program: str, case: str, version: str | None) -> dict[str, Any]:
    cases = load_cases(program, version)
    assert case in cases, f"{program}: no recorded case {case!r}; recorded: {sorted(cases)}"
    return cases[case]


def recorded_payload(
    program: str, case: str = "success", *, version: str | None = None, replace: Mapping[str, str] | None = None
) -> Any:
    """The recorded body (a dict for JSON answers). `replace` swaps text in it, e.g. the absent domain's name."""
    body = copy.deepcopy(_case(program, case, version)["body"])
    if not replace:
        return body
    text = json.dumps(body)
    for old, new in replace.items():
        text = text.replace(old, new)
    return json.loads(text)


def recorded_http_response(
    program: str, case: str = "success", *, version: str | None = None, replace: Mapping[str, str] | None = None
) -> requests.Response:
    recorded = _case(program, case, version)
    body = recorded_payload(program, case, version=version, replace=replace)
    response = requests.Response()
    response.status_code = recorded["http_status"]
    response.encoding = "utf-8"
    response._content = (body if isinstance(body, str) else json.dumps(body)).encode()
    response._content_consumed = True
    return response


def accepted_keys(program: str, version: str | None = None) -> set[str]:
    """The parameter names the node accepted for `program` in the contract suite (its successful cases)."""
    keys: set[str] = set()
    for recorded in load_cases(program, version).values():
        if recorded["classification"]["success"]:
            keys |= set(recorded["params"])
    return keys


class RecordedVirtualminGateway(VirtualminGateway):
    """The production gateway answering from the recordings.

    Only the transport is replaced: validation, parsing, normalisation, retries and every classification
    run the production code. `cases` maps a program to the recorded case (or a list of cases, used in order,
    the last repeating) it should answer with; a program not listed answers "success".

    With `strict_params` (the default) a call whose parameter names the node never accepted in the contract
    suite fails the test: the recording is evidence of what Virtualmin 8.3 takes, so a caller that drifts
    from it (the `format` parameter, `bandwidth` on modify-domain) is caught here.
    """

    def __init__(
        self,
        cases: Mapping[str, str | Sequence[str]] | None = None,
        *,
        version: str | None = None,
        strict_params: bool = True,
        replace: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(
            VirtualminConfig.from_credentials(
                hostname=RECORDED_HOST, username="recorded", password="recorded", verify_ssl=True  # noqa: S106  # A stand-in for the replayed transport
            )
        )
        self._plan = {
            program: [chosen] if isinstance(chosen, str) else list(chosen) for program, chosen in (cases or {}).items()
        }
        self._version = version
        self._strict = strict_params
        self._replace = dict(replace or {})
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def _get_credentials(self, reason: str = "Virtualmin API call") -> Result[tuple[str, str], str]:
        return Ok(("recorded", "recorded"))

    def _check_rate_limit(self, operation: str) -> RateLimitOutcome:
        return RateLimitOutcome.ALLOWED

    def _check_qps_limit(self) -> RateLimitOutcome:
        return RateLimitOutcome.ALLOWED

    def _execute_http_request(
        self,
        params: dict[str, Any],
        auth: tuple[str, str] | None = None,
        timeout_seconds: int | None = None,
        deadline: float | None = None,
    ) -> requests.Response:
        program = str(params["program"])
        sent = {key: value for key, value in params.items() if key not in {"program", "json", "xml"}}
        self.sent.append((program, sent))
        if self._strict:
            unknown = set(sent) - accepted_keys(program, self._version)
            assert not unknown, f"{program}: Virtualmin never accepted {sorted(unknown)} in the contract suite"
        planned = self._plan.get(program, ["success"])
        case = planned.pop(0) if len(planned) > 1 else planned[0]
        return recorded_http_response(program, case, version=self._version, replace=self._replace)


def recorded_response(
    program: str, case: str = "success", *, params: dict[str, Any] | None = None, replace: Mapping[str, str] | None = None
) -> VirtualminResponse:
    """The `VirtualminResponse` the production gateway builds from a recorded answer."""
    gateway = RecordedVirtualminGateway({program: case}, strict_params=False, replace=replace)
    result = gateway.call(program, params)
    assert result.is_ok(), result
    return result.unwrap()
