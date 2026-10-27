"""The editable fields of one explicit customer DNS record intent."""

from dataclasses import dataclass
from typing import TypedDict
from uuid import UUID


class RecordMutation(TypedDict, total=False):
    record_id: str | UUID | None
    name: str
    record_type: str
    rdata: str
    ttl: int
    delete: bool


@dataclass(frozen=True)
class RecordChange:
    record_id: str | UUID | None = None
    name: str = ""
    record_type: str = ""
    rdata: str = ""
    ttl: int = 300
    delete: bool = False
