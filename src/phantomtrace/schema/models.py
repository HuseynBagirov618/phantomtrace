from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, ConfigDict


CoverageState = Literal["SUPPORTED", "PARTIAL", "UNKNOWN", "UNSUPPORTED"]
EdgeStrength = Literal["HARD", "SOFT", "CONDITIONAL", "DERIVED"]
ReviewOperation = Literal["CONFIRM", "REJECT", "QUESTION", "NOTE"]


class Case(BaseModel):
    """
    Investigation container.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    created_at: datetime
    description: str | None = None


class EvidenceFile(BaseModel):
    """
    Original evidence file identity.

    Original bytes must stay immutable.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1)
    sha256: str = Field(min_length=64, max_length=64)
    source_name: str = Field(min_length=1)
    collected_at: datetime
    byte_length: int = Field(ge=0)


class RawRecord(BaseModel):
    """
    Pointer back to a raw event record inside an evidence file.
    """

    model_config = ConfigDict(extra="forbid")

    file_sha256: str = Field(min_length=64, max_length=64)
    channel: str = Field(min_length=1)
    record_locator: str = Field(min_length=1)
    raw_hash: str = Field(min_length=64, max_length=64)
    raw_xml: str = Field(min_length=1)


class NormalizedEvent(BaseModel):
    """
    Normalized event used by rules, graph joins, timeline, and reports.

    Unknown fields from source records should not be silently discarded.
    Store source-specific values inside event_data or pt.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    raw_ref: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)

    timestamp: datetime
    event_code: str = Field(min_length=1)
    host_id: str | None = None
    host_name: str | None = None

    event_data: dict[str, Any] = Field(default_factory=dict)
    pt: dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    """
    Persisted relationship between two observations or entities.

    A hard edge is an identifier-backed association, not proof of intent.
    """

    model_config = ConfigDict(extra="forbid")

    edge_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    strength: EdgeStrength
    from_id: str = Field(min_length=1)
    to_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    support_event_ids: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    explanation: str = Field(min_length=1)


class ReviewAction(BaseModel):
    """
    Append-only analyst review action.
    """

    model_config = ConfigDict(extra="forbid")

    actor: str = Field(min_length=1)
    timestamp: datetime
    target: str = Field(min_length=1)
    operation: ReviewOperation
    rationale: str = Field(min_length=1)