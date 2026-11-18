"""Configuration and documented evidence attestations for a case."""
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from phantomtrace.investigation.rules import CAPABILITIES

NonBlank = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]


class BootRange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: NonBlank
    start: datetime
    end: datetime
    reference: NonBlank


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    boot_ranges: list[BootRange] = Field(default_factory=list, max_length=100)
    verified_policy: dict[str, NonBlank] = Field(default_factory=dict, max_length=len(CAPABILITIES))
