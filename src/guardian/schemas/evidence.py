"""Evidence records: the only things a finding or an AI explanation may cite."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from guardian.schemas.common import EvidenceId, GuardianModel, WorkspacePath


class EvidenceKind(StrEnum):
    SCANNER_RESULT = "scanner_result"
    FILE_LOCATION = "file_location"
    GRAPH_NODE = "graph_node"
    REGISTRY_METADATA = "registry_metadata"
    DIFF_HUNK = "diff_hunk"
    ADVISORY = "advisory"


class EvidenceRecord(GuardianModel):
    """One deterministic fact produced by a tool and stored with an ID.

    ``excerpt`` must already be redacted by the producer; the redaction step itself is
    implemented with the scanners (see DECISIONS.md D1-04).
    """

    id: EvidenceId
    kind: EvidenceKind
    tool: str = Field(min_length=1, description="Producing tool, e.g. 'grype'.")
    tool_version: str | None = None
    ref: str | None = Field(default=None, description="Tool-native ID, e.g. GHSA/CVE/rule ID.")
    file: WorkspacePath | None = None
    line: int | None = Field(default=None, ge=1)
    graph_node: str | None = Field(default=None, description="Dependency-graph node ID.")
    excerpt: str | None = Field(default=None, max_length=2000)
    redacted: bool = Field(
        default=False, description="True if secret material was removed from the excerpt."
    )
    collected_at: datetime | None = None

    @model_validator(mode="after")
    def _locatable(self) -> EvidenceRecord:
        if self.line is not None and self.file is None:
            raise ValueError("'line' requires 'file'")
        if self.ref is None and self.file is None and self.graph_node is None:
            raise ValueError("evidence must carry at least one of 'ref', 'file' or 'graph_node'")
        if self.kind is EvidenceKind.FILE_LOCATION and self.file is None:
            raise ValueError("file_location evidence requires 'file'")
        if self.kind is EvidenceKind.GRAPH_NODE and self.graph_node is None:
            raise ValueError("graph_node evidence requires 'graph_node'")
        return self


class EvidenceRef(GuardianModel):
    """A citation from a finding to a stored evidence record (PDF section 5 'evidence' entry)."""

    evidence_id: EvidenceId
    tool: str = Field(min_length=1)
    ref: str | None = None
    file: WorkspacePath | None = None
    line: int | None = Field(default=None, ge=1)
