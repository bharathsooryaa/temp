"""Shared types and validators for Guardian contracts."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


class GuardianModel(BaseModel):
    """Base for every contract: strict field names, immutable, no silent extras."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Ecosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    GOLANG = "golang"
    CARGO = "cargo"
    NUGET = "nuget"
    GEM = "gem"
    DEB = "deb"
    APK = "apk"
    RPM = "rpm"
    GITHUB_ACTIONS = "github-actions"
    OCI = "oci"
    OTHER = "other"


EVIDENCE_ID_PATTERN = r"^E-\d{3,}$"
FINDING_ID_PATTERN = r"^F-\d{3,}$"
EVIDENCE_ID_RE = re.compile(r"\bE-\d{3,}\b")

EvidenceId = Annotated[str, Field(pattern=EVIDENCE_ID_PATTERN)]
FindingId = Annotated[str, Field(pattern=FINDING_ID_PATTERN)]


def _check_workspace_relative(value: str) -> str:
    """Reject absolute paths and parent traversal so evidence cannot point outside the jail."""
    if not value:
        raise ValueError("path must not be empty")
    if "\\" in value or "\x00" in value:
        raise ValueError("path must use '/' separators and contain no NUL bytes")
    path = PurePosixPath(value)
    if path.is_absolute() or re.match(r"^[A-Za-z]:", value):
        raise ValueError("path must be relative to the workspace")
    if any(part == ".." for part in path.parts):
        raise ValueError("path must not contain '..'")
    return path.as_posix()


WorkspacePath = Annotated[str, AfterValidator(_check_workspace_relative)]


def _check_purl(value: str) -> str:
    # Minimal structural check (pkg:type/name[@version]); full parsing happens in the SBOM step.
    if not re.match(r"^pkg:[a-z][a-z0-9.+-]*/.+", value):
        raise ValueError("purl must look like 'pkg:<type>/<name>[@<version>]'")
    return value


Purl = Annotated[str, AfterValidator(_check_purl)]


def cited_evidence_ids(text: str) -> set[str]:
    """Return every evidence ID (E-###) referenced in free text such as an AI rationale."""
    return set(EVIDENCE_ID_RE.findall(text))
