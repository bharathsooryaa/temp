"""Normalized SBOM component (parsed from CycloneDX 1.5 JSON in a later step)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from guardian.schemas.common import Ecosystem, GuardianModel, Purl, WorkspacePath

SBOM_FORMAT = "CycloneDX"
SBOM_SPEC_VERSION = "1.5"


class DependencyScope(StrEnum):
    """Where a component is used; feeds the exposure factor."""

    RUNTIME = "runtime"
    BUILD = "build"
    DEV = "dev"
    TEST = "test"
    UNKNOWN = "unknown"


class Component(GuardianModel):
    """Component identity as carried on a finding (PDF section 5 'component')."""

    name: str = Field(min_length=1)
    version: str | None = Field(default=None, description="None means unknown, never guessed.")
    purl: Purl | None = None
    ecosystem: Ecosystem | None = None


class SourceLocation(GuardianModel):
    """Where a component is declared, usable directly as evidence (file and line)."""

    file: WorkspacePath
    line: int | None = Field(default=None, ge=1)


class SbomComponent(GuardianModel):
    """One graph node.

    ``bom_ref`` is the node ID. For npm it is the lockfile install path (e.g.
    ``node_modules/express/node_modules/qs``), which is unique even when one name@version is
    installed at several paths. For other sources it is the CycloneDX bom-ref.
    """

    bom_ref: str = Field(min_length=1)
    component: Component
    scope: DependencyScope = DependencyScope.UNKNOWN
    direct: bool | None = Field(default=None, description="Declared in a manifest; None=unknown.")
    optional: bool = False
    locations: tuple[SourceLocation, ...] = Field(
        default=(), description="Manifest or lockfile entries that declare this component."
    )
