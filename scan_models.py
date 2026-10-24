"""Domain models shared by fingerprinting, probing, and presentation layers."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Credential:
    """A public Supabase client configuration safe to use for anonymous checks."""

    supabase_url: str
    project_id: str
    anon_key: str
    source_file: str


@dataclass
class TableResult:
    """Result of a bounded table read in the selected access mode."""

    name: str
    row_count: int | None
    sample_columns: list[str] = field(default_factory=list)
    rls_likely_disabled: bool = False
    error: str | None = None
    sample_data: list[dict[str, Any]] = field(default_factory=list)

    @property
    def anonymously_readable(self) -> bool:
        """Evidence-accurate name for the compatibility field above."""
        return self.rls_likely_disabled


@dataclass(frozen=True)
class SensitiveKeyExposure:
    """Non-reusable metadata for privileged key material found client-side."""

    key_type: str
    occurrence_count: int
    source_file: str
    fingerprint: str


@dataclass
class ScanResult:
    target_url: str
    credentials: list[Credential] = field(default_factory=list)
    sensitive_key_exposures: list[SensitiveKeyExposure] = field(default_factory=list)
    tables_checked: list[TableResult] = field(default_factory=list)
    js_files_scanned: int = 0
    auth_mode: str = "anon"
    error: str | None = None

    @property
    def found_credentials(self) -> bool:
        return bool(self.credentials)

    @property
    def readable_tables(self) -> list[TableResult]:
        return [table for table in self.tables_checked if table.anonymously_readable]

    @property
    def vulnerable_tables(self) -> list[TableResult]:
        """Compatibility alias retained for existing files and API clients."""
        return self.readable_tables

    @property
    def sensitive_key_occurrence_count(self) -> int:
        return sum(item.occurrence_count for item in self.sensitive_key_exposures)

    @property
    def finding_count(self) -> int:
        return len(self.readable_tables) + self.sensitive_key_occurrence_count

    @property
    def has_reportable_findings(self) -> bool:
        return self.finding_count > 0
