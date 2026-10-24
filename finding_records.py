"""Safe persisted-record serialization shared by all scanner entry points."""

import json
from pathlib import Path
from typing import Any

from masking import EvidenceConfig, credential_preview, prepare_sample_data
from scan_models import Credential, ScanResult, SensitiveKeyExposure, TableResult


def serialize_public_config(credential: Credential) -> dict[str, Any]:
    """Serialize only a non-reusable preview of the public client key."""
    return {
        "supabase_url": credential.supabase_url,
        "project_id": credential.project_id,
        "anon_key_preview": credential_preview(credential.anon_key),
        "source_file": credential.source_file,
    }


def serialize_sensitive_key_exposure(
    exposure: SensitiveKeyExposure,
) -> dict[str, Any]:
    """Serialize metadata that cannot be used as the detected privileged key."""
    return {
        "key_type": exposure.key_type,
        "occurrence_count": exposure.occurrence_count,
        "source_file": exposure.source_file,
        "fingerprint": exposure.fingerprint,
    }


def serialize_table(
    table: TableResult,
    evidence: EvidenceConfig,
    *,
    include_access_state: bool,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": table.name,
        "row_count": table.row_count,
        "sample_columns": table.sample_columns,
        "sample_data": prepare_sample_data(
            table.sample_data,
            raw_values=evidence.raw_values,
            limit=evidence.sample_limit,
        ),
    }
    if include_access_state:
        record.update(
            {
                "rls_likely_disabled": table.rls_likely_disabled,
                "error": table.error,
            }
        )
    return record


def serialize_evidence(
    result: ScanResult,
    evidence: EvidenceConfig,
    *,
    include_tables_checked: bool,
) -> dict[str, Any]:
    """Serialize bounded evidence without any reusable client or secret key."""
    payload: dict[str, Any] = {
        "masked": not evidence.raw_values,
        "sample_mode": ("raw_secrets_redacted" if evidence.raw_values else "masked"),
        "finding_count": result.finding_count,
        "sensitive_key_exposure_count": result.sensitive_key_occurrence_count,
        "credentials": [
            serialize_public_config(credential) for credential in result.credentials
        ],
        "sensitive_key_exposures": [
            serialize_sensitive_key_exposure(exposure)
            for exposure in result.sensitive_key_exposures
        ],
        "vulnerable_tables": [
            serialize_table(table, evidence, include_access_state=False)
            for table in result.readable_tables
        ],
    }
    if include_tables_checked:
        payload["tables_checked"] = [
            serialize_table(table, evidence, include_access_state=True)
            for table in result.tables_checked
        ]
    return payload


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")
