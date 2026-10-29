"""Small, opt-in command line interface for authorized single-site checks."""

import argparse
import asyncio
import json
import sys

from masking import credential_preview, prepare_sample_data
from scanner import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="supascan",
        description="Review bounded Supabase access evidence on an authorized site.",
    )
    parser.add_argument("url", help="Website URL you own or have permission to test")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm permission for active requests to the site and Supabase backend",
    )
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("active checks require --authorized")

    result = asyncio.run(scan(args.url))
    payload = {
        "target_url": result.target_url,
        "found_credentials": result.found_credentials,
        "js_files_scanned": result.js_files_scanned,
        "credentials": [
            {
                "supabase_url": item.supabase_url,
                "project_id": item.project_id,
                "anon_key_preview": credential_preview(item.anon_key),
                "source_file": item.source_file,
            }
            for item in result.credentials
        ],
        "sensitive_key_exposures": [
            {
                "key_type": item.key_type,
                "occurrence_count": item.occurrence_count,
                "source_file": item.source_file,
                "fingerprint": item.fingerprint,
            }
            for item in result.sensitive_key_exposures
        ],
        "readable_tables": [
            {
                "name": item.name,
                "row_count": item.row_count,
                "sample_columns": item.sample_columns,
                "sample_data": prepare_sample_data(item.sample_data, raw_values=False),
            }
            for item in result.readable_tables
        ],
        "error": result.error,
    }
    print(json.dumps(payload, indent=2))
    if result.error:
        print(result.error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
