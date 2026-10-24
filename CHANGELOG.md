# Changelog

Notable changes to Supabase Scanner are documented here. Dates use ISO 8601
(`YYYY-MM-DD`). The project does not currently publish numbered releases, so
entries are grouped by date.

## Unreleased

No unreleased changes yet.

## 2026-10-24 — Fingerprinting, evidence, and reliability overhaul

### Added

- Detection for modern `sb_publishable_` client keys alongside legacy anon JWTs.
- Non-reusable findings for exposed `sb_secret_` and legacy service-role keys.
  The scanner records only the key type, occurrence count, source label, and a
  short one-way fingerprint.
- Supabase configuration fingerprints for documented Next.js, Vite, and generic
  environment-variable names.
- Hosted `supabase.co` and `supabase.in` projects, custom domains, and strongly
  paired self-hosted service URLs.
- Service-route fingerprints for REST, Auth, Storage, Realtime, GraphQL,
  Functions, JWKS, public Storage objects, and self-hosted Realtime sockets.
- Confidence levels for passive discovery candidates and source metadata.
- A passive `--discover-only` workflow that creates a deduplicated candidate
  inventory without requesting discovered targets.
- Common Crawl pagination, retry/backoff, JavaScript MIME support, bounded WARC
  handling, and modern Supabase content markers.
- Structured rotating logs, request/operation correlation IDs, safe error
  summaries, provider status, and an authenticated diagnostics view.
- An explicitly enabled raw-evidence review mode with bounded samples. Reusable
  keys and tokens remain redacted in every mode.
- Open-source project metadata, CI configuration, contribution guidance, and
  security documentation.

### Changed

- Split the original scanner into focused boundaries:
  - `fingerprints.py` for passive parsing.
  - `scan_models.py` for shared domain models.
  - `supabase_probe.py` for bounded Supabase API checks.
  - `scanner.py` for orchestration.
  - `scan_batch.py` for per-target failure isolation.
  - `finding_records.py` for persisted evidence serialization.
  - `finding_store.py` for resilient finding retrieval and summaries.
- Centralized evidence serialization so the web, unified discovery, and
  standalone Shodan paths apply identical redaction and sample limits.
- Made discovery providers independent: one provider failure no longer discards
  successful results from another provider.
- Discovery runs now distinguish `discovered`, `completed`, `partial`, `empty`,
  `disabled`, and `failed` outcomes instead of treating every zero-result run as
  success.
- Publishable keys are sent as `apikey` only. A bearer header is used only for
  an exact legacy `anon` JWT or an explicitly supplied user access token.
- Finding descriptions and UI labels now describe observed readable data rather
  than automatically claiming that Row Level Security is disabled.
- The scheduled discovery job uses strict shell settings, private output
  permissions, safe environment parsing, and configurable sources and limits.

### Fixed

- Rejected malformed legacy JWTs and legacy keys with privileged roles from the
  public-client path.
- Preserved secret-key-only findings even when no readable table was detected.
- Revalidated every redirect and failed closed when DNS resolution could not be
  completed.
- Removed reusable keys from persisted JSONL, API output, logs, and exception
  messages.
- Isolated unexpected target failures so one target cannot abort an entire scan
  batch.
- Made malformed or unreadable historical JSONL records non-fatal to the
  findings browser.
- Made all-provider discovery failures exit non-zero and report an accurate
  failure state.
- Bounded Common Crawl compressed and decompressed record processing.

### Verification

- Expanded the regression suite to 72 tests covering fingerprints, provider
  failures, discovery-only isolation, evidence handling, storage compatibility,
  SSRF controls, and bounded probing.
- Added Ruff formatting/linting, Python compilation, shell syntax, and browser
  JavaScript parsing checks.

## 2026-04-18 — Multi-source discovery

### Added

- Common Crawl and BuiltWith discovery adapters.
- Unified candidate merging across discovery providers.

## 2026-04-17 — Internet-scale discovery

### Added

- Paginated Shodan search support.
- Shodan fingerprints for TLS certificates, HTML references, and PostgREST.

### Security

- Hardened Supabase URL validation and client-facing error handling.

## 2026-04-16 — Initial scanner

### Added

- Web UI and API for scanning a supplied site.
- Frontend JavaScript extraction and Supabase client detection.
- REST/OpenAPI and GraphQL-assisted table discovery.
- Bounded table reads, authenticated comparison support, token refresh, and
  HTTP `206 Partial Content` handling.
- Scheduled Shodan discovery and JSONL finding storage.

### Security

- Added SSRF protections covering private, loopback, link-local, reserved, and
  metadata-service destinations.
