# Supabase RLS Scanner

A security research tool that detects Supabase clients and identifies tables
that return rows to an anonymous or explicitly supplied authenticated session.

Built for responsible disclosur. Find it, report it, get it fixed.

[Changelog](CHANGELOG.md) · [Security policy](SECURITY.md) ·
[Contributing](CONTRIBUTING.md)

> [!IMPORTANT]
> A readable table does **not** by itself prove that RLS is disabled or that the
> data is unintentionally public. Supabase policies can deliberately grant
> anonymous read access. Treat scanner output as a lead and review the bounded
> sample and application context before assigning severity.

---

## What it does

Many web apps built on Supabase embed their project URL and public client key
directly in frontend JavaScript. Public client keys are designed to be shipped
to browsers; the security boundary is the database policy, not key secrecy.

This tool automates finding that combination:

1. Fetches the target page and all linked JavaScript files
2. Extracts hosted, custom-domain, and strongly paired self-hosted client
   configuration, including legacy JWT and `sb_publishable_` public keys
3. Queries the Supabase REST API to discover table names via the OpenAPI spec
4. Makes a bounded read request and records tables that return at least one row

Read more about the underlying issue: [Supabase Shenanigans](https://skelli.win/posts/supabase-shenanigans/)

---

## Features

- Web UI for one-off scans
- REST API for programmatic use
- Discovery adapters for Shodan, Common Crawl, and BuiltWith
- Passive discovery-only mode with provider pagination, retry/backoff, and
  de-duplicated, confidence-ranked candidate inventories
- Modern environment-name, Realtime, Storage, Auth/JWKS, custom-domain, and
  self-hosted service-route fingerprints
- Rate limiting (10 scans/min per IP)
- Docker + nginx config ready for self-hosting
- Findings saved as JSONL for easy processing
- Structured rotating logs, correlation IDs, provider status, and an
  access-controlled diagnostics view
- Privileged `sb_secret_` and legacy service-role keys are never used, returned,
  logged, or persisted. Findings retain only type, count, source, and a short
  one-way correlation fingerprint so analysts can identify the exposure safely.

---

## Screenshots

> Web UI — paste a URL, see results in seconds

---

## Quickstart

### Local (Python)

```bash
git clone https://github.com/Mrs-Skelli/supabase-scanner
cd supabase-scanner

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

uvicorn main:app --reload
# Open http://localhost:8000
```

### Docker

```bash
cp .env.example .env
# Edit .env and add your SHODAN_API_KEY if you want Shodan scanning

docker compose up -d
# Open http://localhost:8000
```

---

## Self-hosting

Deploy to your own domain with TLS:

```bash
# 1. Get a TLS cert
sudo certbot certonly --nginx -d research.example.com

# 2. Configure nginx
sudo cp nginx.conf /etc/nginx/sites-available/supabase-scanner
sudo ln -s /etc/nginx/sites-available/supabase-scanner /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 3. Start the app
docker compose up -d
```

The app binds to `127.0.0.1:8000` only — nginx is the public entry point.

---

## Internet-scale scanning (Shodan)

Requires a [Shodan](https://shodan.io) API key with enough credits for search cursors.

```bash
# Put SHODAN_API_KEY in the untracked .env file
cp .env.example .env

# Run a scan (defaults: up to 1000 results, 10 concurrent)
python shodan_scanner.py

# Options
python shodan_scanner.py --max 5000 --batch 20 --output results/run1.jsonl

# Custom Shodan query
python shodan_scanner.py --query 'http.html:"supabase.co" http.html:"eyJhbGciOiJIUzI1NiIs"'

# Collect passive candidates without sending requests to discovered targets
python discovery.py --discover-only --max-per-source 20000
```

`shodan_cron.sh` uses paths relative to the repository and safely parses simple
`KEY=VALUE` entries from `.env` without executing the file. Its interpreter,
output directory, source list, provider cap, and batch size can be overridden
with `PYTHON_BIN`, `RESULTS_DIR`, `DISCOVERY_SOURCES`, `MAX_PER_SOURCE`, and
`SCAN_BATCH_SIZE`. Set `DISCOVERY_ONLY=true` to make the scheduled job write a
de-duplicated candidate inventory without probing discovered targets. A provider
run that produces no current inventory exits non-zero rather than reusing an
older file.

The fingerprint scanner recognizes documented browser configuration names such
as `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` and
`VITE_SUPABASE_PUBLISHABLE_KEY`. It also pairs nearby public keys with
documented Realtime, Storage, Auth/JWKS, REST, GraphQL, and Functions URLs. A
service URL without a nearby key remains a passive lead and is not treated as a
confirmed Supabase client configuration.

Findings are saved as JSONL in `results/` — one JSON object per target with an
anonymously readable table or a detected privileged-key exposure.

Sample values are masked by default. For an access-controlled analyst
deployment, set `RAW_EVIDENCE_ENABLED=true` to retain and display a maximum of
one bounded raw row per readable table. Credential-shaped fields and token
values remain redacted. `RAW_EVIDENCE_SAMPLE_LIMIT` may be set from 1 to 3;
values outside that range are clamped. The findings browser still starts in
masked mode and requires an explicit per-session action to reveal raw samples.
The one-off scan API likewise requires `"raw_evidence": true`; enabling the
environment variable alone never changes its default response.

Do not expose analyst mode on an unauthenticated public deployment. Stored
evidence can contain personal or otherwise sensitive application data even
after credentials are removed.

```json
{
  "timestamp": "2026-04-16T10:00:00",
  "target": "https://example.com",
  "status": "finding",
  "finding_count": 1,
  "credentials": [{ "supabase_url": "...", "project_id": "...", "anon_key_preview": "..." }],
  "sensitive_key_exposures": [],
  "vulnerable_tables": [{ "name": "public_profiles", "row_count": 5, "sample_columns": ["id", "display_name"] }]
}
```

---

## API

### `POST /api/scan`

```bash
curl -X POST https://research.example.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://target.com", "raw_evidence": false}'
```

**Response:**
```json
{
  "target_url": "https://target.com",
  "found_credentials": true,
  "js_files_scanned": 12,
  "credentials": [...],
  "sensitive_key_exposures": [...],
  "tables_checked": [...],
  "vulnerable_table_count": 2,
  "evidence_mode": "masked",
  "error": null
}
```

`vulnerable_table_count` and the older `rls_likely_disabled` table field remain
for API compatibility. They mean that the request returned rows; they do not,
by themselves, prove RLS is disabled or that the access is unintended.

## Diagnostics and debugging

Open `/diagnostics` on the same access-controlled deployment to see service
uptime, request/scan counters, recent error classes, and the latest discovery
provider status. `GET /api/diagnostics` returns the same derived state with
`Cache-Control: no-store`.

Application logs are JSON Lines by default and rotate at 5 MiB with five
backups:

- `results/logs/api.log`
- `results/logs/discovery.log`
- `results/logs/shodan.log`
- `results/shodan_cron.log` for the cron wrapper

Every API response includes `X-Request-ID`; scan and discovery log entries also
carry an operation ID. Use those IDs to correlate failures without searching
for target data. Set `LOG_LEVEL=DEBUG` temporarily for deeper transport and
request-flow diagnostics. `LOG_FORMAT=text` is available for interactive use,
and `LOG_TO_FILE=false` keeps logs on stderr/journald only.

Messages are filtered for JWTs, Supabase keys, authorization headers, and
common token query parameters. Tracebacks retain stack locations and exception
types but omit exception values. Logs deliberately omit target identities,
table names, response bodies, samples, raw credentials, and auth tokens. Keep
the diagnostics route behind the same reverse-proxy authentication as the
findings browser.

## Development

The supported runtime is Python 3.12.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
ruff format --check .
ruff check .
pytest
```

### Architecture and safety boundaries

- `fingerprints.py` parses supplied HTML and JavaScript. It cannot perform
  network requests and must receive the fail-closed URL validator before a
  detected endpoint becomes usable configuration.
- `supabase_probe.py` owns the bounded schema and one-row access requests.
  Publishable keys are sent only as `apikey`; a bearer header is added only for
  a legacy anon JWT or an explicitly supplied user token.
- `scanner.py` is the single orchestration boundary connecting fetched target
  content to active Supabase probes.
- `finding_records.py` is the only persisted-evidence serializer. Reusable keys
  never cross that boundary; raw application evidence remains bounded,
  deployment-gated, explicitly requested for display, and secret-redacted.
- `discovery.py` merges passive providers. Its discovery-only branch writes
  candidates and returns before the separate active-scanning branch can call
  the target scanner.

Provider adapters may fail independently. A partial refresh is recorded as
partial, while a run where every enabled provider fails exits non-zero instead
of presenting stale or empty output as a successful refresh.

---

## Responsible disclosure

If you find a vulnerable site:

1. **Don't access more data than needed** to confirm the issue exists
2. **Find a security contact** — check for `security.txt`, a bug bounty program, or a general contact email
3. **Report clearly** — include the Supabase project URL, which tables are readable, what type of data is accessible, and why the access appears unintended
4. **Give them time** — standard practice is 30–90 days before publishing
5. **Follow up** — if no response after 2 weeks, try another contact

The Netherlands has a [coordinated vulnerability disclosure guideline](https://www.ncsc.nl/onderwerpen/coordinated-vulnerability-disclosure) from the NCSC if you need a framework to point to.

---

## Legal

This tool is for **authorized security testing and responsible disclosure only**.

Only scan websites you own or have explicit written permission to test. Unauthorized scanning may violate computer fraud laws in your jurisdiction (including the Dutch *Wet computercriminaliteit*).

---

## License

MIT — see [LICENSE](LICENSE)
