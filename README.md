# Supabase RLS Scanner

A security research tool that detects Supabase clients and identifies tables
that return rows to an anonymous or explicitly supplied authenticated session.

Built for responsible disclosure — find it, report it, get it fixed.

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
- Rate limiting (10 scans/min per IP)
- Docker + nginx config ready for self-hosting
- Findings saved as JSONL for easy processing
- `sb_secret_` values are recognized only to exclude them; they are never used,
  returned by the API, or written to findings

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
# Set your key
export SHODAN_API_KEY=your_key_here

# Run a scan (defaults: up to 1000 results, 10 concurrent)
python shodan_scanner.py

# Options
python shodan_scanner.py --max 5000 --batch 20 --output results/run1.jsonl

# Custom Shodan query
python shodan_scanner.py --query 'http.html:"supabase.co" http.html:"eyJhbGciOiJIUzI1NiIs"'
```

Findings are saved as JSONL in `results/` — one JSON object per vulnerable target.

Sample values are masked by default. For an access-controlled analyst
deployment, set `RAW_EVIDENCE_ENABLED=true` to retain and display a maximum of
one bounded raw row per exposed table. Credential-shaped fields and token
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
  "credentials": [{ "supabase_url": "...", "project_id": "...", "anon_key_preview": "..." }],
  "vulnerable_tables": [{ "name": "users", "row_count": 5, "sample_columns": ["id", "email"] }]
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
  "tables_checked": [...],
  "vulnerable_table_count": 2,
  "evidence_mode": "masked",
  "error": null
}
```

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

---

## Responsible disclosure

If you find a vulnerable site:

1. **Don't access more data than needed** to confirm the issue exists
2. **Find a security contact** — check for `security.txt`, a bug bounty program, or a general contact email
3. **Report clearly** — include the Supabase project URL, which tables are exposed, and what type of data is accessible
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
