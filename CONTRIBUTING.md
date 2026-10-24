# Contributing

Thanks for helping improve the scanner. Keep changes focused, documented, and
safe for authorized research.

## Development setup

Use Python 3.12 and install `requirements-dev.txt`. Before opening a pull
request, run:

```bash
ruff format --check .
ruff check .
pytest
```

Keep module boundaries intact: passive fingerprint parsing belongs in
`fingerprints.py`, network access checks in `supabase_probe.py`, orchestration in
`scanner.py`, and persisted JSONL shape changes in `finding_records.py`. New
discovery-only behavior must include a regression test proving that the target
scanner is never called.

## Evidence safety

- Keep masked, bounded evidence as the default.
- Never add real targets, API keys, tokens, personal data, `.env` files, or
  contents from `results/` to tests, issues, or commits.
- Use synthetic `.test` fixtures.
- Changes that expand active probing or collection volume need an explicit
  rationale and tests for their bounds.

## Reporting bugs

Ordinary bugs can use GitHub issues. Please use GitHub's private security
advisory flow for vulnerabilities in the scanner itself.
