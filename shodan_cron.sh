#!/usr/bin/env bash
# Unified Supabase discovery + RLS scanner - runs every 48 hours
# Per-target results saved to results/targets/

set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="${SCANNER_DIR:-$SCRIPT_DIR}"
RESULTS_DIR="${RESULTS_DIR:-$SCANNER_DIR/results}"
TARGETS_DIR="$RESULTS_DIR/targets"
LOG="$RESULTS_DIR/shodan_cron.log"
ENV_FILE="${ENV_FILE:-$SCANNER_DIR/.env}"
PYTHON_BIN="${PYTHON_BIN:-$SCANNER_DIR/venv/bin/python}"
DISCOVERY_SOURCES="${DISCOVERY_SOURCES:-shodan,commoncrawl,builtwith}"
MAX_PER_SOURCE="${MAX_PER_SOURCE:-20000}"
SCAN_BATCH_SIZE="${SCAN_BATCH_SIZE:-20}"

mkdir -p "$TARGETS_DIR"

log() {
  printf '%s - %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" "$1" >> "$LOG"
}

load_env_file() {
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" == export\ * ]]; then
      line="${line#export }"
      line="${line#"${line%%[![:space:]]*}"}"
    fi
    if [[ "$line" != *=* ]]; then
      log "Ignoring malformed environment entry"
      continue
    fi
    key="${line%%=*}"
    key="${key%"${key##*[![:space:]]}"}"
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      log "Ignoring environment entry with an invalid name"
      continue
    fi
    value="${line#*=}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ ${#value} -ge 2 ]]; then
      if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
        value="${value:1:${#value}-2}"
      fi
    fi
    export "$key=$value"
  done < "$1"
}

if [[ -f "$ENV_FILE" ]]; then
  # Parse simple KEY=VALUE lines without executing the file as shell code.
  load_env_file "$ENV_FILE"
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  log "Discovery failed: Python interpreter is not executable"
  exit 1
fi

log "Starting unified discovery scan"

cd "$SCANNER_DIR"
TS="$(date -u '+%Y%m%d_%H%M%S')_$$"
FINDINGS="$RESULTS_DIR/findings_${TS}.jsonl"
INVENTORY="$RESULTS_DIR/inventory_${TS}.jsonl"
if ! "$PYTHON_BIN" "$SCANNER_DIR/discovery.py" \
  --sources "$DISCOVERY_SOURCES" \
  --max-per-source "$MAX_PER_SOURCE" \
  --batch "$SCAN_BATCH_SIZE" \
  --output "$FINDINGS" \
  --inventory-output "$INVENTORY" \
  >> "$LOG" 2>&1; then
  log "Discovery failed: scanner process returned a non-zero status"
  exit 1
fi

# A successful process with no inventory means no provider supplied candidates.
# Treat that as a failed refresh and never fall back to an older inventory.
if [[ ! -s "$INVENTORY" ]]; then
  log "Discovery failed: no candidates were written to the current inventory"
  exit 2
fi

# Split this run's inventory into per-target history files.
while IFS= read -r line; do
  TARGET=$(printf '%s' "$line" | "$PYTHON_BIN" -c "import sys,json,re; d=json.load(sys.stdin); t=re.sub(r'[^a-zA-Z0-9._-]','_',d.get('target','')); print(t)" 2>/dev/null)
  if [[ -n "$TARGET" ]]; then
    printf '%s\n' "$line" >> "$TARGETS_DIR/${TARGET}.jsonl"
  fi
done < "$INVENTORY"

if [[ -s "$FINDINGS" ]]; then
  log "Discovery scan complete. Inventory: $INVENTORY Findings: $FINDINGS"
else
  log "Discovery scan complete. Inventory: $INVENTORY Findings: none"
fi
