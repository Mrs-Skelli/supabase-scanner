#!/bin/bash
# Unified Supabase discovery + RLS scanner - runs every 48 hours
# Per-target results saved to results/targets/

source /root/supabase-scanner/.env
export SHODAN_API_KEY
export BUILTWITH_API_KEY
export BUILTWITH_TECH

SCANNER_DIR="/root/supabase-scanner"
RESULTS_DIR="$SCANNER_DIR/results"
TARGETS_DIR="$RESULTS_DIR/targets"
LOG="$RESULTS_DIR/shodan_cron.log"

mkdir -p "$TARGETS_DIR"

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') - Starting unified discovery scan" >> "$LOG"

cd "$SCANNER_DIR"
TS=$(date -u '+%Y%m%d_%H%M%S')
FINDINGS="$RESULTS_DIR/findings_${TS}.jsonl"
INVENTORY="$RESULTS_DIR/inventory_${TS}.jsonl"
"$SCANNER_DIR/venv/bin/python" "$SCANNER_DIR/discovery.py" \
  --sources shodan,commoncrawl,builtwith \
  --max-per-source 20000 \
  --batch 20 \
  --output "$FINDINGS" \
  --inventory-output "$INVENTORY" \
  >> "$LOG" 2>&1

# Split latest inventory into per-target files so each target keeps a history of clean/vulnerable/error states
LATEST=$(ls -t "$RESULTS_DIR"/inventory_*.jsonl 2>/dev/null | head -1)
if [ -n "$LATEST" ] && [ -f "$LATEST" ]; then
  while IFS= read -r line; do
    TARGET=$(printf '%s' "$line" | python3 -c "import sys,json,re; d=json.load(sys.stdin); t=re.sub(r'[^a-zA-Z0-9._-]','_',d.get('target','')); print(t)" 2>/dev/null)
    if [ -n "$TARGET" ]; then
      printf '%s\n' "$line" >> "$TARGETS_DIR/${TARGET}.jsonl"
    fi
  done < "$LATEST"
fi

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') - Discovery scan complete. Inventory: $LATEST Findings: $FINDINGS" >> "$LOG"
