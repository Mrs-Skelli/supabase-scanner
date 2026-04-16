#!/bin/bash
# Shodan Supabase RLS Scanner - runs every 48 hours
# Findings saved per-target to results/targets/

source /root/supabase-scanner/.env
export SHODAN_API_KEY

SCANNER_DIR="/root/supabase-scanner"
RESULTS_DIR="$SCANNER_DIR/results"
TARGETS_DIR="$RESULTS_DIR/targets"
LOG="$RESULTS_DIR/shodan_cron.log"

mkdir -p "$TARGETS_DIR"

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') - Starting Shodan scan" >> "$LOG"

cd "$SCANNER_DIR"
"$SCANNER_DIR/venv/bin/python" "$SCANNER_DIR/shodan_scanner.py" \
  --max 5000 \
  --batch 20 \
  --output "$RESULTS_DIR/findings_$(date -u '+%Y%m%d_%H%M%S').jsonl" \
  >> "$LOG" 2>&1

# Split findings into per-target files
LATEST=$(ls -t "$RESULTS_DIR"/findings_*.jsonl 2>/dev/null | head -1)
if [ -n "$LATEST" ] && [ -f "$LATEST" ]; then
  while IFS= read -r line; do
    TARGET=$(echo "$line" | python3 -c "import sys,json,re; d=json.load(sys.stdin); t=re.sub(r'[^a-zA-Z0-9._-]','_',d.get('target','')); print(t)" 2>/dev/null)
    if [ -n "$TARGET" ]; then
      echo "$line" >> "$TARGETS_DIR/${TARGET}.jsonl"
    fi
  done < "$LATEST"
fi

echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') - Scan complete. Results: $LATEST" >> "$LOG"
