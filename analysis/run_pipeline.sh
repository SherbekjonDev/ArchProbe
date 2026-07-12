#!/bin/bash
# Full ArchProbe pipeline: parse traces → extract features → classify
set -e

SCRIPT_DIR="$(dirname "$0")"
DATA_DIR="$SCRIPT_DIR/../data"
RESULTS_DIR="$SCRIPT_DIR/../results"
mkdir -p "$RESULTS_DIR"

echo "=== ArchProbe Analysis Pipeline ==="
echo ""

# Step 1: Parse x86 traces
echo "[1/3] Parsing x86 traces..."
python3 "$SCRIPT_DIR/parse_traces.py" \
    "$DATA_DIR/x86" \
    "$RESULTS_DIR/features_x86.json"

# Step 2: Parse ARM traces
echo ""
echo "[2/3] Parsing ARM traces..."
python3 "$SCRIPT_DIR/parse_traces.py" \
    "$DATA_DIR/arm" \
    "$RESULTS_DIR/features_arm.json"

# Step 3: Run classification experiments
echo ""
echo "[3/3] Running experiments..."
python3 "$SCRIPT_DIR/classify.py" \
    "$RESULTS_DIR/features_x86.json" \
    "$RESULTS_DIR/features_arm.json" \
    --out "$RESULTS_DIR/results.json"

echo ""
echo "=== Done. Results in $RESULTS_DIR/ ==="
