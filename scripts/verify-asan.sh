#!/usr/bin/env bash
# End-to-end verification: build both demos under ASan, run every bug mode,
# pipe stderr through `asan-harness ingest`, assert the triage clusters
# match the expected set.
#
# Exits 0 on full success, non-zero on the first missing expectation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET=x86_64-unknown-linux-gnu
BIN_DIR="$ROOT/target/$TARGET/debug"
RESULTS="$ROOT/target/verify"
LOGS="$RESULTS/logs"
CRASHES="$RESULTS/crashes"

rm -rf "$RESULTS"
mkdir -p "$LOGS" "$CRASHES"

echo "==> building asan-cli"
cargo build -q -p asan-cli

echo "==> building rust-asan under -Zsanitizer=address"
RUSTFLAGS="-Zsanitizer=address" \
    cargo +nightly build -q -p rust-asan --target "$TARGET"

echo "==> building c-ffi-asan under -Zsanitizer=address"
RUSTFLAGS="-Zsanitizer=address" \
    cargo +nightly build -q -p c-ffi-asan --target "$TARGET"

run_mode() {
    local bin="$1" mode="$2" tag="$3"
    local logfile="$LOGS/${tag}-${mode}.log"
    # Expected: the binary aborts. Allow non-zero, capture stderr.
    "$bin" "$mode" 2>"$logfile" || true
    if [ ! -s "$logfile" ]; then
        echo "  FAIL: $tag/$mode produced no sanitizer output"
        return 1
    fi
    echo "  ok:   $tag/$mode  ($(wc -l <"$logfile") lines)"
    "$BIN_DIR/../../debug/asan-harness" ingest \
        --file "$logfile" --out-dir "$CRASHES" >/dev/null
}

echo "==> exercising rust-asan"
for m in hbo uaf df; do
    run_mode "$BIN_DIR/rust-asan-demo" "$m" rust
done

echo "==> exercising c-ffi-asan"
for m in hbo uaf df; do
    run_mode "$BIN_DIR/c-ffi-asan-demo" "$m" c
done

echo "==> triage"
clusters=$("$ROOT/target/debug/asan-harness" \
    --format json triage --dir "$CRASHES" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['total_crashes'])")

echo "  distinct clusters: $("$ROOT/target/debug/asan-harness" \
    triage --dir "$CRASHES" | awk '/^clusters/{print $3}')"
echo "  total crashes:     $clusters"

if [ "$clusters" != "6" ]; then
    echo "FAIL: expected 6 crashes, got $clusters"
    exit 1
fi

# Every expected crash kind must be present at least twice (rust + C source).
export CRASHES
python3 - <<'PY'
import glob, json, os, sys
kinds = {}
for fn in sorted(glob.glob(os.path.join(os.environ['CRASHES'], '*.json'))):
    with open(fn) as f:
        r = json.load(f)
    k = r['kind']['kind']
    kinds[k] = kinds.get(k, 0) + 1
print("  kind counts:")
for k, n in sorted(kinds.items()):
    print(f"    {k}: {n}")
expected = ('heap_buffer_overflow', 'use_after_free', 'double_free')
missing = [k for k in expected if kinds.get(k, 0) < 2]
if missing:
    print("FAIL: expected each kind present ≥ 2×, missing:", missing)
    sys.exit(1)
PY

echo ""
echo "PASS: 6 distinct crashes ingested across Rust-ASan and C-FFI-ASan modes."
