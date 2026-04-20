# asan-harness

A Rust harness for driving AddressSanitizer-instrumented targets and turning
their output into triageable crash reports. Built for reverse-engineering
work where the target may be a Rust crate, a C/C++ library behind an FFI
boundary, a stripped binary running under QEMU, or a firmware image.

The design, math, and operating modes are in [SPEC.md](./SPEC.md). This
README covers what's implemented, how to build it, and how to use it.

## About

`asan-harness` sits between a memory-safety sanitizer and a human analyst.
It reads the raw sanitizer events a target emits, classifies each one
(heap-buffer-overflow, use-after-free, double-free, and so on), attaches
alloc and free provenance when available, and produces a stable JSON
report that downstream tools (triage, minify, replay) can consume.

The goal is a single pipeline that works across the common
reverse-engineering modes:

- source-available Rust or C/C++ rebuilt with `-fsanitize=address`
- closed-source shared libraries instrumented via Frida
- stripped binaries executed under QEMU with QASan
- firmware images re-hosted on Unicorn or QEMU system-mode

The sanitizer math, invariants, and the boundary of what the tool can and
cannot detect are all documented in `SPEC.md`. This repository is the
implementation.

## Status

What runs today:

- Parser for compiler-rt AddressSanitizer stderr (heap-buffer-overflow,
  stack-buffer-overflow, heap-use-after-free, double-free, invalid-free,
  stack-use-after-{return,scope}). Handles both the legacy
  `to the right of` phrasing and the LLVM 20+ `N bytes after` form.
- Crash report type with stable JSON schema (`schema_version = 1`),
  FNV-1a-64 dedup hash over the top-N symbolicated frames, severity
  ranking per SPEC §12.2.
- CLI: `doctor`, `ingest`, `triage`, `replay`, `minify`.
- Delta-debugging minimiser (`ddmin`) that shrinks inputs against any
  user-supplied predicate.
- In-memory corpus with Shannon-entropy weighted selection
  (SPEC §8.4).
- End-to-end demo: Rust binary under nightly `-Zsanitizer=address` **or**
  C library compiled with `clang -fsanitize=address` → harness ingests,
  clusters, replays.

What's a stub:

- `asan-re-frida` (Mode B), `asan-re-qemu` (Mode C), `asan-re-firmware`
  (Mode D). The `Sanitizer` trait implementations return
  `SanError::Runtime("not yet implemented")` rather than silently passing,
  so a misconfigured harness fails loudly.
- `asan-harness run` and `cov` subcommands. Wiring to `libafl_libfuzzer`
  is not in place; the `fuzz_target!` macro emits the libFuzzer ABI but
  nothing drives it yet.

## Build

Stable toolchain for the harness itself:

```sh
cargo build --workspace
cargo test --workspace
```

The two demo crates (`rust-asan`, `c-ffi-asan`) require nightly because
they depend on `-Zsanitizer=address`:

```sh
RUSTFLAGS="-Zsanitizer=address" \
    cargo +nightly build \
        --target x86_64-unknown-linux-gnu \
        -p rust-asan -p c-ffi-asan
```

`c-ffi-asan` additionally requires `clang` on PATH; its `build.rs`
invokes `clang -fsanitize=address -O0` on `c/buggy.c`.

## Use

End-to-end against real ASan output:

```sh
./target/x86_64-unknown-linux-gnu/debug/rust-asan-demo hbo 2>asan.log
cargo run -q --bin asan-harness -- ingest --file asan.log --out-dir crashes/
cargo run -q --bin asan-harness -- triage --dir crashes/
```

Machine-readable output:

```sh
asan-harness --format json ingest --file asan.log
asan-harness --format json triage --dir crashes/
```

Minify a crash report against a synthetic predicate (standalone; no
target required):

```sh
asan-harness minify crash.json --keep-byte 0x41 --out crash.min.json
```

The full pipeline (build both demos, run every bug mode, assert six
distinct clusters):

```sh
./scripts/verify-asan.sh
```

## Layout

```
crates/
  asan-core       Sanitizer trait; shadow-memory math and invariants (§2).
  asan-alloc      GlobalAlloc wrapper routing allocator events through a Sanitizer.
  asan-oracle     CrashReport/CrashKind/Severity; FNV-1a dedup; ASan log parser.
  asan-driver     Target/Oracle traits; fuzz_target! macro; replay runner; ddmin.
  asan-corpus     Seed corpus with Shannon-entropy weighted selection (§8.4).
  asan-re-frida   Mode B stub (closed-source .so via Frida).
  asan-re-qemu    Mode C stub (stripped binary via QEMU/QASan).
  asan-re-firmware Mode D stub (firmware re-hosting).
  asan-cli        `asan-harness` binary.

examples/
  demo            Canned ASan fixtures → CrashReport → triage.
  rust-asan       Rust binary with planted bugs; requires nightly ASan.
  c-ffi-asan      C library (ASan-instrumented) + Rust FFI harness.

scripts/
  verify-asan.sh  End-to-end pipeline verification.
```

## Tests

```
asan-oracle  20 tests   (CrashReport, dedup, log parser, schema)
asan-core    15 tests   ( 9 proptest properties for shadow invariants)
asan-driver   7 tests   (Target/Oracle, replay, ddmin)
asan-corpus   4 tests   (entropy, rare-edge dominance, determinism)
asan-alloc    2 tests
─────────────────────
             48 tests passing
```

`cargo clippy --workspace --all-targets -- -D warnings` passes clean.

## Scope

The harness reports memory-safety facts that AddressSanitizer observes.
It does not find uninitialized reads (MemorySanitizer), data races
(ThreadSanitizer), integer-overflow UB (UBSan), or intra-object
overflow. It does not predict exploitability. See SPEC §14 for the full
list of what this tool cannot see.

## License

Apache-2.0 OR MIT (dual).
