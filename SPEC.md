# asan-harness — Specification

A Rust-native harness for driving AddressSanitizer-equivalent memory-safety
telemetry against binaries (open or closed source) for reverse engineering
and vulnerability research.

This document captures the **math, physics, and invariants** that any correct
and competitive implementation must honor. It is descriptive of reality, not
prescriptive of taste.

---

## 0. Scope and Non-Goals

**In scope**
- Spatial memory safety (OOB read/write on heap, stack, globals)
- Temporal memory safety (use-after-free, double-free, invalid-free)
- Harnessing closed-source targets via FFI, emulation, or binary rewriting
- Rust-idiomatic API for corpus, mutation, oracle, and crash triage
- Coverage-guided fuzzing integration (libFuzzer, AFL++, LibAFL)
- Deterministic replay of crashing inputs

**Explicitly out of scope** (other sanitizers cover these — do not pretend otherwise)
- Uninitialized reads → MemorySanitizer (MSan)
- Data races → ThreadSanitizer (TSan)
- Integer overflow / signed shift UB → UBSan
- Type confusion across virtual dispatch → CFI / HWASan tagging
- Intra-object (sub-field) overflow → ASan cannot see it; needs typed bounds

Knowing what the tool **cannot** see is part of the truth.

---

## 1. First Principles

### 1.1 The observer effect

Any sanitizer perturbs the target: address space layout shifts, allocation
timing changes, shadow memory pollutes caches, forks reset PRNG state. A
harness must therefore distinguish:

1. **Intrinsic bugs** — present in the target under all executions.
2. **Harness-induced artifacts** — only reproduce with instrumentation.

Every reported crash must be reproducible under the *uninstrumented* target
(modulo the original corruption symptom), or it is suspect.

### 1.2 The harness trinity

A harness is defined by three functions over input space `I`:

```
drive  : I → Execution          (feeds input, runs target)
oracle : Execution → Verdict    (ok | crash(kind, site))
distil : Execution → Feedback   (coverage, novelty, distance)
```

Quality of the harness = quality of these three. Everything else is plumbing.

### 1.3 The fundamental trade-off

```
expected_bugs_per_second  =  throughput  ×  P(bug | execution)
                          =  (1/latency) × (coverage_density × bug_density)
```

Instrumentation *decreases* throughput but *increases* `P(bug | execution)` by
turning silent corruption into loud crashes. The harness must maximize the
product, not either factor.

---

## 2. Shadow Memory — The Math

### 2.1 Mapping

ASan compresses memory state via a **shadow map**:

```
shadow(addr) = (addr >> SHADOW_SCALE) + SHADOW_OFFSET
```

Defaults (x86-64 Linux, compatible with compiler-rt):
- `SHADOW_SCALE = 3`  →  8 application bytes map to 1 shadow byte
- `SHADOW_OFFSET = 0x00007fff_8000_0000`  (chosen so user VA never overlaps shadow VA)

**Why 8-to-1?**
- x86-64 minimum meaningful alignment for heap objects is 8 bytes.
- 8 bytes = one 64-bit word = one natural load.
- Enables a single shadow byte to encode *partial* granularity (see §2.2).

Memory overhead from the shadow map alone:
```
overhead_shadow = 2^(-SHADOW_SCALE) = 12.5 %
```

### 2.2 Shadow byte encoding

Each shadow byte `s` describes 8 application bytes:

| Value       | Meaning                                                 |
|-------------|---------------------------------------------------------|
| `0x00`      | All 8 bytes addressable                                 |
| `0x01..=0x07` | First `s` bytes addressable, remaining `8-s` are not   |
| `0x80..=0xFF` (negative) | All 8 bytes poisoned; low bits identify the poison kind |
| `0xFA`      | Heap left redzone                                       |
| `0xFB`      | Heap right redzone                                      |
| `0xFC`      | Stack left redzone                                      |
| `0xFD`      | Stack mid / right redzone (after return)                |
| `0xFE`      | Global redzone                                          |
| `0xFF`      | Freed heap memory                                       |
| `0xF1..=0xF9` | Stack-use-after-return / -scope variants              |

**Access check** for a load/store of `k` bytes at `addr` with `k ∈ {1,2,4,8}`:

```rust
let s = *shadow(addr);
if s != 0 {
    let last_accessed_byte = (addr & 7) as i8 + (k as i8 - 1);
    if last_accessed_byte >= s as i8 {
        report_error(addr, k);
    }
}
```

For `k = 16` (SSE) or larger, the check spans two shadow bytes and must be
split.

### 2.3 Invariants (must hold at all times)

Let `A` be the set of live allocations, `F` the set of quarantined allocations.

```
I1 (heap accessibility):
    ∀ a ∈ A, ∀ i ∈ [0, size(a)):   shadow(a + i) indicates byte i addressable

I2 (heap redzone):
    ∀ a ∈ A, ∀ i ∈ [−R_left, 0) ∪ [size(a), size(a) + R_right):
        shadow(a + i) ∈ { 0xFA, 0xFB }

I3 (quarantine):
    ∀ f ∈ F, ∀ i ∈ [0, size(f)):   shadow(f + i) = 0xFF

I4 (no aliasing):
    A ∩ F = ∅    (no live alloc shares bytes with a quarantined one)

I5 (shadow-of-shadow is poison):
    ∀ s in shadow region:   shadow(s) is marked inaccessible to user code
```

Violating I1–I5 causes either false negatives (missed bugs) or false
positives (phantom bugs). The harness must provide test vectors that
*assert* each invariant holds after every allocation event.

---

## 3. Redzone Physics

### 3.1 Detection probability

Given a redzone of `R` bytes on the far side of an allocation and a
contiguous overflow of `W` bytes past the end:

```
P(detect | contiguous, W bytes) = 1       if 1 ≤ W ≤ R
                                ≈ P(next region is instrumented)   if W > R
```

Non-contiguous overflow (single write at offset `k` past end):

```
P(detect | offset k) = 1                   if 1 ≤ k ≤ R
                     = P(shadow(&alloc + k) ≠ 0)    otherwise
                     ≈ ρ_instrumented       (fraction of heap covered by red or freed shadow)
```

### 3.2 Redzone sizing

Let `R` be redzone size, `N` allocation size. Per-allocation overhead:

```
overhead_per_alloc = (R_left + R_right) / N
```

For default `R = 16` and heap with mean allocation 64 bytes, per-object
overhead is 50 %. Total heap blow-up (empirical): 2–3×.

**Design choice**: scale `R` with allocation size (compiler-rt uses
`max(32, min(2048, N/8))`). This keeps overhead bounded *and* catches
large stride overflows.

### 3.3 Alignment tax

All heap allocations must round up to `1 << SHADOW_SCALE = 8` bytes so a
partial-granularity byte can exist only at the *end* of one chunk. A
21-byte `malloc` becomes a 24-byte allocation + redzones; the trailing 3
bytes of the last 8-byte chunk are marked with shadow value `5` (first 5
bytes accessible).

---

## 4. Temporal Safety — The Quarantine

### 4.1 Model

A free does not immediately return memory to the allocator. It goes to a
FIFO **quarantine** of capacity `Q` bytes. Memory only exits quarantine
when displaced by newer frees.

Let:
- `λ_free` = bytes freed per second
- `τ_q = Q / λ_free` = expected residence time

### 4.2 UAF detection probability

If buggy code dereferences a freed pointer `t` seconds after free:

```
P(detect UAF) = { 1                         if t < τ_q
                { α_reclaim(t - τ_q)        otherwise
```

where `α_reclaim` is the probability the region has *not* yet been
overwritten with a live allocation shadow-marked as accessible.

Consequence: increasing `Q` gives linear improvement up to memory budget,
then catastrophic slowdown when `Q` exceeds RSS working set × cache size.
Default `Q = 256 MB` is a Pareto point for typical targets.

### 4.3 Double-free detection

Trivial under the quarantine invariant: at `free(p)`, read `shadow(p)`.
If already `0xFF`, it is a double-free. If `0xFA`/`0xFB`, it is an
invalid free (middle of an allocation or unrelated address).

### 4.4 Quarantine and ASLR interaction

Randomizing *which* quarantined slot gets displaced (vs strict FIFO)
increases variance of `P(detect UAF)` but reduces worst-case attacker
control. For a fuzzing harness (our use case), strict FIFO is preferred
for determinism; for exploit-mitigation production use, randomized is
preferred.

---

## 5. Instrumentation Physics

### 5.1 Per-access cost

Inline fast path (`shadow == 0`):
```
shr   rax, 3                  ; 1 cycle
cmp   byte [rax + OFFSET], 0  ; 1 cycle + L1 hit (~4 cycles typical)
jne   slow_path               ; 1 cycle, predicted not-taken
```

Approx 3–5 cycles per memory access in the best case. Slow path (partial
granularity) adds 5–10 cycles. Reported compiler-rt slowdown: **1.5×–3×**
on general workloads, **10×** on pointer-heavy code.

### 5.2 Cache pressure

Every app load/store triggers a shadow-byte load. Because shadow is 8×
denser, *one shadow cache line (64 B) covers 512 B of application memory*.

Effective L1 utilization:
```
L1_effective = L1_size × (app / (app + shadow))
             = L1_size × (8 / 9)
             ≈ 0.89 × L1_size
```

This 11 % L1 tax is the *actual* irreducible cost of the technique. All
other overheads are addressable; this one is fundamental.

### 5.3 TLB pressure

Every memory access potentially touches two distinct 4 KB pages (app +
shadow). For working sets > TLB reach, TLB misses roughly double.
Hugepage-backing the shadow region is a known win (2 MB pages reduce
shadow TLB entries by 512×).

### 5.4 Branch prediction

Fast path is biased **not-taken** (most accesses hit zero-shadow). For
bug-dense code where the predictor learns to predict taken, a 10–15 cycle
mispredict penalty per access dominates. This is why **targeted**
harnessing (instrument only the hot target function) outperforms
whole-program instrumentation on pathological inputs.

### 5.5 Speculative execution

Branch-predicted past the `jne slow_path`, the CPU speculatively executes
the real memory operation. If shadow indicates poison but prediction
picks fast path, the poisoned access *has already happened* in the
shadow domain — visible via cache side channels. This is fine for
diagnosis (the crash still fires on retirement) but matters if ASan is
used as a *security barrier* (it is not; it is a debugging tool).

---

## 6. Rust-Specific Truths

### 6.1 Rust safe code is already spatially safe

Bounds-checked indexing, lifetime-verified references, and the absence
of pointer arithmetic mean `-Zsanitizer=address` on 100 % safe Rust
finds almost nothing. ASan matters in Rust at:

- `unsafe { ... }` blocks
- `extern "C"` FFI into C/C++ targets
- Custom `GlobalAlloc` or `Allocator` implementations
- Raw pointer arithmetic (`ptr::offset`, `slice::from_raw_parts`)
- `MaybeUninit` misuse
- Stack buffer reuse via `mem::transmute`

Harness design consequence: **the target of interest is almost always
behind an FFI boundary**. Rust is the driver, not the driven.

### 6.2 Miri vs ASan

| Property          | Miri                           | ASan                             |
|-------------------|--------------------------------|----------------------------------|
| Execution         | Interpreted MIR                 | Native, instrumented             |
| Speed             | 100–1000× slowdown              | 1.5–3× slowdown                  |
| Scope             | Rust only                       | Any LLVM-instrumented native     |
| Uninitialized     | Yes                             | No (MSan territory)              |
| Aliasing (SB/TB)  | Yes                             | No                               |
| FFI to binary     | No                              | Yes                              |
| Target for RE use | No                              | **Yes**                          |

A Rust ASan harness is not a replacement for Miri on pure-Rust code. It
is the only option for driving **native binary targets**.

### 6.3 Nightly `-Zsanitizer=address`

Available since 2019. Requires:
- Nightly toolchain
- `-Zbuild-std` to instrument libstd
- `RUSTFLAGS="-Zsanitizer=address"`
- Matching C/C++ deps compiled with `-fsanitize=address`

The harness must detect mismatched ASan runtimes between Rust and linked
C code (different shadow offsets → silent corruption of the shadow map).

### 6.4 `#[global_allocator]` swap

To hook allocations, the harness exposes:

```rust
#[global_allocator]
static GLOBAL: AsanAllocator = AsanAllocator::new();
```

where `AsanAllocator`:
1. Adds left+right redzones.
2. Poisons redzones in shadow.
3. Records allocation stack via `backtrace` crate.
4. On `dealloc`, poisons the region (`0xFF`) and pushes to quarantine
   rather than freeing to the system allocator.

### 6.5 Drop order and stack roots

Rust's deterministic drop order means a use-after-free of a Rust object
is a *logic bug* (dangling raw pointer captured before drop), not an
allocator race. The harness must record the drop call site, not just
the free call site, for useful triage.

---

## 7. Reverse Engineering Integration

Four operating modes, in order of preference when source is unavailable:

### 7.1 Mode A: Source-available dependency

Recompile the library with `-fsanitize=address`. Rust harness links
against it, drives via FFI. Lowest overhead, highest signal. Use when
possible.

### 7.2 Mode B: Closed-source shared library

- **Frida-based**: inject Frida into a Rust-driven process, hook
  allocators, implement shadow-less allocation tracking (heap
  metadata only). Catches UAF and double-free; does not catch OOB.
- **libdislocator** (AFL++): each allocation on its own page with
  `PROT_NONE` guard page. Catches OOB via segfault. No shadow memory
  required. Works on any binary.

### 7.3 Mode C: Pure binary blob, architecture-matched

- **QASan**: run target under QEMU-user with ASan checks synthesized in
  the TCG IR. 30–50× slowdown, but works on stripped binaries without
  recompilation.
- **E9Patch / DynamoRIO**: static or dynamic binary rewriting to insert
  shadow-byte checks. 2–5× slowdown, fragile on exotic code patterns.

### 7.4 Mode D: Firmware / exotic architecture

- **Unicorn + custom shadow**: emulate the target CPU, implement shadow
  memory in the harness itself, hook every memory callback.
- **Fuzzware / HALucinator**: re-host embedded firmware with symbolic
  MMIO models; ASan-equivalent checks on emulated RAM.

The harness crate **must** export a `Sanitizer` trait with
implementations for all four modes, selectable at harness-build time.

```rust
pub trait Sanitizer {
    fn on_alloc(&self, ptr: *mut u8, size: usize, stack: &Backtrace);
    fn on_free(&self, ptr: *mut u8, stack: &Backtrace) -> Result<(), SanError>;
    fn check_access(&self, ptr: *const u8, size: usize, kind: AccessKind) -> Result<(), SanError>;
    fn report(&self) -> SanReport;
}
```

---

## 8. Fuzzer Coupling

Bugs come from inputs. ASan reveals bugs that executions already exhibit
but normally mask. Therefore the fuzzer is the other half of the system.

### 8.1 libFuzzer protocol

```rust
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    let slice = unsafe { std::slice::from_raw_parts(data, size) };
    harness::drive(slice);
    0
}
```

### 8.2 AFL++ forkserver

A fork-server reduces per-execution cost to `fork()` (~1 ms) instead of
`exec()` (~10 ms). Persistent mode reduces further to loop iteration (~1 µs)
but requires the target to be *resettable* — i.e. the harness must
restore global state between iterations. This is a **hard** invariant.

### 8.3 Coverage feedback

`SanitizerCoverage` via `-Csanitizer-coverage-level=3`:

```
__sanitizer_cov_trace_pc_guard_init(start, stop)
__sanitizer_cov_trace_pc_guard(guard)
__sanitizer_cov_trace_cmp{1,2,4,8}(a, b)
__sanitizer_cov_trace_div{4,8}(a)
```

The harness records edge IDs into a shared bitmap. Corpus selection
criterion:

```
novelty(input) = |edges(input) \ edges(corpus)|
```

### 8.4 Information-theoretic prioritization

Corpus energy (Shannon-style):

```
H(corpus) = −Σ p(edge) log p(edge)
```

Seeds that *reduce* `H` (add rare edges) get higher selection weight.
Formal statement: expected information gain per mutation is maximized
when the seed is drawn proportional to `exp(−λ × hit_count(edge))` for
its rarest edge.

---

## 9. Performance Model

### 9.1 Throughput

```
executions_per_second = 1 / (T_reset + T_exec × slowdown_asan)
```

With persistent-mode reset (~1 µs), a 10 µs target becomes ~20 µs
under 2× slowdown → ~50k exec/s per core.

### 9.2 Time to bug

Let `ρ = P(bug | single execution)` for a bug of interest.

```
E[time to first crash] = 1 / (executions_per_second × ρ)
```

For a bug reachable on 1 in 10⁶ random inputs:
```
50_000 exec/s × 10⁻⁶ = 0.05 bugs/s  →  20 s expected
```

Coverage guidance transforms random ρ into *effective* ρ by focusing on
novel edges. Empirical multiplier: 100×–10 000× over pure random.

### 9.3 Parallel scaling (Amdahl, for fuzzing)

Multi-core fuzzing has a serial component: corpus sharing and
deduplication. Let `f_serial ≈ 0.01` (1 % of runtime spent on corpus
sync).

```
speedup(N) = 1 / (f_serial + (1 − f_serial) / N)
```

Ceiling: `1/f_serial = 100×`. Hence mesh-of-workers designs (LibAFL
EventManager) prefer peer-to-peer corpus gossip over centralized
coordinator.

---

## 10. Proposed Crate Architecture

### 10.0 Vendoring decision

**We build on [LibAFL](https://github.com/AFLplusplus/LibAFL)** (AFLplusplus
org, Apache-2.0/MIT, v0.15.4 as of 2025-11-12, ~14.7k monthly downloads).
It is the only Rust-native fuzzing framework that covers every operating
mode in §7 and ships a dedicated `libafl_asan` crate with a no_std,
dlmalloc-backed shadow implementation.

We do **not** reinvent:
- shadow mapping and poison encoding (`libafl_asan`)
- QEMU-user hooks / QASan (`libafl_qemu`)
- Frida instrumentation (`libafl_frida`)
- libFuzzer ABI compatibility (`libafl_libfuzzer`)
- LLMP multi-core corpus sync (`libafl_bolts`)

We **do** write:
- a unifying `Sanitizer` trait across modes A/B/C/D (§7)
- crash triage + dedup layer (§12)
- deterministic replay driver (§11)
- Rust `#[global_allocator]` integration (§6.4)
- the RE-focused CLI (§10.2)

### 10.1 Dependency mapping

| SPEC section | LibAFL crate             | Our crate                           |
|--------------|--------------------------|-------------------------------------|
| §2 Shadow    | `libafl_asan`            | `asan-core` (thin wrapper + asserts) |
| §6.4 Alloc   | `libafl_asan`            | `asan-alloc` (GlobalAlloc glue)     |
| §7 Mode A    | `libafl_targets`         | `asan-driver`                       |
| §7 Mode B    | `libafl_frida`           | `asan-re-frida`                     |
| §7 Mode C    | `libafl_qemu` (QASan)    | `asan-re-qemu`                      |
| §7 Mode D    | `libafl_qemu` + `libafl_nyx` | `asan-re-firmware`              |
| §8.1 libFuzzer | `libafl_libfuzzer`    | re-exported via `asan-driver`       |
| §8.3 SanCov  | `libafl_targets`         | `asan-driver`                       |
| §9.3 Parallel | `libafl_bolts` (LLMP)   | `asan-corpus`                       |

### 10.2 Workspace layout

```
asan-harness/
├── Cargo.toml                       # workspace; pins libafl = "0.15"
├── SPEC.md                          # this document
├── crates/
│   ├── asan-core/                   # re-export + runtime invariant asserts
│   ├── asan-alloc/                  # #[global_allocator] on libafl_asan
│   ├── asan-driver/                 # libFuzzer + AFL++ entry points
│   ├── asan-re-frida/               # Mode B
│   ├── asan-re-qemu/                # Mode C
│   ├── asan-re-firmware/            # Mode D
│   ├── asan-oracle/                 # crash classification, dedup hash
│   ├── asan-corpus/                 # seed storage, novelty selection
│   └── asan-cli/                    # `asan-harness run ...` binary
└── examples/
    ├── libpng-harness/              # Mode A
    ├── closed-so-frida/             # Mode B
    ├── stripped-binary-qemu/        # Mode C
    └── firmware-unicorn/            # Mode D
```

### 10.3 Core traits

```rust
/// The thing under test.
pub trait Target {
    type Input<'a>;
    fn run(&mut self, input: Self::Input<'_>) -> ExecResult;
}

/// Something that can detect a memory-safety violation.
pub trait Oracle {
    fn observe(&mut self, result: ExecResult) -> Verdict;
}

pub enum Verdict {
    Clean,
    Crash(CrashReport),
    Timeout,
    OutOfMemory,
}

pub struct CrashReport {
    pub kind: CrashKind,              // HeapBufferOverflow, UAF, ...
    pub access_site: Backtrace,
    pub alloc_site: Option<Backtrace>,
    pub free_site: Option<Backtrace>,
    pub dedup_hash: u64,              // hash of top N frames
    pub raw_input: Vec<u8>,
}

pub enum CrashKind {
    HeapBufferOverflow { left_or_right: Side },
    StackBufferOverflow,
    GlobalBufferOverflow,
    UseAfterFree { quarantine_residence_ms: u64 },
    DoubleFree,
    InvalidFree,
    StackUseAfterReturn,
    StackUseAfterScope,
    MemoryLeak,
}
```

### 10.4 CLI shape (Hashimoto-style, progressive disclosure)

```
asan-harness run     <target> --corpus DIR [--sanitizer=asan|qasan|frida|unicorn]
asan-harness replay  <crash.json>
asan-harness minify  <crash.json>
asan-harness triage  <corpus-dir>         # cluster crashes by dedup_hash
asan-harness cov     <target> --input FILE
asan-harness doctor                       # verify shadow/offset/runtime match
```

Output modes:
- Human: ANSI-colored crash report with source context.
- JSON: one crash per line, stable schema, suitable for pipelines.
- SARIF: for CI integration.

---

## 11. Determinism Requirements

Non-negotiable for a harness to be useful:

1. **Reproducible**: given the same corpus entry, target, and harness
   version, produce the same verdict (or document the non-determinism
   source: threading, `/dev/urandom`, time).
2. **Deterministic shadow mapping**: shadow offset chosen at harness
   init is logged; replay uses the same value.
3. **Seeded PRNG**: all mutator randomness is seeded; seed recorded in
   crash report.
4. **Pinned ASLR**: either disable (`setarch -R`) or record the base
   address of each loaded module per run.

---

## 12. Crash Triage — The "Truth" Layer

Not all crashes are the same bug. Deduplication is both an ergonomic
necessity and an information-theoretic operation.

### 12.1 Dedup hash

```
dedup(crash) = fnv1a_64(
    top_N_frames(crash.access_site)
        .map(|f| f.symbol_name)
        .concat()
)
```

Default `N = 3`. Tunable, because too-deep hashing splits one bug into
many (hostile to the user), and too-shallow hashing merges distinct bugs
(hostile to the truth).

### 12.2 Severity ranking

In order of default severity:

1. Arbitrary write primitive (heap overflow on attacker-controlled size).
2. Use-after-free with attacker-controlled reallocation window.
3. Double-free.
4. Out-of-bounds read.
5. Invalid free.
6. Memory leak (reported only with `detect_leaks=1`).

The harness must *not* invent exploitability claims. It reports the
memory-safety fact; exploitability is downstream analysis.

---

## 13. Validation Plan

A harness that claims to implement this spec must pass:

### 13.1 Oracle validation

A test battery of **known bugs** — e.g. the Juliet Test Suite subset for
CWE-121/122/124/126/127/415/416 — with labeled ground truth. Harness
must detect ≥ 95 % of labeled positives and produce ≤ 1 % false
positives on the negative controls.

### 13.2 Invariant property tests

Property-based tests (quickcheck-style) over I1–I5 from §2.3:

```
prop_heap_alloc_marks_accessible(size in 1..1024) {
    let p = alloc(size);
    for i in 0..size {
        assert!(shadow_accessible(p.add(i)));
    }
    for i in 1..=R {
        assert!(shadow_poisoned(p.add(size + i - 1)));
        assert!(shadow_poisoned(p.sub(i)));
    }
}
```

Run for ≥ 10⁶ iterations per property on every CI commit.

### 13.3 Performance regression

Benchmark corpus: libpng decode, sqlite amalgamation, rustls handshake,
one stripped ARM firmware blob. Track:
- `exec/sec` under each sanitizer mode
- RSS peak
- Shadow-check cache miss rate (measured via `perf stat`)

Regression > 10 % on any metric blocks merge.

### 13.4 Crash-replay determinism

For the latest 1000 crashes in the corpus, replay must reproduce bit-for-bit:
- Crash kind
- Top 5 frames
- Dedup hash

Non-determinism indicates a hidden source of entropy; must be logged and
attributed.

---

## 14. What This Tool Will Not Do (Repeated, Because It Matters)

- It will not find uninitialized reads. Use MSan.
- It will not find data races. Use TSan.
- It will not find intra-object overflow (e.g. overflowing field `a`
  into field `b` within a single allocation). No sanitizer does,
  without type information.
- It will not prove the *absence* of bugs. It reports bugs it observes
  on executed paths; unreached code is silent.
- It will not produce exploits. It produces crash reports with enough
  fidelity for a human analyst to reason about exploitability.

Claiming otherwise is dishonest and drives users to waste time chasing
ghosts.

---

## 15. Open Questions (to resolve before v0.1)

1. **Shadow implementation**: **Resolved** — use `libafl_asan`. It is
   no_std, dlmalloc-backed, and already correct. We wrap it, we do not
   replace it. Compiler-rt FFI remains available as a fallback feature
   flag for targets where matching ABIs with existing C/C++ ASan
   builds is required.
2. **Quarantine memory policy**: strict FIFO (deterministic, predictable
   memory ceiling) or randomized (better UAF detection variance)?
   Default strict; expose knob.
3. **Stack-use-after-return**: requires compiler cooperation
   (`-fsanitize-address-use-after-return`). Document as opt-in;
   incompatible with some ABIs.
4. **Leak detection**: LSan-style reachability scan on exit requires
   walking stacks and globals for pointers. Expensive; disabled by
   default.
5. **Fuzzer core**: **Resolved** — LibAFL. See §10.0.
6. **LibAFL version pinning policy**: track minor versions (currently
   0.15.x) with a stated 90-day window to absorb breaking changes
   after upstream release. Document each bump in `CHANGELOG.md`.

---

## 16. Version History

- **v0.0 (2026-04-19)**: initial spec. No implementation yet.

---

*"A memory sanitizer is not a mystery. It is a shadow, a redzone, and a
quarantine — and the discipline to keep their invariants under every
fork, every signal, every exit."*
