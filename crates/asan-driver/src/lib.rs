//! Target + Oracle traits, plus fuzzer entry points.
//!
//! This crate is the bridge between the fuzzer (libFuzzer / AFL++) and the
//! target under test. Three things live here:
//!
//! 1. The [`Target`] trait — something that consumes an input.
//! 2. The [`Oracle`] trait — something that produces a verdict from an
//!    execution's observable state.
//! 3. The [`fuzz_target!`] macro — SPEC §8.1 libFuzzer ABI glue.
//!
//! # Split of responsibilities
//!
//! - `asan-core` owns the Sanitizer contract.
//! - `asan-alloc` owns in-process allocator hooks.
//! - `asan-oracle` owns crash classification + dedup.
//! - `asan-driver` (this crate) owns the fuzzer-side entry point and the
//!   top-level execution loop.
//!
//! This lets consumers pull in just the pieces they need — e.g. a pure
//! replayer tool depends only on `asan-oracle`, not on any fuzzer.

#![forbid(unsafe_op_in_unsafe_fn)]

use asan_oracle::Verdict;
use std::time::Duration;

/// A single unit of work to be driven by inputs.
///
/// Implementations are expected to be **resettable** (SPEC §8.2): after
/// `run` returns, any globals the target mutated must be restored, so the
/// next `run` sees a clean state. Non-resettable targets cannot use AFL++
/// persistent mode and must fork per execution.
pub trait Target {
    /// Process one input. Returns a coarse-grained execution result.
    fn run(&mut self, input: &[u8]) -> ExecResult;

    /// Reset state between executions, for persistent-mode fuzzing.
    /// Default no-op for stateless targets.
    fn reset(&mut self) {}

    /// Human-readable description, surfaced by `asan-harness doctor`.
    fn description(&self) -> &'static str {
        "unnamed target"
    }
}

/// Coarse execution outcome, handed to an [`Oracle`] for classification.
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub elapsed: Duration,
    pub exit: ExitState,
    /// Sanitizer-emitted diagnostic text (compiler-rt ASan spits human-readable
    /// reports to stderr; we capture them for triage). Empty if no event fired.
    pub sanitizer_output: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitState {
    Normal,
    Signal(i32),
    SanitizerAbort,
    Timeout,
}

/// Turns observable execution state into a [`Verdict`]. SPEC §10.3.
pub trait Oracle {
    fn observe(&mut self, input: &[u8], result: &ExecResult) -> Verdict;
}

pub mod fuzz_target;
pub mod minify;
pub mod replay;

pub use minify::ddmin;
pub use replay::ReplayRunner;
