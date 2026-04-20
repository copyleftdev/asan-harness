//! Crash classification, deduplication, and triage.
//!
//! Implements SPEC §12 (dedup hash, severity ranking) and §10.3 (CrashReport
//! types). The oracle is the layer that turns a raw memory-safety event into
//! a stable, reportable, comparable artifact.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

pub mod dedup;
pub mod log_parser;
pub mod report;

pub use dedup::{dedup_hash, DEDUP_DEFAULT_DEPTH};
pub use log_parser::{parse as parse_asan_log, parse_one as parse_asan_log_one};
pub use report::{Backtrace, CrashReport, Frame, Verdict};

/// The classification of a memory-safety violation.
///
/// Ordered by the default severity heuristic from SPEC §12.2. The enum
/// discriminant value is **not** the severity — use [`CrashKind::severity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CrashKind {
    HeapBufferOverflow { side: Side },
    StackBufferOverflow,
    GlobalBufferOverflow,
    UseAfterFree { quarantine_residence_ms: u64 },
    DoubleFree,
    InvalidFree,
    StackUseAfterReturn,
    StackUseAfterScope,
    MemoryLeak { bytes: u64 },
    /// A sanitizer error we could not attribute to any known kind.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Left,
    Right,
}

/// SPEC §12.2 severity ranking. Higher = more severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

impl CrashKind {
    /// Default severity per SPEC §12.2.
    ///
    /// This is a heuristic ranking of *memory-safety fact*, not exploitability.
    /// The harness explicitly refuses to predict exploitability (§12.2 final
    /// paragraph) — downstream analysts are responsible for that judgment.
    ///
    /// The explicit one-arm-per-variant form is deliberate: merging arms
    /// with identical bodies (which clippy suggests) would hide the
    /// auditable CrashKind → Severity mapping. An editor reading this
    /// function must see every classification decision at the call site.
    #[allow(clippy::match_same_arms)]
    pub const fn severity(&self) -> Severity {
        match self {
            // Arbitrary write primitives — top of the ladder.
            CrashKind::HeapBufferOverflow { side: Side::Right } => Severity::Critical,
            CrashKind::UseAfterFree { .. } => Severity::Critical,
            CrashKind::DoubleFree => Severity::High,
            CrashKind::HeapBufferOverflow { side: Side::Left } => Severity::High,
            CrashKind::StackBufferOverflow => Severity::High,
            CrashKind::StackUseAfterReturn => Severity::High,
            CrashKind::GlobalBufferOverflow => Severity::Medium,
            CrashKind::StackUseAfterScope => Severity::Medium,
            CrashKind::InvalidFree => Severity::Medium,
            CrashKind::MemoryLeak { .. } => Severity::Low,
            CrashKind::Unknown => Severity::Info,
        }
    }

    pub const fn short_name(&self) -> &'static str {
        match self {
            CrashKind::HeapBufferOverflow { .. } => "heap-buffer-overflow",
            CrashKind::StackBufferOverflow => "stack-buffer-overflow",
            CrashKind::GlobalBufferOverflow => "global-buffer-overflow",
            CrashKind::UseAfterFree { .. } => "use-after-free",
            CrashKind::DoubleFree => "double-free",
            CrashKind::InvalidFree => "invalid-free",
            CrashKind::StackUseAfterReturn => "stack-use-after-return",
            CrashKind::StackUseAfterScope => "stack-use-after-scope",
            CrashKind::MemoryLeak { .. } => "memory-leak",
            CrashKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("i/o failure: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering_matches_spec_12_2() {
        // SPEC §12.2 ordering: right-overflow ≥ UAF ≥ double-free ≥ OOB read ≥ invalid-free ≥ leak
        assert!(
            CrashKind::HeapBufferOverflow { side: Side::Right }.severity()
                >= CrashKind::UseAfterFree { quarantine_residence_ms: 0 }.severity()
        );
        assert!(
            CrashKind::UseAfterFree { quarantine_residence_ms: 0 }.severity()
                >= CrashKind::DoubleFree.severity()
        );
        assert!(CrashKind::DoubleFree.severity() >= CrashKind::InvalidFree.severity());
        assert!(CrashKind::InvalidFree.severity() >= CrashKind::MemoryLeak { bytes: 0 }.severity());
    }

    #[test]
    fn short_name_is_stable() {
        // The name is part of our machine-readable output contract.
        assert_eq!(
            CrashKind::HeapBufferOverflow { side: Side::Right }.short_name(),
            "heap-buffer-overflow"
        );
    }
}
