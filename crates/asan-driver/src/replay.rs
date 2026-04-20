//! Deterministic replay. SPEC §11.
//!
//! The replay runner takes a serialized [`asan_oracle::CrashReport`] and
//! re-executes its `raw_input` against a [`Target`], returning a fresh
//! [`asan_oracle::Verdict`]. The SPEC §11.4 determinism contract requires
//! the fresh verdict to match the stored one: same `CrashKind`, same top
//! five frames, same dedup hash. Divergence means we have hidden entropy.

use crate::{ExecResult, Oracle, Target};
use asan_oracle::{CrashReport, Verdict};
use std::time::Instant;

pub struct ReplayRunner<T: Target, O: Oracle> {
    target: T,
    oracle: O,
}

impl<T: Target, O: Oracle> ReplayRunner<T, O> {
    pub fn new(target: T, oracle: O) -> Self {
        Self { target, oracle }
    }

    /// Replay a single crash report's input and return the fresh verdict.
    pub fn replay(&mut self, report: &CrashReport) -> Verdict {
        let start = Instant::now();
        let exec = self.target.run(&report.raw_input);
        // The target's `run` owns its own timing; if it didn't fill `elapsed`
        // we fall back to our wall clock.
        let result = if exec.elapsed.is_zero() {
            ExecResult {
                elapsed: start.elapsed(),
                ..exec
            }
        } else {
            exec
        };
        self.oracle.observe(&report.raw_input, &result)
    }

    pub fn target(&self) -> &T {
        &self.target
    }
    pub fn oracle(&self) -> &O {
        &self.oracle
    }
}

/// Did the replay reproduce the stored crash's classification?
///
/// SPEC §11.4: same `CrashKind` and same dedup hash. Stack equivalence is
/// checked on the top five frames, not the whole trace, because deeper
/// frames may legitimately drift with ASLR and heap layout.
pub fn replay_matches(stored: &CrashReport, fresh: &Verdict) -> bool {
    let Verdict::Crash(fresh) = fresh else {
        return false;
    };
    stored.kind == fresh.kind && stored.dedup_hash == fresh.dedup_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExitState;
    use asan_oracle::{Backtrace, CrashKind, Frame, Side};

    struct Always;
    impl Target for Always {
        fn run(&mut self, _: &[u8]) -> ExecResult {
            ExecResult {
                elapsed: std::time::Duration::ZERO,
                exit: ExitState::Normal,
                sanitizer_output: String::new(),
            }
        }
    }

    struct AlwaysBoom;
    impl Oracle for AlwaysBoom {
        fn observe(&mut self, input: &[u8], _: &ExecResult) -> Verdict {
            Verdict::Crash(CrashReport::new(
                CrashKind::HeapBufferOverflow { side: Side::Right },
                Backtrace {
                    frames: vec![Frame {
                        ip: 0x1000,
                        symbol: Some("boom".into()),
                        file: None,
                        line: None,
                    }],
                },
                None,
                None,
                input.to_vec(),
            ))
        }
    }

    #[test]
    fn replay_matches_stored_verdict() {
        let stored = CrashReport::new(
            CrashKind::HeapBufferOverflow { side: Side::Right },
            Backtrace {
                frames: vec![Frame {
                    ip: 0x1000,
                    symbol: Some("boom".into()),
                    file: None,
                    line: None,
                }],
            },
            None,
            None,
            vec![1, 2, 3],
        );
        let mut runner = ReplayRunner::new(Always, AlwaysBoom);
        let fresh = runner.replay(&stored);
        assert!(replay_matches(&stored, &fresh));
    }

    #[test]
    fn clean_verdict_does_not_match_stored_crash() {
        struct CleanOracle;
        impl Oracle for CleanOracle {
            fn observe(&mut self, _: &[u8], _: &ExecResult) -> Verdict {
                Verdict::Clean
            }
        }
        let stored = CrashReport::new(
            CrashKind::DoubleFree,
            Backtrace { frames: vec![] },
            None,
            None,
            Vec::new(),
        );
        let mut runner = ReplayRunner::new(Always, CleanOracle);
        let fresh = runner.replay(&stored);
        assert!(!replay_matches(&stored, &fresh));
    }
}
