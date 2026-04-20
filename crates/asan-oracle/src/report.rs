//! Crash report shape — stable machine-readable schema.
//!
//! SPEC §10.3, §11 (determinism), §12 (triage).

use crate::{dedup, CrashKind, OracleError, Severity};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    pub ip: u64,
    pub symbol: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Backtrace {
    pub frames: Vec<Frame>,
}

impl Backtrace {
    pub fn empty() -> Self {
        Self { frames: Vec::new() }
    }

    /// Capture the current stack. Heavy; call it at the crash site, not in
    /// hot paths.
    pub fn capture_current() -> Self {
        let raw = backtrace::Backtrace::new();
        let mut frames = Vec::with_capacity(raw.frames().len());
        for f in raw.frames() {
            let ip = f.ip() as u64;
            let mut sym = None;
            let mut file = None;
            let mut line = None;
            for s in f.symbols() {
                if sym.is_none() {
                    sym = s.name().map(|n| n.to_string());
                }
                if file.is_none() {
                    file = s.filename().map(|p| p.display().to_string());
                }
                if line.is_none() {
                    line = s.lineno();
                }
            }
            frames.push(Frame { ip, symbol: sym, file, line });
        }
        Self { frames }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrashReport {
    pub kind: CrashKind,
    pub severity: Severity,
    pub access_site: Backtrace,
    pub alloc_site: Option<Backtrace>,
    pub free_site: Option<Backtrace>,
    /// Stable dedup hash over top-N frames of [`access_site`]. SPEC §12.1.
    pub dedup_hash: u64,
    /// The raw input that triggered this crash, for SPEC §11 replay.
    pub raw_input: Vec<u8>,
    /// PRNG seed used by the mutator when this input was produced. §11.3.
    pub rng_seed: Option<u64>,
    /// Schema version for forward/backward compatibility.
    #[serde(default = "schema_version_default")]
    pub schema_version: u32,
}

fn schema_version_default() -> u32 {
    CrashReport::SCHEMA_VERSION
}

impl CrashReport {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn new(
        kind: CrashKind,
        access_site: Backtrace,
        alloc_site: Option<Backtrace>,
        free_site: Option<Backtrace>,
        raw_input: Vec<u8>,
    ) -> Self {
        let severity = kind.severity();
        let dedup_hash = dedup::dedup_hash(&access_site.frames, dedup::DEDUP_DEFAULT_DEPTH);
        Self {
            kind,
            severity,
            access_site,
            alloc_site,
            free_site,
            dedup_hash,
            raw_input,
            rng_seed: None,
            schema_version: Self::SCHEMA_VERSION,
        }
    }

    pub fn to_json(&self) -> Result<String, OracleError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json(s: &str) -> Result<Self, OracleError> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Result of a single execution's oracle evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Crash(CrashReport),
    Timeout { millis: u64 },
    OutOfMemory { bytes: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Side;

    #[test]
    fn roundtrip_json() {
        let report = CrashReport::new(
            CrashKind::HeapBufferOverflow { side: Side::Right },
            Backtrace { frames: vec![Frame { ip: 0x1000, symbol: Some("boom".into()), file: None, line: None }] },
            None,
            None,
            b"bad input".to_vec(),
        );
        let j = report.to_json().unwrap();
        let back = CrashReport::from_json(&j).unwrap();
        assert_eq!(back.kind, report.kind);
        assert_eq!(back.dedup_hash, report.dedup_hash);
        assert_eq!(back.raw_input, report.raw_input);
        assert_eq!(back.schema_version, CrashReport::SCHEMA_VERSION);
    }

    #[test]
    fn dedup_hash_is_set_on_construction() {
        let report = CrashReport::new(
            CrashKind::DoubleFree,
            Backtrace { frames: vec![Frame { ip: 0x1, symbol: Some("f".into()), file: None, line: None }] },
            None,
            None,
            Vec::new(),
        );
        assert_ne!(report.dedup_hash, 0);
    }
}
