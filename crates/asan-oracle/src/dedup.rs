//! Crash deduplication via FNV-1a-64 over the top N symbolicated frames.
//!
//! SPEC §12.1. Default depth = 3. Too deep → splits a single bug across many
//! buckets (hostile to the user). Too shallow → merges distinct bugs (hostile
//! to the truth).

use crate::report::Frame;

/// Default frame depth for dedup hashing. SPEC §12.1.
pub const DEDUP_DEFAULT_DEPTH: usize = 3;

/// FNV-1a-64 constants. RFC draft, de facto standard.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Compute the dedup hash over the first `depth` frames.
///
/// Frames without a symbol name contribute their instruction pointer in hex.
/// This keeps dedup meaningful for stripped binaries where only addresses are
/// available — accepting that ASLR may then split identical bugs across runs
/// (the SPEC §11 determinism pins ASLR to prevent exactly this).
pub fn dedup_hash(frames: &[Frame], depth: usize) -> u64 {
    let mut h = FNV_OFFSET_BASIS;
    for frame in frames.iter().take(depth) {
        let tag: &str = frame.symbol.as_deref().unwrap_or("");
        if tag.is_empty() {
            // Unsymbolicated: fall back to ip in lowercase hex so dedup is
            // still stable across runs *if* ASLR is pinned.
            let ip = format!("{:016x}", frame.ip);
            h = fnv1a_update(h, ip.as_bytes());
        } else {
            // Symbol present: hash the demangled symbol name.
            h = fnv1a_update(h, tag.as_bytes());
        }
        // Separator to prevent "foobar" + "" from hashing identical to "foo" + "bar".
        h = fnv1a_update(h, b"\x00");
    }
    h
}

#[inline]
fn fnv1a_update(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(sym: Option<&str>, ip: u64) -> Frame {
        Frame {
            ip,
            symbol: sym.map(String::from),
            file: None,
            line: None,
        }
    }

    #[test]
    fn identical_top_frames_hash_equal_even_if_deeper_frames_differ() {
        let a = vec![
            frame(Some("parse_header"), 0x1000),
            frame(Some("read_chunk"), 0x1100),
            frame(Some("main"), 0x1200),
            frame(Some("call_a"), 0x1300),
        ];
        let b = vec![
            frame(Some("parse_header"), 0x1000),
            frame(Some("read_chunk"), 0x1100),
            frame(Some("main"), 0x1200),
            frame(Some("call_b"), 0x1400), // differs, but beyond depth=3
        ];
        assert_eq!(dedup_hash(&a, 3), dedup_hash(&b, 3));
    }

    #[test]
    fn distinct_top_frames_hash_differently() {
        let a = vec![frame(Some("parse_header"), 0x1000)];
        let b = vec![frame(Some("parse_footer"), 0x1000)];
        assert_ne!(dedup_hash(&a, 3), dedup_hash(&b, 3));
    }

    #[test]
    fn separator_prevents_boundary_collisions() {
        // Without the NUL separator, "foo"+"bar" and "foobar"+"" would collide.
        let a = vec![
            frame(Some("foo"), 0),
            frame(Some("bar"), 0),
        ];
        let b = vec![
            frame(Some("foobar"), 0),
            frame(Some(""), 0),
        ];
        assert_ne!(dedup_hash(&a, 2), dedup_hash(&b, 2));
    }

    #[test]
    fn stripped_binaries_use_ip_hex() {
        let a = vec![frame(None, 0x7f1234)];
        let b = vec![frame(None, 0x7f1234)];
        let c = vec![frame(None, 0x7f1235)];
        assert_eq!(dedup_hash(&a, 3), dedup_hash(&b, 3));
        assert_ne!(dedup_hash(&a, 3), dedup_hash(&c, 3));
    }
}
