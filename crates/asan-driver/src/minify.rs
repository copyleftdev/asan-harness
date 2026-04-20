//! Delta-debugging minimizer.
//!
//! Shrinks a crashing input while preserving a user-supplied predicate —
//! typically "reproduces the same crash kind and dedup hash" (SPEC §12.1,
//! §10.4). The algorithm is Zeller's classical `ddmin`: start by splitting
//! into `n=2` chunks, try removing each single chunk, then try removing
//! each (n-1)-complement, then double `n` and retry. Stop when `n` exceeds
//! the input length, which is the algorithm's fixed point.
//!
//! The minimizer is oracle-agnostic: it is parameterised on a `FnMut(&[u8])
//! -> bool` predicate. The harness CLI wires this predicate to
//! `run_target(candidate).dedup_hash == stored.dedup_hash`.
//!
//! # Complexity
//!
//! Worst-case `O(n²)` predicate invocations for input length `n`. In
//! practice the first few rounds remove most of the input, so the observed
//! cost is closer to `O(n log n)`. No-one cares: the crashing input is
//! always much smaller than the corpus it came from.

/// Reduce `input` while `predicate(candidate)` returns true.
///
/// Guarantees:
/// - Returned slice is ⊆ input (by contiguous substring concatenation).
/// - `predicate(returned)` is true (if `predicate(input)` was true on entry).
/// - Returned length is 1-minimal: no single-byte removal still reproduces.
pub fn ddmin<F>(input: &[u8], mut predicate: F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    // If the original doesn't reproduce, we have nothing to shrink.
    if !predicate(input) {
        return input.to_vec();
    }
    let mut cur: Vec<u8> = input.to_vec();
    let mut n: usize = 2;

    loop {
        if cur.len() < 2 {
            break;
        }
        let chunk_size = cur.len().div_ceil(n.max(2));
        let mut progressed = false;

        // Phase 1: try removing one chunk at a time.
        let mut i = 0;
        while i < cur.len() {
            let end = (i + chunk_size).min(cur.len());
            let mut candidate = Vec::with_capacity(cur.len() - (end - i));
            candidate.extend_from_slice(&cur[..i]);
            candidate.extend_from_slice(&cur[end..]);
            if !candidate.is_empty() && predicate(&candidate) {
                cur = candidate;
                progressed = true;
                n = 2.max(n.saturating_sub(1));
                break;
            }
            i += chunk_size;
        }

        if progressed {
            continue;
        }

        // Phase 2: try removing complements (keep only one chunk).
        //
        // This catches cases where the crash needs *some* chunk but most
        // of the input is ballast. We loop over "which chunk to keep".
        if n > 2 {
            let mut i = 0;
            while i < cur.len() {
                let end = (i + chunk_size).min(cur.len());
                let candidate = cur[i..end].to_vec();
                if !candidate.is_empty() && predicate(&candidate) {
                    cur = candidate;
                    progressed = true;
                    n = 2;
                    break;
                }
                i += chunk_size;
            }
            if progressed {
                continue;
            }
        }

        // Phase 3: increase granularity and retry.
        if n >= cur.len() {
            break;
        }
        n = (n * 2).min(cur.len());
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shrink a string down to the first byte that equals b'X'.
    /// A classic ddmin benchmark: the predicate cares only about one byte.
    #[test]
    fn shrinks_to_single_required_byte() {
        let input = b"aaaXaaa";
        let out = ddmin(input, |c| c.contains(&b'X'));
        assert_eq!(out, b"X");
    }

    #[test]
    fn preserves_input_when_predicate_false() {
        let input = b"hello";
        let out = ddmin(input, |c| c == b"never-matches");
        assert_eq!(out, input);
    }

    #[test]
    fn minimizes_across_long_inputs() {
        let input: Vec<u8> = (0..2048).map(|i| i as u8).collect();
        // Crash requires both 0x42 and 0x7F present.
        let out = ddmin(&input, |c| c.contains(&0x42) && c.contains(&0x7F));
        assert!(out.contains(&0x42) && out.contains(&0x7F));
        assert!(out.len() <= 64, "expected aggressive shrink, got {} bytes", out.len());
    }

    #[test]
    fn one_byte_inputs_are_preserved() {
        let input = [0xAAu8];
        let out = ddmin(&input, |c| c == [0xAA]);
        assert_eq!(out, input);
    }

    #[test]
    fn contiguous_pair_requirement() {
        // Predicate needs two adjacent 0xFF bytes somewhere in the input.
        let input: Vec<u8> = b"abcde".iter().chain([0xFFu8, 0xFF].iter()).chain(b"fghij").copied().collect();
        let out = ddmin(&input, |c| c.windows(2).any(|w| w == [0xFF, 0xFF]));
        assert_eq!(out, [0xFF, 0xFF]);
    }
}
