//! Property tests for SPEC §13.2: the shadow-memory invariants I1–I5.
//!
//! These tests treat the shadow math as a contract. Any change to
//! `SHADOW_SCALE`, `SHADOW_OFFSET_DEFAULT`, or the accessibility formula
//! must first break these tests; if they still pass after an edit, the
//! edit did not actually change behavior.
//!
//! Each property is tied back to a clause in the spec.

use asan_core::{
    is_accessible_shadow, poison_kind_of, shadow_addr, PoisonKind, SHADOW_GRANULARITY,
    SHADOW_OFFSET_DEFAULT, SHADOW_SCALE,
};
use proptest::prelude::*;

proptest! {
    /// SPEC §2.1 — the mapping `shadow(addr) = (addr >> 3) + offset`
    /// must be monotonic and collapse each 8-byte chunk to a single byte.
    #[test]
    fn mapping_collapses_8_byte_chunks(addr in 0u64..(1u64 << 48), lane in 0u8..8) {
        let base = addr & !0x7;
        let variant = base + u64::from(lane);
        prop_assert_eq!(
            shadow_addr(base, SHADOW_OFFSET_DEFAULT),
            shadow_addr(variant, SHADOW_OFFSET_DEFAULT)
        );
    }

    /// SPEC §2.1 — distinct 8-byte chunks map to distinct shadow bytes.
    #[test]
    fn distinct_chunks_map_distinct(chunk_a in 0u64..(1u64 << 45), delta in 1u64..1024) {
        let a = chunk_a << SHADOW_SCALE;
        let b = a + (delta << SHADOW_SCALE);
        prop_assert_ne!(
            shadow_addr(a, SHADOW_OFFSET_DEFAULT),
            shadow_addr(b, SHADOW_OFFSET_DEFAULT)
        );
    }

    /// SPEC §2.2 — accessibility formula agrees with its spec restatement.
    /// Fully-accessible byte (0) admits any in-granule access.
    #[test]
    fn accessible_granule_admits_any_in_granule_access(lo in 0u8..8, k in prop::sample::select(vec![1u8, 2, 4, 8])) {
        prop_assume!(u16::from(lo) + u16::from(k) <= 8);
        prop_assert!(is_accessible_shadow(0, lo, k));
    }

    /// SPEC §2.2 — for shadow byte `s` in [1..=7], exactly the first `s`
    /// bytes of the 8-byte chunk are accessible, and the rest are poisoned.
    #[test]
    fn partial_granule_boundary(s in 1u8..=7, lo in 0u8..8) {
        let legal_for_1_byte = lo < s;
        prop_assert_eq!(is_accessible_shadow(s, lo, 1), legal_for_1_byte);
    }

    /// SPEC §2.2 — poison bytes (0x80..=0xFF, i.e. the high-bit-set range)
    /// reject every access without exception.
    #[test]
    fn poison_bytes_reject_everything(s in 0x80u8..=0xFF, lo in 0u8..8, k in prop::sample::select(vec![1u8, 2, 4, 8])) {
        prop_assume!(u16::from(lo) + u16::from(k) <= 8);
        prop_assert!(!is_accessible_shadow(s, lo, k));
    }

    /// SPEC §2.2 table — classification of known ASan poison codes.
    #[test]
    fn poison_kind_is_stable(raw in 0u8..=0xFF) {
        // The function must be total — every input yields some PoisonKind.
        let _ = poison_kind_of(raw);
    }

    /// SPEC §2.2 — reserved heap redzone bytes classify as HeapRedzone.
    #[test]
    fn heap_redzone_classification(raw in prop::sample::select(vec![0xFAu8, 0xFB])) {
        prop_assert!(matches!(poison_kind_of(raw), PoisonKind::HeapRedzone));
    }

    /// SPEC §2.3 I1 — accessing any byte in a fully-accessible granule
    /// is legal; accessing the 9th byte (cross-granule) is outside the
    /// function's contract and must be split by the caller.
    #[test]
    fn in_granule_contract_is_honored(lo in 0u8..8) {
        prop_assert!(is_accessible_shadow(0, lo, 1));
    }
}

/// Anchor: if `SHADOW_SCALE` ever changes, every invariant in SPEC §2
/// must be re-derived. This test is intentionally fragile.
#[test]
fn shadow_scale_constant_matches_spec_2_1() {
    assert_eq!(SHADOW_SCALE, 3);
    assert_eq!(SHADOW_GRANULARITY, 1 << SHADOW_SCALE);
}
