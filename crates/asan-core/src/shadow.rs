//! Shadow-memory mapping and byte encoding.
//!
//! Canonical math from SPEC §2. These functions are `const` and `#[inline]`
//! wherever possible so backends that want to inline the fast path can do so
//! without crossing a crate boundary.
//!
//! The default offset here matches compiler-rt on x86-64 Linux. Real backends
//! may override it (e.g. `libafl_asan` in a QEMU guest picks a different
//! offset based on guest VA layout). All invariant checks are
//! offset-parameterised so they remain correct in every mode.

/// 8 application bytes → 1 shadow byte. SPEC §2.1.
pub const SHADOW_SCALE: u32 = 3;

/// Granularity of shadow coverage (= `1 << SHADOW_SCALE`). Every allocation
/// alignment, redzone size, and partial-granularity byte is derived from this.
pub const SHADOW_GRANULARITY: usize = 1 << SHADOW_SCALE;

/// Default compiler-rt shadow offset on x86-64 Linux. SPEC §2.1.
///
/// Chosen so user VA never collides with shadow VA. A real backend re-reads
/// this from `__asan_shadow_memory_dynamic_address` when compiler-rt is in
/// dynamic-shadow mode (Windows, Android, QEMU user-mode).
pub const SHADOW_OFFSET_DEFAULT: u64 = 0x0000_7fff_8000;

/// Compute the shadow byte address for a given application address.
///
/// `shadow(addr) = (addr >> SHADOW_SCALE) + offset`  (SPEC §2.1)
#[inline]
pub const fn shadow_addr(app_addr: u64, offset: u64) -> u64 {
    (app_addr >> SHADOW_SCALE) + offset
}

/// A single shadow byte's interpretation. SPEC §2.2.
///
/// Values match compiler-rt so byte-level dumps of our shadow region are
/// readable by existing tools (`asan_symbolize.py`, `llvm-symbolizer`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowByte {
    /// All 8 bytes in this chunk are addressable.
    Accessible = 0x00,
    HeapLeftRedzone = 0xFA,
    HeapRightRedzone = 0xFB,
    StackLeftRedzone = 0xFC,
    StackMidRedzone = 0xFD,
    GlobalRedzone = 0xFE,
    FreedHeap = 0xFF,
}

/// Qualitative category of a poison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoisonKind {
    /// `0x00..=0x07`: first N bytes accessible. N=0 means a fully-accessible
    /// 8-byte granule; that is represented as `Accessible` in `ShadowByte`.
    PartialGranularity { n_accessible: u8 },
    HeapRedzone,
    StackRedzone,
    GlobalRedzone,
    FreedHeap,
    Other,
}

/// Classify a raw shadow byte. See SPEC §2.2 table.
#[inline]
pub const fn poison_kind_of(raw: u8) -> PoisonKind {
    match raw {
        0x00..=0x07 => PoisonKind::PartialGranularity { n_accessible: raw },
        0xFA | 0xFB => PoisonKind::HeapRedzone,
        0xFC | 0xFD => PoisonKind::StackRedzone,
        0xFE => PoisonKind::GlobalRedzone,
        0xFF => PoisonKind::FreedHeap,
        _ => PoisonKind::Other,
    }
}

/// Is an access of `k` bytes at app address `addr` (with known `addr & 7`
/// offset inside the 8-byte granule) legal given the shadow byte `s`?
///
/// Implements the fast-path check from SPEC §2.2:
///
/// ```text
/// let last_accessed = (addr & 7) + (k - 1);
/// legal = s == 0 || last_accessed < s as i8
/// ```
///
/// Access sizes `k > 8` must be split by the caller; this function assumes
/// `addr_low .. addr_low + k` stays within a single 8-byte granule.
#[inline]
pub const fn is_accessible_shadow(s: u8, addr_low: u8, k: u8) -> bool {
    if s == 0 {
        return true;
    }
    // Partial granularity: first `s` bytes accessible, rest not.
    // Works only when s is in [1, 7]. Outside that range the byte is poison,
    // which means inaccessible by definition.
    if s >= 0x80 {
        return false;
    }
    let last = addr_low.wrapping_add(k).wrapping_sub(1);
    last < s
}

/// Kind of memory access being checked. Used by [`crate::Sanitizer::check_access`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessKind {
    Load,
    Store,
    Atomic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_scale_is_three() {
        // Anchor: if this constant ever changes, every invariant in SPEC §2
        // must be re-derived. Breaking this test is intentional.
        assert_eq!(SHADOW_SCALE, 3);
        assert_eq!(SHADOW_GRANULARITY, 8);
    }

    #[test]
    fn shadow_mapping_matches_spec_2_1() {
        // SPEC §2.1: shadow(addr) = (addr >> 3) + offset
        let offset = SHADOW_OFFSET_DEFAULT;
        assert_eq!(shadow_addr(0x1000, offset), 0x200 + offset);
        assert_eq!(shadow_addr(0x1007, offset), 0x200 + offset);
        assert_eq!(shadow_addr(0x1008, offset), 0x201 + offset);
    }

    #[test]
    fn fully_accessible_granule_allows_all_accesses() {
        for lo in 0..8u8 {
            for k in [1u8, 2, 4, 8] {
                if u16::from(lo) + u16::from(k) <= 8 {
                    assert!(is_accessible_shadow(0, lo, k), "lo={lo} k={k}");
                }
            }
        }
    }

    #[test]
    fn partial_granule_matches_spec_2_2_formula() {
        // Shadow byte 5 = first 5 bytes accessible (indices 0..5).
        assert!(is_accessible_shadow(5, 0, 1));   // byte 0
        assert!(is_accessible_shadow(5, 4, 1));   // byte 4
        assert!(!is_accessible_shadow(5, 5, 1));  // byte 5 — poisoned
        assert!(!is_accessible_shadow(5, 4, 4));  // bytes 4..8 — crosses
    }

    #[test]
    fn poison_bytes_always_reject() {
        for byte in [0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF] {
            assert!(!is_accessible_shadow(byte, 0, 1));
            assert!(!is_accessible_shadow(byte, 7, 1));
        }
    }

    #[test]
    fn poison_classification_matches_spec_2_2() {
        assert!(matches!(
            poison_kind_of(0xFA),
            PoisonKind::HeapRedzone
        ));
        assert!(matches!(
            poison_kind_of(0xFF),
            PoisonKind::FreedHeap
        ));
        assert!(matches!(
            poison_kind_of(0xFE),
            PoisonKind::GlobalRedzone
        ));
        assert!(matches!(
            poison_kind_of(5),
            PoisonKind::PartialGranularity { n_accessible: 5 }
        ));
    }
}
