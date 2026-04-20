//! The Sanitizer trait and shadow-memory math.
//!
//! This crate is the stable contract. It does **not** itself link against any
//! particular sanitizer runtime — concrete implementations live in:
//!
//! - `asan-alloc`      — in-process via `libafl_asan` (SPEC §7 Mode A)
//! - `asan-re-frida`   — Mode B
//! - `asan-re-qemu`    — Mode C
//! - `asan-re-firmware` — Mode D
//!
//! The responsibilities of this crate are:
//!
//! 1. Define the [`Sanitizer`] trait that every mode implements.
//! 2. Provide the canonical shadow-memory mapping math from SPEC §2.
//! 3. Provide the shadow-byte encoding from SPEC §2.2.
//! 4. Provide runtime invariant checks (I1–I5 from SPEC §2.3) for testing
//!    and debug builds.
//!
//! # What this crate does not do
//!
//! It does not allocate. It does not install itself as `#[global_allocator]`.
//! It does not talk to a kernel. Those are the job of implementors.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod shadow;

pub use shadow::{
    is_accessible_shadow, poison_kind_of, shadow_addr, AccessKind, PoisonKind, ShadowByte,
    SHADOW_GRANULARITY, SHADOW_OFFSET_DEFAULT, SHADOW_SCALE,
};

/// Errors raised by [`Sanitizer`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SanError {
    #[error("access would violate sanitizer invariants at {ptr:#x} +{size}")]
    BadAccess {
        ptr: u64,
        size: usize,
        kind: AccessKind,
    },
    #[error("free of pointer not under sanitizer management: {ptr:#x}")]
    InvalidFree { ptr: u64 },
    #[error("double free detected at {ptr:#x}")]
    DoubleFree { ptr: u64 },
    #[error("sanitizer runtime error: {0}")]
    Runtime(&'static str),
}

/// Opaque report produced by a [`Sanitizer`] implementation.
///
/// Concrete sanitizer backends produce their own reports which are converted
/// to [`asan_oracle::CrashReport`] at the harness boundary.
#[derive(Debug, Clone)]
pub struct SanReport {
    pub summary: &'static str,
}

/// The single sanitizer contract across every operating mode (SPEC §7).
///
/// Implementors see allocations, frees, and individual memory accesses. They
/// decide whether each event is compliant with the shadow-memory invariants
/// (SPEC §2.3 I1–I5) and produce a [`SanError`] when it is not.
///
/// # Why a trait and not a concrete struct
///
/// Because Mode A (in-process libafl_asan), Mode B (Frida), Mode C (QEMU),
/// and Mode D (Unicorn/firmware) have disjoint implementation techniques but
/// share one observable contract. The trait is that contract.
pub trait Sanitizer: Send + Sync {
    /// Hook called after every live allocation. The pointer is the user-facing
    /// address, not including redzones. `size` is the requested size.
    fn on_alloc(&self, ptr: *mut u8, size: usize);

    /// Hook called at every free. Returns `Err(DoubleFree)` for repeat frees
    /// of a pointer already in the quarantine, or `Err(InvalidFree)` for
    /// pointers not produced by this allocator.
    fn on_free(&self, ptr: *mut u8) -> Result<(), SanError>;

    /// Check a single memory access. `size` is the number of bytes being
    /// read or written; `kind` distinguishes load vs store.
    ///
    /// Implementors may no-op this when checks are instrumented inline by
    /// the compiler (Mode A, `-Zsanitizer=address`). For Modes C/D that
    /// intercept emulated memory callbacks, this is the hot path.
    fn check_access(&self, ptr: *const u8, size: usize, kind: AccessKind) -> Result<(), SanError>;

    /// Produce a human-summary report. Used by `asan-harness doctor` to
    /// verify the sanitizer is live.
    fn report(&self) -> SanReport;
}

/// A no-op sanitizer for tests and for the `--sanitizer=off` CLI mode.
///
/// Never reports a violation. Useful as a control when measuring the
/// instrumentation tax from SPEC §5.
#[derive(Debug, Default)]
pub struct NoopSanitizer;

impl Sanitizer for NoopSanitizer {
    fn on_alloc(&self, _: *mut u8, _: usize) {}
    fn on_free(&self, _: *mut u8) -> Result<(), SanError> {
        Ok(())
    }
    fn check_access(&self, _: *const u8, _: usize, _: AccessKind) -> Result<(), SanError> {
        Ok(())
    }
    fn report(&self) -> SanReport {
        SanReport {
            summary: "noop sanitizer: all accesses pass",
        }
    }
}
