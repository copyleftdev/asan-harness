//! Mode B — closed-source shared-library harnessing via Frida.
//!
//! SPEC §7.2. This crate is a placeholder. The intended implementation
//! layers `libafl_frida` under the [`asan_core::Sanitizer`] trait, hooking
//! allocator symbols in the target library (`malloc`, `free`, `realloc`,
//! `calloc`, `memalign`, ...) and maintaining a shadow-less metadata map
//! to catch UAF / double-free.
//!
//! Out-of-bounds detection in this mode is best-effort: Frida cannot
//! instrument individual memory accesses efficiently, so OOB typically
//! requires guard pages (see `libdislocator`-style allocator) which this
//! crate will wire up once the `real` feature is enabled.

#![forbid(unsafe_op_in_unsafe_fn)]

use asan_core::{AccessKind, SanError, SanReport, Sanitizer};

/// Frida-based sanitizer. Currently a stub that refuses all operations.
///
/// A stub that silently passes every check would invite users to ship
/// broken harnesses; we fail loudly instead. SPEC §14: "Claiming otherwise
/// is dishonest and drives users to waste time chasing ghosts."
#[derive(Debug, Default)]
pub struct FridaSanitizer;

impl FridaSanitizer {
    pub const UNIMPLEMENTED: &'static str =
        "asan-re-frida: Mode B not yet implemented; see SPEC §7.2 and enable the `real` feature";
}

impl Sanitizer for FridaSanitizer {
    fn on_alloc(&self, _: *mut u8, _: usize) {
        // Allocator hooks are benign to drop — silent is acceptable here
        // because the allocation happened in the target regardless.
    }

    fn on_free(&self, _: *mut u8) -> Result<(), SanError> {
        Err(SanError::Runtime(Self::UNIMPLEMENTED))
    }

    fn check_access(&self, _: *const u8, _: usize, _: AccessKind) -> Result<(), SanError> {
        Err(SanError::Runtime(Self::UNIMPLEMENTED))
    }

    fn report(&self) -> SanReport {
        SanReport { summary: Self::UNIMPLEMENTED }
    }
}
