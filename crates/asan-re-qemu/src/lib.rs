//! Mode C — stripped-binary harnessing via QEMU user-mode (QASan).
//!
//! SPEC §7.3. Layers `libafl_qemu` under the [`asan_core::Sanitizer`]
//! trait. Uses QEMU TCG memory hooks to intercept every guest load/store
//! and consult a shadow map (SPEC §2) maintained in host memory.
//!
//! Compared to Mode A the slowdown is 30–50× (SPEC §7.3). Compared to Mode B
//! it gains full OOB detection at the cost of requiring TCG emulation.

#![forbid(unsafe_op_in_unsafe_fn)]

use asan_core::{AccessKind, SanError, SanReport, Sanitizer};

#[derive(Debug, Default)]
pub struct QemuSanitizer;

impl QemuSanitizer {
    pub const UNIMPLEMENTED: &'static str =
        "asan-re-qemu: Mode C not yet implemented; see SPEC §7.3 and enable the `real` feature";
}

impl Sanitizer for QemuSanitizer {
    fn on_alloc(&self, _: *mut u8, _: usize) {}
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
