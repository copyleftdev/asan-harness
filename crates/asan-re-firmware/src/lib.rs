//! Mode D — firmware / exotic architecture re-hosting.
//!
//! SPEC §7.4. Uses Unicorn (or `libafl_qemu` system-mode) to emulate the
//! target CPU, and maintains a shadow map in the harness itself. Memory
//! callbacks fire per guest access; each consults the shadow map and
//! reports violations through the [`asan_core::Sanitizer`] contract.
//!
//! This is the most invasive mode — every MMIO peripheral needs a model
//! (Fuzzware / HALucinator style) — and is the slowest. It is also the
//! only option for IoT / baseband / MCU reverse engineering.

#![forbid(unsafe_op_in_unsafe_fn)]

use asan_core::{AccessKind, SanError, SanReport, Sanitizer};

#[derive(Debug, Default)]
pub struct FirmwareSanitizer;

impl FirmwareSanitizer {
    pub const UNIMPLEMENTED: &'static str =
        "asan-re-firmware: Mode D not yet implemented; see SPEC §7.4 and enable the `real` feature";
}

impl Sanitizer for FirmwareSanitizer {
    fn on_alloc(&self, _: *mut u8, _: usize) {}
    fn on_free(&self, _: *mut u8) -> Result<(), SanError> {
        Err(SanError::Runtime(Self::UNIMPLEMENTED))
    }
    fn check_access(&self, _: *const u8, _: usize, _: AccessKind) -> Result<(), SanError> {
        Err(SanError::Runtime(Self::UNIMPLEMENTED))
    }
    fn report(&self) -> SanReport {
        SanReport {
            summary: Self::UNIMPLEMENTED,
        }
    }
}
