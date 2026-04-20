//! Allocator instrumentation driving a [`Sanitizer`].
//!
//! This crate provides a thin wrapper over `std::alloc::System` that forwards
//! every allocation and free through a [`Sanitizer`] implementation. It is
//! **not** a `#[global_allocator]` on its own — installing it as the global
//! allocator requires a reentry-protected metadata store, which is left to
//! downstream backends (`libafl_asan` being the canonical one).
//!
//! # When to use this crate
//!
//! - You are writing a harness in Rust that drives an in-process target and
//!   want allocator events piped through your [`Sanitizer`].
//! - You want a reference implementation to test the [`Sanitizer`] trait
//!   contract without the complexity of a real shadow-memory runtime.
//!
//! # When not to use this crate
//!
//! - The target binary is already compiled with `-fsanitize=address`.
//!   Compiler-rt provides its own allocator. Do not double-hook.
//! - You are in Mode B/C/D (SPEC §7). Allocator events come from Frida/QEMU
//!   callbacks, not Rust's `alloc` API.

#![forbid(unsafe_op_in_unsafe_fn)]

use asan_core::Sanitizer;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;

/// Forwarder that converts the [`GlobalAlloc`] contract into [`Sanitizer`]
/// callbacks. Parameterised on a `Sanitizer` so tests can substitute
/// [`asan_core::NoopSanitizer`].
///
/// # Safety
///
/// The inner sanitizer is consulted on every alloc/dealloc. If the sanitizer
/// implementation itself allocates (e.g. records a backtrace through a
/// `Vec`), installing this as `#[global_allocator]` will deadlock or stack
/// overflow. Use a reentry-protected sanitizer, or call the wrapper
/// explicitly rather than going through the global allocator.
pub struct SanitizerAlloc<S: Sanitizer> {
    inner: Arc<S>,
}

impl<S: Sanitizer> SanitizerAlloc<S> {
    pub fn new(sanitizer: Arc<S>) -> Self {
        Self { inner: sanitizer }
    }

    pub fn sanitizer(&self) -> &S {
        &self.inner
    }
}

// Safety: we delegate to `System`, whose safety contract is upheld by std.
// We add bookkeeping that does not read or write the allocation's bytes.
unsafe impl<S: Sanitizer> GlobalAlloc for SanitizerAlloc<S> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.inner.on_alloc(ptr, layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SPEC §4.3: consult the sanitizer before releasing. A double-free
        // or invalid-free is not propagated here (GlobalAlloc has no error
        // channel); implementors typically abort via a panic in on_free.
        let _ = self.inner.on_free(ptr);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asan_core::{NoopSanitizer, SanError};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts calls so we can assert the hook fires.
    #[derive(Default)]
    struct CountingSanitizer {
        allocs: AtomicUsize,
        frees: AtomicUsize,
    }

    impl Sanitizer for CountingSanitizer {
        fn on_alloc(&self, _: *mut u8, _: usize) {
            self.allocs.fetch_add(1, Ordering::Relaxed);
        }
        fn on_free(&self, _: *mut u8) -> Result<(), SanError> {
            self.frees.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn check_access(
            &self,
            _: *const u8,
            _: usize,
            _: asan_core::AccessKind,
        ) -> Result<(), SanError> {
            Ok(())
        }
        fn report(&self) -> asan_core::SanReport {
            asan_core::SanReport {
                summary: "counting",
            }
        }
    }

    #[test]
    fn hooks_fire_on_alloc_and_dealloc() {
        let san = Arc::new(CountingSanitizer::default());
        let allocator = SanitizerAlloc::new(Arc::clone(&san));

        // Exercise the GlobalAlloc path directly; we are not installing it.
        let layout = Layout::from_size_align(64, 8).unwrap();
        let ptr = unsafe { allocator.alloc(layout) };
        assert!(!ptr.is_null());
        assert_eq!(san.allocs.load(Ordering::Relaxed), 1);

        unsafe { allocator.dealloc(ptr, layout) };
        assert_eq!(san.frees.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn noop_sanitizer_never_errors() {
        let san = Arc::new(NoopSanitizer);
        let allocator = SanitizerAlloc::new(san);
        let layout = Layout::from_size_align(16, 8).unwrap();
        let ptr = unsafe { allocator.alloc(layout) };
        unsafe { allocator.dealloc(ptr, layout) };
    }
}
