//! libFuzzer ABI entry point.
//!
//! SPEC §8.1. The emitted symbol is `LLVMFuzzerTestOneInput`, the contract
//! expected by compiler-rt libFuzzer and by `libafl_libfuzzer`. The macro
//! lets a harness author write:
//!
//! ```ignore
//! asan_driver::fuzz_target!(|data: &[u8]| {
//!     let _ = my_parser::parse(data);
//! });
//! ```
//!
//! and get the correct `extern "C"` entry point without touching unsafe
//! FFI glue.

/// Declare the libFuzzer entry point.
///
/// The body is called once per fuzzer iteration with a byte slice of the
/// current input. A return of `0` from `LLVMFuzzerTestOneInput` means
/// "input was consumed, continue"; non-zero means "reject this input as
/// invalid" and is reserved for input-filter harnesses.
#[macro_export]
macro_rules! fuzz_target {
    (|$data:ident: &[u8]| $body:block) => {
        #[no_mangle]
        pub extern "C" fn LLVMFuzzerTestOneInput(
            data: *const u8,
            size: usize,
        ) -> ::core::ffi::c_int {
            let $data: &[u8] = unsafe { ::core::slice::from_raw_parts(data, size) };
            let _ = (|| $body)();
            0
        }
    };
}
