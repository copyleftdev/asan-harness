//! Rust harness that FFI-calls into an ASan-instrumented C library.
//!
//! The C library (`c/buggy.c`) is compiled by `build.rs` with
//! `-fsanitize=address`. This Rust binary must be compiled with
//! `-Zsanitizer=address` so the runtimes match and the linker pulls in
//! `libclang_rt.asan-*`.
//!
//! Build:
//!
//! ```sh
//! RUSTFLAGS="-Zsanitizer=address" \
//!     cargo +nightly build -p c-ffi-asan \
//!         --target x86_64-unknown-linux-gnu
//! ```
//!
//! Run:
//!
//! ```sh
//! ./target/x86_64-unknown-linux-gnu/debug/c-ffi-asan-demo hbo 2>asan.log
//! ```

use std::env;
use std::process::ExitCode;

extern "C" {
    fn buggy_parse_hbo(input: *const u8, len: usize);
    fn buggy_parse_uaf(input: *const u8, len: usize) -> u8;
    fn buggy_parse_df(input: *const u8, len: usize);
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let payload: [u8; 8] = *b"ABCDEFGH";
    let mode = args.get(1).map_or("help", String::as_str);
    match mode {
        "hbo" => unsafe { buggy_parse_hbo(payload.as_ptr(), payload.len()) },
        "uaf" => unsafe {
            let b = buggy_parse_uaf(payload.as_ptr(), payload.len());
            std::hint::black_box(b);
        },
        "df" => unsafe { buggy_parse_df(payload.as_ptr(), payload.len()) },
        "clean" => {
            println!("clean exit — no bugs exercised");
            return ExitCode::from(0);
        }
        _ => {
            let prog = &args[0];
            eprintln!("usage: {prog} {{hbo|uaf|df|clean}}");
            return ExitCode::from(2);
        }
    }
    ExitCode::from(0)
}
