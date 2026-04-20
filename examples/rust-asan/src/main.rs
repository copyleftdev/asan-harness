//! Rust binary with planted memory-safety bugs.
//!
//! Intended to be compiled under nightly with `-Zsanitizer=address`:
//!
//! ```sh
//! RUSTFLAGS="-Zsanitizer=address" \
//!     cargo +nightly build -p rust-asan \
//!         --target x86_64-unknown-linux-gnu
//! ./target/x86_64-unknown-linux-gnu/debug/rust-asan-demo hbo 2>asan.log
//! ```
//!
//! Each mode triggers one canonical sanitizer event:
//!
//! | arg   | bug                                |
//! |-------|------------------------------------|
//! | `hbo` | heap-buffer-overflow, 4-byte right |
//! | `uaf` | heap-use-after-free                |
//! | `df`  | double-free                        |
//!
//! The asan-harness parser (`asan_oracle::parse_asan_log`) consumes the
//! emitted stderr and produces a stable CrashReport. The round-trip from
//! real sanitizer output through our pipeline is what turns this crate
//! from a toy into a usable RE harness.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map_or("help", String::as_str);
    match mode {
        "hbo" => heap_buffer_overflow(),
        "uaf" => use_after_free(),
        "df" => double_free(),
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

/// Heap-buffer-overflow: write 4 bytes past the end of a 16-byte allocation.
///
/// Under `-Zsanitizer=address`, the final write hits a shadow byte poisoned
/// by the right redzone (SPEC §2.2, value `0xFB`) and aborts with
/// `heap-buffer-overflow on address ...`.
#[inline(never)]
fn heap_buffer_overflow() {
    let mut v: Vec<u8> = vec![0u8; 16];
    let p = v.as_mut_ptr();
    unsafe {
        // In-bounds stores so the compiler can't statically prove UB without
        // actually running the code.
        for i in 0u8..16 {
            *p.add(usize::from(i)) = i;
        }
        // 4 bytes past the end.
        *p.add(20) = 0x41;
    }
    std::hint::black_box(&v);
}

/// Use-after-free: drop the Vec, then read through a dangling raw pointer.
#[inline(never)]
fn use_after_free() {
    let v: Vec<u8> = vec![0xAA; 32];
    let p = v.as_ptr();
    drop(v);
    let stolen = unsafe { core::ptr::read_volatile(p) };
    std::hint::black_box(stolen);
}

/// Double-free: synthesize two Vecs from the same raw pointer.
///
/// `Vec::from_raw_parts` + duplicate consumption is the direct way to
/// trigger a double-free under the ASan allocator.
#[inline(never)]
fn double_free() {
    let layout = std::alloc::Layout::from_size_align(32, 8).unwrap();
    unsafe {
        let p = std::alloc::alloc(layout);
        assert!(!p.is_null());
        std::alloc::dealloc(p, layout);
        // Second dealloc of the same pointer under the ASan allocator triggers
        // "attempting double-free".
        std::alloc::dealloc(p, layout);
    }
}
