//! Build the C library with `-fsanitize=address`.
//!
//! The Rust binary links against this static archive *and* against the
//! ASan runtime (automatically pulled in when the Rust crate is built with
//! `-Zsanitizer=address`). If you build without `-Zsanitizer=address`, the
//! link step will fail — that failure is the whole point of this example,
//! because running ASan-instrumented code under a non-ASan runtime is
//! undefined behavior.

fn main() {
    let mut b = cc::Build::new();
    // -O0 is required: at -O1 the compiler eliminates dead stores past the
    // end of the buffer (the write is never read before `free`), which
    // means ASan has no instrumented access to check. Keeping -O0 preserves
    // the semantics of the planted bug.
    b.file("c/buggy.c")
        .flag("-fsanitize=address")
        .flag("-fno-omit-frame-pointer")
        .flag("-fno-optimize-sibling-calls")
        .flag("-O0")
        .flag("-g")
        .compiler("clang");
    b.compile("buggy");

    println!("cargo:rerun-if-changed=c/buggy.c");
    println!("cargo:rerun-if-changed=build.rs");
}
