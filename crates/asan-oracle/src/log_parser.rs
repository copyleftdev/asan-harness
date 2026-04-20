//! Parser for compiler-rt AddressSanitizer stderr output.
//!
//! The ASan runtime emits human-readable reports when it detects a
//! violation. This module turns those reports into [`CrashReport`] values so
//! the harness can symbolicate, dedup, serialize, and replay them without
//! depending on the ASan runtime being live at report time.
//!
//! # Grammar (informal)
//!
//! ```text
//! report    := header access_line stack blank context alloc_stack? free_stack? summary?
//! header    := "==" PID "==" "ERROR: AddressSanitizer: " KIND rest_of_line
//! access    := ("READ" | "WRITE") " of size " N " at " ADDR " thread " TID
//! stack     := frame+
//! frame     := INDENT "#" IDX " 0x" IP " in " SYM (" " FILE ":" LINE (":" COL)?)?
//! context   := ADDR " is located " ("N bytes" | N " bytes") (" to the " SIDE " of"
//!              | " inside of") " N-byte region " "[" ADDR "," ADDR ")"
//! alloc_stack := "allocated by thread " TID " here:" frame+
//! free_stack  := "freed by thread " TID " here:" frame+
//! summary     := "SUMMARY: AddressSanitizer: " KIND ...
//! ```
//!
//! We parse conservatively: any line that doesn't match the expected grammar
//! at the current state is ignored, rather than erroring. Sanitizer output
//! formats drift across compiler-rt versions and platforms, and a lenient
//! parser catches more reports. Missing optional fields are set to `None`
//! rather than fabricated.

use crate::{Backtrace, CrashKind, CrashReport, Frame, Side};

/// Parse a complete ASan stderr blob into one or more [`CrashReport`]s.
///
/// ASan normally produces at most one report per crash (it `abort`s on
/// detection), but with `halt_on_error=0` a single log may contain several.
pub fn parse(text: &str) -> Vec<CrashReport> {
    let mut out = Vec::new();
    let mut cur = Parser::default();
    for line in text.lines() {
        cur.feed(line);
        if let Some(report) = cur.take_finished() {
            out.push(report);
        }
    }
    if let Some(report) = cur.finish() {
        out.push(report);
    }
    out
}

/// Parse a single ASan report blob, returning the first report if any.
/// Convenience wrapper for callers that execute the target once.
pub fn parse_one(text: &str) -> Option<CrashReport> {
    parse(text).into_iter().next()
}

#[derive(Default)]
struct Parser {
    state: State,
    kind: Option<CrashKind>,
    access: Vec<Frame>,
    alloc: Vec<Frame>,
    free: Vec<Frame>,
    finished: Option<CrashReport>,
}

#[derive(Default, PartialEq, Eq)]
enum State {
    #[default]
    Idle,
    AfterHeader,   // saw header; waiting for access stack frames
    InAccessStack, // collecting access frames
    InAllocStack,  // collecting alloc frames
    InFreeStack,   // collecting free frames
}

impl Parser {
    fn feed(&mut self, line: &str) {
        let trimmed = line.trim_start();

        if let Some(kind_str) = header_kind(trimmed) {
            self.flush();
            self.kind = map_kind(kind_str);
            self.state = State::AfterHeader;
            return;
        }

        // Transition markers
        if trimmed.starts_with("allocated by thread")
            || trimmed.starts_with("previously allocated by thread")
        {
            self.state = State::InAllocStack;
            return;
        }
        if trimmed.starts_with("freed by thread") {
            self.state = State::InFreeStack;
            return;
        }
        if trimmed.starts_with("SUMMARY:") {
            self.finalize();
            return;
        }

        // Side detection from the context line.
        if let Some(side) = detect_side(trimmed) {
            self.apply_side(side);
            return;
        }

        // Access direction lines ("READ of size ..." / "WRITE of size ...")
        // transition us into access-stack collection.
        if self.state == State::AfterHeader
            && (trimmed.starts_with("READ of size") || trimmed.starts_with("WRITE of size"))
        {
            self.state = State::InAccessStack;
            return;
        }

        // Frame lines.
        if let Some(frame) = parse_frame(trimmed) {
            match self.state {
                State::InAccessStack | State::AfterHeader => self.access.push(frame),
                State::InAllocStack => self.alloc.push(frame),
                State::InFreeStack => self.free.push(frame),
                State::Idle => {}
            }
        }
    }

    fn apply_side(&mut self, side: Side) {
        // Only relevant for heap-buffer-overflow.
        if let Some(CrashKind::HeapBufferOverflow { side: s }) = self.kind.as_mut() {
            *s = side;
        }
    }

    fn finalize(&mut self) {
        if self.kind.is_some() {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if let Some(kind) = self.kind.take() {
            let access_site = Backtrace {
                frames: std::mem::take(&mut self.access),
            };
            let alloc_site = if self.alloc.is_empty() {
                None
            } else {
                Some(Backtrace {
                    frames: std::mem::take(&mut self.alloc),
                })
            };
            let free_site = if self.free.is_empty() {
                None
            } else {
                Some(Backtrace {
                    frames: std::mem::take(&mut self.free),
                })
            };
            let report = CrashReport::new(kind, access_site, alloc_site, free_site, Vec::new());
            self.finished = Some(report);
        }
        self.state = State::Idle;
    }

    fn take_finished(&mut self) -> Option<CrashReport> {
        self.finished.take()
    }

    fn finish(mut self) -> Option<CrashReport> {
        self.finalize();
        self.finished
    }
}

fn header_kind(line: &str) -> Option<&str> {
    // Match "==PID==ERROR: AddressSanitizer: <rest-of-line>"
    let needle = "ERROR: AddressSanitizer: ";
    let idx = line.find(needle)?;
    Some(&line[idx + needle.len()..])
}

/// Identify the crash kind by searching the header tail for the first known
/// token. Compiler-rt mixes plain-kind headers (`heap-buffer-overflow on
/// address ...`) with prose-y ones (`attempting double-free on ...`, `bad
/// parameter ...`), so a token-contains match is more robust than splitting
/// on whitespace and matching the first word.
fn map_kind(tail: &str) -> Option<CrashKind> {
    // Order matters: check longer, more-specific tokens first so that
    // `heap-use-after-free` wins over `use-after-free`.
    const TABLE: &[(&str, CrashKindCtor)] = &[
        ("heap-buffer-overflow", CrashKindCtor::HeapBufferOverflow),
        ("stack-buffer-overflow", CrashKindCtor::StackBufferOverflow),
        (
            "global-buffer-overflow",
            CrashKindCtor::GlobalBufferOverflow,
        ),
        ("stack-use-after-return", CrashKindCtor::StackUseAfterReturn),
        ("stack-use-after-scope", CrashKindCtor::StackUseAfterScope),
        ("heap-use-after-free", CrashKindCtor::UseAfterFree),
        ("use-after-free", CrashKindCtor::UseAfterFree),
        ("double-free", CrashKindCtor::DoubleFree),
        // Compiler-rt says "attempting free on address which was not malloc()-ed".
        (
            "free on address which was not malloc",
            CrashKindCtor::InvalidFree,
        ),
        ("bad-free", CrashKindCtor::InvalidFree),
        ("invalid-free", CrashKindCtor::InvalidFree),
    ];
    for (token, ctor) in TABLE {
        if tail.contains(token) {
            return Some(ctor.build());
        }
    }
    None
}

enum CrashKindCtor {
    HeapBufferOverflow,
    StackBufferOverflow,
    GlobalBufferOverflow,
    StackUseAfterReturn,
    StackUseAfterScope,
    UseAfterFree,
    DoubleFree,
    InvalidFree,
}

impl CrashKindCtor {
    fn build(&self) -> CrashKind {
        match self {
            Self::HeapBufferOverflow => CrashKind::HeapBufferOverflow { side: Side::Right },
            Self::StackBufferOverflow => CrashKind::StackBufferOverflow,
            Self::GlobalBufferOverflow => CrashKind::GlobalBufferOverflow,
            Self::StackUseAfterReturn => CrashKind::StackUseAfterReturn,
            Self::StackUseAfterScope => CrashKind::StackUseAfterScope,
            Self::UseAfterFree => CrashKind::UseAfterFree {
                quarantine_residence_ms: 0,
            },
            Self::DoubleFree => CrashKind::DoubleFree,
            Self::InvalidFree => CrashKind::InvalidFree,
        }
    }
}

fn detect_side(line: &str) -> Option<Side> {
    // Compiler-rt has used two phrasings across versions:
    //   - older: "to the right of" / "to the left of"
    //   - newer: "after" / "before"        (observed in LLVM 20+)
    // Both coexist in the wild; both must parse.
    if line.contains("to the right of") || line.contains(" after ") {
        Some(Side::Right)
    } else if line.contains("to the left of") || line.contains(" before ") {
        Some(Side::Left)
    } else {
        None
    }
}

/// Parse a stack-frame line of the form:
///   "#3 0x7f8d4f023d8f in __libc_start_main /lib/x86_64-linux-gnu/libc.so.6+0x23d8f"
///   "#0 0x55cd8e2a8b31 in process_input /tmp/buggy.c:12:5"
fn parse_frame(line: &str) -> Option<Frame> {
    if !line.starts_with('#') {
        return None;
    }
    // Skip "#<idx> "
    let after_hash = line.trim_start_matches('#');
    let (_idx, rest) = split_once_ws(after_hash)?;
    let rest = rest.trim_start();
    if !rest.starts_with("0x") {
        return None;
    }
    let (ip_str, rest) = split_once_ws(rest)?;
    let ip = u64::from_str_radix(ip_str.trim_start_matches("0x"), 16).ok()?;

    // Expect "in <sym> [<file>:<line>[:<col>]]"
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("in ").unwrap_or(rest);

    let (symbol, file, line_no) = parse_symbol_and_location(rest);
    Some(Frame {
        ip,
        symbol,
        file,
        line: line_no,
    })
}

fn parse_symbol_and_location(s: &str) -> (Option<String>, Option<String>, Option<u32>) {
    // Symbol is everything up to the first whitespace that is followed by
    // something containing ':' (a file:line) or '(' (a module+offset form).
    // We handle the common case: `sym file:line[:col]` or `sym (module+0xoff)`
    // or just `sym` alone.
    let mut parts = s.splitn(2, ' ');
    let sym = parts.next().map(|s| s.trim_end_matches('(').to_string());
    let sym = sym.filter(|s| !s.is_empty());
    let tail = parts.next().unwrap_or("").trim();

    if tail.is_empty() {
        return (sym, None, None);
    }

    // `(module+0xoffset)` — location unknown.
    if tail.starts_with('(') {
        return (sym, None, None);
    }

    // file:line[:col]
    let tail = tail.trim_matches(|c: char| c == '(' || c == ')');
    let mut bits = tail.rsplitn(3, ':');
    // bits yields in reverse: possible col, line, file
    let first = bits.next();
    let second = bits.next();
    let third = bits.next();

    let (file, line_no) = match (third, second, first) {
        (Some(file), Some(line), Some(_col)) => (Some(file.to_string()), line.parse::<u32>().ok()),
        (None, Some(file), Some(line)) => (Some(file.to_string()), line.parse::<u32>().ok()),
        (None, None, Some(only)) => {
            // Single token with no colons: treat as a bare path.
            (Some(only.to_string()), None)
        }
        _ => (None, None),
    };

    (sym, file, line_no)
}

fn split_once_ws(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(|c: char| c.is_whitespace())?;
    Some((&s[..idx], &s[idx + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HBO_RIGHT: &str = "\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x55cd8e2a8b32 bp 0x7ffeabcd1230 sp 0x7ffeabcd1228
WRITE of size 1 at 0x602000000014 thread T0
    #0 0x55cd8e2a8b31 in process_input /tmp/buggy.c:12:5
    #1 0x55cd8e2a8a1f in main /tmp/buggy.c:23:9
    #2 0x7f8d4f023d8f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x23d8f)

0x602000000014 is located 4 bytes to the right of 16-byte region [0x602000000000,0x602000000010)
allocated by thread T0 here:
    #0 0x7f8d4f25ccd1 in __interceptor_malloc
    #1 0x55cd8e2a89d5 in main /tmp/buggy.c:21:23

SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/buggy.c:12:5 in process_input
";

    const UAF: &str = "\
==7777==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x400abc
READ of size 4 at 0x602000000010 thread T0
    #0 0x400abc in use_after_free /tmp/uaf.c:10:5
    #1 0x400def in main /tmp/uaf.c:20:5

0x602000000010 is located 0 bytes inside of 16-byte region [0x602000000010,0x602000000020)
freed by thread T0 here:
    #0 0x7f111111 in __interceptor_free
    #1 0x400444 in main /tmp/uaf.c:18:5
previously allocated by thread T0 here:
    #0 0x7f000000 in __interceptor_malloc
    #1 0x400333 in main /tmp/uaf.c:15:15
";

    #[test]
    fn parses_heap_buffer_overflow_right_side() {
        let r = parse_one(HBO_RIGHT).expect("parse");
        assert_eq!(r.kind, CrashKind::HeapBufferOverflow { side: Side::Right });
        assert_eq!(r.access_site.frames.len(), 3);
        assert_eq!(
            r.access_site.frames[0].symbol.as_deref(),
            Some("process_input")
        );
        assert_eq!(
            r.access_site.frames[0].file.as_deref(),
            Some("/tmp/buggy.c")
        );
        assert_eq!(r.access_site.frames[0].line, Some(12));
        assert!(r.alloc_site.is_some());
        assert_eq!(r.alloc_site.as_ref().unwrap().frames.len(), 2);
    }

    #[test]
    fn parses_use_after_free_with_alloc_and_free_stacks() {
        let r = parse_one(UAF).expect("parse");
        assert!(matches!(r.kind, CrashKind::UseAfterFree { .. }));
        assert_eq!(r.access_site.frames.len(), 2);
        assert!(r.free_site.is_some());
        assert!(r.alloc_site.is_some());
        assert_eq!(
            r.free_site.as_ref().unwrap().frames[1].symbol.as_deref(),
            Some("main")
        );
        assert_eq!(r.alloc_site.as_ref().unwrap().frames[1].line, Some(15));
    }

    #[test]
    fn unknown_kind_is_skipped_not_errored() {
        let txt = "==1==ERROR: AddressSanitizer: something-new-we-dont-know\n";
        assert!(parse(txt).is_empty());
    }

    #[test]
    fn empty_input_yields_no_reports() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn dedup_hash_is_stable_across_parses() {
        let a = parse_one(HBO_RIGHT).unwrap().dedup_hash;
        let b = parse_one(HBO_RIGHT).unwrap().dedup_hash;
        assert_eq!(a, b);
    }

    #[test]
    fn frame_without_location_parses() {
        let line = "    #0 0x7f25ccd1 in __interceptor_malloc";
        let f = parse_frame(line.trim_start()).unwrap();
        assert_eq!(f.symbol.as_deref(), Some("__interceptor_malloc"));
        assert_eq!(f.file, None);
        assert_eq!(f.line, None);
    }

    #[test]
    fn frame_with_module_offset_parses() {
        let line =
            "    #2 0x7f8d4f023d8f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x23d8f)";
        let f = parse_frame(line.trim_start()).unwrap();
        assert_eq!(f.symbol.as_deref(), Some("__libc_start_main"));
        assert_eq!(f.ip, 0x7f8d4f023d8f);
    }

    #[test]
    fn parses_double_free_prose_header() {
        let txt = "==9999==ERROR: AddressSanitizer: attempting double-free on 0x602000000020 in thread T0:\n\
                   #0 0x7f200000 in __interceptor_free\n\
                   #1 0x400777 in bad_cleanup /tmp/uaf.c:40:5\n\
                   SUMMARY: AddressSanitizer: double-free /tmp/uaf.c:40:5 in bad_cleanup\n";
        let r = parse_one(txt).expect("parse");
        assert_eq!(r.kind, CrashKind::DoubleFree);
    }

    #[test]
    fn parses_invalid_free_prose_header() {
        let txt = "==1==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed: 0x42 in thread T0\n\
                   SUMMARY: AddressSanitizer: bad-free in foo\n";
        let r = parse_one(txt).expect("parse");
        assert_eq!(r.kind, CrashKind::InvalidFree);
    }

    #[test]
    fn heap_use_after_free_matches_uaf_not_plain_use_after_free_prefix() {
        // Regression: the table ordering must not accidentally match the
        // shorter `use-after-free` token inside `heap-use-after-free`.
        let r = parse_one(UAF).expect("parse");
        assert!(matches!(r.kind, CrashKind::UseAfterFree { .. }));
    }

    #[test]
    fn left_side_is_detected() {
        let txt = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2\n\
                   WRITE of size 1 at 0x1 thread T0\n\
                   0x1 is located 8 bytes to the left of 16-byte region [0x10,0x20)\n\
                   SUMMARY: AddressSanitizer: heap-buffer-overflow\n";
        let r = parse_one(txt).unwrap();
        assert_eq!(r.kind, CrashKind::HeapBufferOverflow { side: Side::Left });
    }

    #[test]
    fn modern_after_before_phrasing_detected() {
        // LLVM 20+ uses "after"/"before" in context lines.
        let after = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2\n\
                     WRITE of size 1 at 0x1 thread T0\n\
                     0x1 is located 4 bytes after 16-byte region [0x10,0x20)\n\
                     SUMMARY: AddressSanitizer: heap-buffer-overflow\n";
        assert_eq!(
            parse_one(after).unwrap().kind,
            CrashKind::HeapBufferOverflow { side: Side::Right }
        );

        let before =
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2\n\
                      WRITE of size 1 at 0x1 thread T0\n\
                      0x1 is located 8 bytes before 16-byte region [0x10,0x20)\n\
                      SUMMARY: AddressSanitizer: heap-buffer-overflow\n";
        assert_eq!(
            parse_one(before).unwrap().kind,
            CrashKind::HeapBufferOverflow { side: Side::Left }
        );
    }
}
