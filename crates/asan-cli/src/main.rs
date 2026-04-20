//! `asan-harness` — the command-line driver.
//!
//! SPEC §10.4. Progressive disclosure: each subcommand does one thing;
//! advanced flags hide behind `--advanced`-gated sections (not yet
//! implemented). Output format is selectable between human and JSON.

use anyhow::{Context, Result};
use asan_oracle::{CrashReport, Verdict};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

mod triage;

#[derive(Parser, Debug)]
#[command(name = "asan-harness", version, about = "ASan harness for reverse engineering.", long_about = None)]
struct Cli {
    /// Output format.
    #[arg(long, value_enum, global = true, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SanitizerMode {
    /// SPEC §7.1 — in-process with `-fsanitize=address`.
    Asan,
    /// SPEC §7.2 — Frida for closed-source shared libs.
    Frida,
    /// SPEC §7.3 — QEMU user-mode with QASan for stripped binaries.
    Qasan,
    /// SPEC §7.4 — Unicorn/QEMU system-mode for firmware.
    Unicorn,
    /// No sanitizer; used for baseline perf measurements.
    Off,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Drive a target with a corpus and record crashes.
    Run {
        target: PathBuf,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long, value_enum, default_value_t = SanitizerMode::Asan)]
        sanitizer: SanitizerMode,
    },
    /// Replay a stored crash and verify determinism (SPEC §11.4).
    Replay { crash: PathBuf },
    /// Shrink a crashing input while preserving the dedup hash.
    ///
    /// Real minimisation requires a live target; this command demonstrates
    /// the shrinker against a synthetic predicate (see `--keep-byte`) so
    /// the ddmin algorithm can be observed and smoke-tested standalone.
    Minify {
        crash: PathBuf,
        /// Synthetic predicate: require the shrunk input to still contain
        /// this byte (hex, e.g. `0x41`). Useful for observing the algorithm
        /// without wiring up a sanitizer-instrumented target.
        #[arg(long, value_parser = parse_hex_byte)]
        keep_byte: Option<u8>,
        /// Where to write the shrunk crash report.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Cluster a directory of crash reports by dedup hash (SPEC §12.1).
    Triage {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Measure coverage of a single input.
    Cov { target: PathBuf, input: PathBuf },
    /// Verify sanitizer runtime is live and shadow-offset is consistent.
    Doctor,

    /// Parse an AddressSanitizer stderr log and emit CrashReport JSON.
    ///
    /// Reads from stdin or a file; writes one JSON line per detected event
    /// to stdout (when `--format json`) or a human summary otherwise.
    Ingest {
        /// Path to an ASan log file. If omitted, reads from stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Directory to write one `<dedup>.json` CrashReport per event.
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let format = cli.format;
    match cli.command {
        Command::Run { target, corpus, sanitizer } => cmd_run(format, target, corpus, sanitizer),
        Command::Replay { crash } => cmd_replay(format, crash),
        Command::Minify { crash, keep_byte, out } => cmd_minify(format, crash, keep_byte, out),
        Command::Triage { dir } => cmd_triage(format, dir),
        Command::Cov { target, input } => cmd_cov(format, target, input),
        Command::Doctor => cmd_doctor(format),
        Command::Ingest { file, out_dir } => cmd_ingest(format, file, out_dir),
    }
}

fn cmd_ingest(fmt: OutputFormat, file: Option<PathBuf>, out_dir: Option<PathBuf>) -> Result<()> {
    use std::io::Read;
    let text = match file {
        Some(path) => fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?,
        None => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).context("reading stdin")?;
            buf
        }
    };
    let reports = asan_oracle::parse_asan_log(&text);
    if reports.is_empty() {
        anyhow::bail!("no AddressSanitizer events detected in input");
    }
    if let Some(dir) = &out_dir {
        fs::create_dir_all(dir)?;
    }
    for (i, report) in reports.iter().enumerate() {
        if let Some(dir) = &out_dir {
            let fname = format!("{:016x}-{i}.json", report.dedup_hash);
            let path = dir.join(&fname);
            fs::write(&path, report.to_json()?)?;
        }
        match fmt {
            OutputFormat::Human => {
                println!(
                    "event {:<2}  {:<22}  severity={}  dedup={:016x}  frames={}",
                    i,
                    report.kind.short_name(),
                    report.severity,
                    report.dedup_hash,
                    report.access_site.frames.len(),
                );
            }
            OutputFormat::Json => println!("{}", report.to_json()?),
        }
    }
    Ok(())
}

fn cmd_run(_fmt: OutputFormat, target: PathBuf, corpus: PathBuf, sanitizer: SanitizerMode) -> Result<()> {
    println!(
        "run: target={} corpus={} sanitizer={:?}",
        target.display(),
        corpus.display(),
        sanitizer
    );
    println!("note: `run` is the driver loop; wire it to libafl_libfuzzer to execute.");
    println!("      see SPEC §8.1 and crates/asan-driver/src/fuzz_target.rs");
    Ok(())
}

fn cmd_replay(fmt: OutputFormat, crash: PathBuf) -> Result<()> {
    let bytes = fs::read_to_string(&crash)
        .with_context(|| format!("reading {}", crash.display()))?;
    let report = CrashReport::from_json(&bytes).context("parsing crash report")?;
    match fmt {
        OutputFormat::Human => {
            println!("kind        : {}", report.kind.short_name());
            println!("severity    : {}", report.severity);
            println!("dedup_hash  : {:016x}", report.dedup_hash);
            println!("input_bytes : {}", report.raw_input.len());
            println!("schema      : v{}", report.schema_version);
            println!();
            println!("(replay loop requires a live target; this command currently");
            println!(" only validates the report can be round-tripped.)");
        }
        OutputFormat::Json => {
            let verdict = Verdict::Crash(report);
            println!("{}", serde_json::to_string(&verdict)?);
        }
    }
    Ok(())
}

fn cmd_minify(
    _fmt: OutputFormat,
    crash: PathBuf,
    keep_byte: Option<u8>,
    out: Option<PathBuf>,
) -> Result<()> {
    let txt = fs::read_to_string(&crash)
        .with_context(|| format!("reading {}", crash.display()))?;
    let mut report = CrashReport::from_json(&txt)?;
    let original_len = report.raw_input.len();

    let Some(byte) = keep_byte else {
        println!("minify: no --keep-byte supplied.");
        println!();
        println!("  raw_input length : {} bytes", original_len);
        println!("  dedup_hash       : {:016x}", report.dedup_hash);
        println!();
        println!("Real delta-debugging requires a live sanitizer-instrumented target");
        println!("to answer 'does this shrunk input still produce the same crash?'");
        println!("Pass --keep-byte 0x.. to demonstrate the ddmin algorithm against a");
        println!("synthetic predicate.");
        return Ok(());
    };

    let shrunk = asan_driver::ddmin(&report.raw_input, |c| c.contains(&byte));
    let shrunk_len = shrunk.len();
    report.raw_input = shrunk;

    let out_path = out.unwrap_or_else(|| {
        let mut p = crash.clone();
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("crash");
        p.set_file_name(format!("{stem}.min.json"));
        p
    });
    fs::write(&out_path, report.to_json()?)?;

    println!("minify: shrunk {} → {} bytes (predicate: contains 0x{:02x})",
        original_len, shrunk_len, byte);
    println!("wrote  : {}", out_path.display());
    Ok(())
}

fn parse_hex_byte(s: &str) -> std::result::Result<u8, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex byte '{s}': {e}"))
}

fn cmd_triage(fmt: OutputFormat, dir: PathBuf) -> Result<()> {
    let clusters = triage::cluster_dir(&dir)?;
    match fmt {
        OutputFormat::Human => print_clusters_human(&clusters),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(&triage::json_view(&clusters))?);
        }
    }
    Ok(())
}

fn cmd_cov(_fmt: OutputFormat, _target: PathBuf, _input: PathBuf) -> Result<()> {
    println!("cov: not yet implemented — requires SanitizerCoverage linkage.");
    println!("     see libafl_targets + SPEC §8.3.");
    Ok(())
}

fn cmd_doctor(_fmt: OutputFormat) -> Result<()> {
    use asan_core::{SHADOW_GRANULARITY, SHADOW_OFFSET_DEFAULT, SHADOW_SCALE};
    println!("asan-harness doctor");
    println!("  SHADOW_SCALE          = {}", SHADOW_SCALE);
    println!("  SHADOW_GRANULARITY    = {}", SHADOW_GRANULARITY);
    println!("  SHADOW_OFFSET_DEFAULT = 0x{:016x}", SHADOW_OFFSET_DEFAULT);
    println!();
    println!("  Spec version          : SPEC.md v0.0 (2026-04-19)");
    println!("  Schema version        : crash-report v{}", CrashReport::SCHEMA_VERSION);
    println!();
    println!("note: runtime ASan-liveness probe (dlsym __asan_report_error) pending.");
    Ok(())
}

fn print_clusters_human(clusters: &BTreeMap<u64, Vec<String>>) {
    if clusters.is_empty() {
        println!("(no crashes found)");
        return;
    }
    println!("clusters  : {}", clusters.len());
    let total: usize = clusters.values().map(|v| v.len()).sum();
    println!("crashes   : {}", total);
    println!();
    for (hash, files) in clusters {
        println!("  {:016x}  ({} crash{})", hash, files.len(), if files.len() == 1 { "" } else { "es" });
        for f in files.iter().take(3) {
            println!("    {}", f);
        }
        if files.len() > 3 {
            println!("    ... and {} more", files.len() - 3);
        }
    }
}
