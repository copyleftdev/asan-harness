//! End-to-end demo of the harness pipeline.
//!
//! Reads canned AddressSanitizer stderr blobs from `fixtures/`, parses each
//! into a [`CrashReport`], writes the reports to `findings/`, and prints a
//! cluster view by dedup hash.
//!
//! This proves the pipeline:
//!
//! ```text
//! ASan stderr  →  parse_asan_log  →  CrashReport  →  JSON on disk  →  triage clusters
//! ```
//!
//! works without any nightly toolchain, without Frida, without QEMU — the
//! ingredients needed to integrate with a real fuzzer.

use anyhow::{Context, Result};
use asan_oracle::{parse_asan_log, CrashReport};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("fixtures");
    let findings = root.join("findings");
    fs::create_dir_all(&findings).context("creating findings/")?;

    println!("asan-harness demo");
    println!("=================");
    println!();
    println!("fixtures:  {}", fixtures.display());
    println!("findings:  {}", findings.display());
    println!();

    let mut reports: Vec<(String, CrashReport)> = Vec::new();

    for entry in fs::read_dir(&fixtures)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let parsed = parse_asan_log(&text);
        if parsed.is_empty() {
            println!(
                "  [skip] {}: no reports parsed",
                path.file_name().unwrap().to_string_lossy()
            );
            continue;
        }
        for (i, report) in parsed.into_iter().enumerate() {
            let name = format!("{}-{i}.json", path.file_stem().unwrap().to_string_lossy());
            let out_path = findings.join(&name);
            fs::write(&out_path, report.to_json()?)?;
            println!(
                "  [ok]   {:<20} → {}  ({:016x})",
                path.file_name().unwrap().to_string_lossy(),
                out_path.file_name().unwrap().to_string_lossy(),
                report.dedup_hash
            );
            reports.push((name, report));
        }
    }

    println!();
    println!("triage:");
    let clusters = cluster(&findings)?;
    for (hash, files) in &clusters {
        println!(
            "  {:016x}  ({} crash{})",
            hash,
            files.len(),
            if files.len() == 1 { "" } else { "es" }
        );
        for f in files {
            println!("    {}", f);
        }
    }

    println!();
    println!("replay check:");
    for (name, stored) in &reports {
        let round = CrashReport::from_json(&fs::read_to_string(findings.join(name))?)?;
        let ok = round.dedup_hash == stored.dedup_hash && round.kind == stored.kind;
        println!("  {:<32} {}", name, if ok { "match" } else { "DIVERGED" });
    }

    Ok(())
}

fn cluster(dir: &Path) -> Result<BTreeMap<u64, Vec<String>>> {
    let mut map: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let txt = fs::read_to_string(&path)?;
        let r = CrashReport::from_json(&txt)?;
        map.entry(r.dedup_hash)
            .or_default()
            .push(path.file_name().unwrap().to_string_lossy().into_owned());
    }
    Ok(map)
}
