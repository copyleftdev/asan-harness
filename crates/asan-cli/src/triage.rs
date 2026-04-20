//! Triage: cluster crash JSON files by dedup hash.
//!
//! SPEC §12.1. Each file in the input directory is parsed as a CrashReport;
//! the resulting map `dedup_hash → [paths]` tells the user how many
//! *distinct* bugs they actually have.

use anyhow::{Context, Result};
use asan_oracle::CrashReport;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

pub fn cluster_dir(dir: &Path) -> Result<BTreeMap<u64, Vec<String>>> {
    let mut clusters: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let txt = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                log::warn!("skipping {}: {}", path.display(), e);
                continue;
            }
        };
        let report: CrashReport = match CrashReport::from_json(&txt) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("skipping {}: not a CrashReport ({})", path.display(), e);
                continue;
            }
        };
        clusters
            .entry(report.dedup_hash)
            .or_default()
            .push(path.display().to_string());
    }
    Ok(clusters)
}

#[derive(Serialize)]
pub struct ClusterView<'a> {
    pub clusters: Vec<ClusterEntry<'a>>,
    pub total_crashes: usize,
}

#[derive(Serialize)]
pub struct ClusterEntry<'a> {
    pub dedup_hash: String,
    pub count: usize,
    pub files: &'a [String],
}

pub fn json_view(clusters: &BTreeMap<u64, Vec<String>>) -> ClusterView<'_> {
    let total = clusters.values().map(|v| v.len()).sum();
    ClusterView {
        clusters: clusters
            .iter()
            .map(|(hash, files)| ClusterEntry {
                dedup_hash: format!("{:016x}", hash),
                count: files.len(),
                files,
            })
            .collect(),
        total_crashes: total,
    }
}
