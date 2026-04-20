//! Seed corpus with information-theoretic prioritization.
//!
//! SPEC §8.4. The energy of a seed is
//!
//! ```text
//! energy(s) = exp(−λ · hit_count(e_rarest(s)))
//! ```
//!
//! where `e_rarest(s)` is the globally-rarest edge that seed `s` covers.
//! Seeds that unlock rare edges get exponentially more selection probability
//! than seeds that only retrace common edges. This is a direct consequence
//! of maximising expected information gain: rarer events carry more
//! Shannon bits.
//!
//! We do not vendor `libafl_bolts` here; corpus selection is a local
//! computation and a thin Rust implementation keeps this crate usable from
//! small replayer tools. A LibAFL-backed corpus can be swapped in at the
//! driver layer by implementing the [`Corpus`] trait.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;

pub type EdgeId = u32;
pub type SeedId = u64;

/// Default lambda for the energy formula. Chosen so that a 10× gap in hit
/// count produces roughly a 22× energy gap — empirically a good balance
/// between exploration (try the rare thing) and exploitation (keep hitting
/// known-good seeds).
pub const DEFAULT_LAMBDA: f64 = 0.3;

#[derive(Debug, Clone)]
pub struct Seed {
    pub id: SeedId,
    pub bytes: Vec<u8>,
    /// The sorted, deduplicated edges this seed covers.
    pub edges: Vec<EdgeId>,
    pub times_selected: u32,
}

/// Global edge hit counts across the corpus.
#[derive(Debug, Default)]
pub struct EdgeTable {
    counts: HashMap<EdgeId, u64>,
}

impl EdgeTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, edges: &[EdgeId]) {
        for e in edges {
            *self.counts.entry(*e).or_insert(0) += 1;
        }
    }

    pub fn hit_count(&self, edge: EdgeId) -> u64 {
        self.counts.get(&edge).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Shannon entropy over the edge distribution, in nats.
    ///
    /// `H = −Σ p(e) ln p(e)`. Used as a corpus-health indicator: higher
    /// entropy = coverage is more uniform; lower entropy = one hot path
    /// dominates and the fuzzer is stuck.
    pub fn entropy_nats(&self) -> f64 {
        let total: f64 = self.counts.values().map(|&c| c as f64).sum();
        if total == 0.0 {
            return 0.0;
        }
        self.counts
            .values()
            .map(|&c| {
                let p = c as f64 / total;
                if p == 0.0 {
                    0.0
                } else {
                    -p * p.ln()
                }
            })
            .sum()
    }
}

pub trait Corpus {
    fn add(&mut self, seed: Seed);
    fn select(&mut self) -> Option<&Seed>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory corpus with Shannon-energy weighted selection.
///
/// Selection is deterministic given a seed to the internal PRNG, which is
/// set at construction. SPEC §11 determinism.
#[derive(Debug)]
pub struct EnergyCorpus {
    seeds: Vec<Seed>,
    edges: EdgeTable,
    lambda: f64,
    rng_state: u64,
}

impl EnergyCorpus {
    pub fn with_seed(rng_seed: u64) -> Self {
        Self {
            seeds: Vec::new(),
            edges: EdgeTable::new(),
            lambda: DEFAULT_LAMBDA,
            rng_state: rng_seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }

    pub fn with_lambda(mut self, lambda: f64) -> Self {
        self.lambda = lambda;
        self
    }

    pub fn edges(&self) -> &EdgeTable {
        &self.edges
    }

    /// Weight for a seed = exp(−λ · hit_count(rarest edge)).
    fn weight(&self, seed: &Seed) -> f64 {
        if seed.edges.is_empty() {
            return 1.0;
        }
        let rarest = seed
            .edges
            .iter()
            .map(|&e| self.edges.hit_count(e))
            .min()
            .unwrap_or(0);
        (-self.lambda * rarest as f64).exp()
    }

    /// splitmix64 — small, fast, deterministic, good enough for selection.
    fn next_rand(&mut self) -> u64 {
        self.rng_state = self.rng_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn rand_f64_01(&mut self) -> f64 {
        // 53-bit mantissa of an f64 in [0, 1).
        (self.next_rand() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }
}

impl Corpus for EnergyCorpus {
    fn add(&mut self, seed: Seed) {
        self.edges.observe(&seed.edges);
        self.seeds.push(seed);
    }

    /// Weighted random selection, O(n) per pick. For large corpora, swap
    /// for a Walker alias method — the contract is stable.
    fn select(&mut self) -> Option<&Seed> {
        if self.seeds.is_empty() {
            return None;
        }
        let weights: Vec<f64> = self.seeds.iter().map(|s| self.weight(s)).collect();
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            // Degenerate: uniform fallback. Modulo in u64 first so that on
            // 32-bit targets we don't silently truncate before the `%` and
            // bias selection toward the low-indexed half of the corpus.
            let n = self.seeds.len() as u64;
            let idx = (self.next_rand() % n) as usize;
            self.seeds[idx].times_selected += 1;
            return Some(&self.seeds[idx]);
        }
        let mut target = self.rand_f64_01() * total;
        for (idx, w) in weights.iter().enumerate() {
            target -= w;
            if target <= 0.0 {
                self.seeds[idx].times_selected += 1;
                return Some(&self.seeds[idx]);
            }
        }
        // Floating-point rounding may leak through; return the last seed.
        let last = self.seeds.len() - 1;
        self.seeds[last].times_selected += 1;
        self.seeds.last()
    }

    fn len(&self) -> usize {
        self.seeds.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(id: SeedId, edges: &[EdgeId]) -> Seed {
        Seed {
            id,
            bytes: vec![id as u8],
            edges: edges.to_vec(),
            times_selected: 0,
        }
    }

    #[test]
    fn entropy_is_zero_for_empty_table() {
        let t = EdgeTable::new();
        assert_eq!(t.entropy_nats(), 0.0);
    }

    #[test]
    fn entropy_is_positive_for_non_uniform_coverage() {
        let mut t = EdgeTable::new();
        t.observe(&[1, 2, 3]);
        t.observe(&[1, 1, 1]);
        assert!(t.entropy_nats() > 0.0);
    }

    #[test]
    fn rare_edge_seed_wins_most_of_the_time() {
        // Seed A covers a common edge (hit 1000 times).
        // Seed B covers a rare edge (hit once).
        // Under λ=0.3, B's weight ≈ exp(-0.3) ≈ 0.74;
        // A's weight ≈ exp(-300) ≈ 10^-131. B dominates.
        let mut corpus = EnergyCorpus::with_seed(42);
        corpus.add(seed(1, &[100]));
        corpus.add(seed(2, &[200]));
        // Pre-load common edge 100 with many hits by adding ghost observations.
        for _ in 0..1000 {
            corpus.edges.observe(&[100]);
        }

        let mut b_wins = 0;
        for _ in 0..1000 {
            if corpus.select().unwrap().id == 2 {
                b_wins += 1;
            }
        }
        assert!(
            b_wins > 950,
            "expected B to dominate selection, got {}/1000",
            b_wins
        );
    }

    #[test]
    fn selection_is_deterministic_for_same_rng_seed() {
        let run = |rng_seed: u64| {
            let mut c = EnergyCorpus::with_seed(rng_seed);
            c.add(seed(1, &[1]));
            c.add(seed(2, &[2]));
            c.add(seed(3, &[3]));
            (0..50).map(|_| c.select().unwrap().id).collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7));
        assert_ne!(run(7), run(8));
    }
}
