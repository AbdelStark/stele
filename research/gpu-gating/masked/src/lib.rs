//! E16-35 (ADR-123): dev-zk masked-sumcheck rounds on a CUDA device against the
//! production CPU summand (`stele_reductions::zk::claims::bench::Masked`, the
//! `Occurrences` rounds of RFC-0013 A5 item 2 and RFC-0008 A7 item 4).
//!
//! Two shapes, both one `Occurrences` summand:
//! - [`relation`]: an identity step `Σ_x eq(τ, x)·(V̇_a·V̇_b − V̇_c)` (A5, RFC-0026 A9)
//!   with M31 columns and M31 mask tables, a QM31 `eq`;
//! - [`gkr_layer`]: a ZK-GKR layer step (RFC-0008 A7 item 4, `zk_lookup::terms`) with the
//!   head, two selected incoming claims and their tiled blocks, and the four masked
//!   QM31 children `p0, p1, q0, q1` with M31 mask tables.
//!
//! Research code: nothing in `crates/` imports it. CPU only by default; the `cuda`
//! feature adds [`gpu`], with the CUDA driver and NVRTC loaded at run time.
use stele_reductions::parallel::eq_table;
pub use stele_reductions::stele_field::{Field, Serialize, CM31, M31, QM31};
use stele_reductions::zk::claims::bench::{mask_table, Masked, Table};

#[cfg(feature = "cuda")]
pub mod gpu;
#[cfg(feature = "cuda")]
pub mod gpu_source;
pub mod source;

/// The challenge field.
pub type K = QM31;

/// Deterministic xorshift64* stream for the random tables.
pub struct Rng(u64);

impl Rng {
    /// A stream from a nonzero seed.
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// A uniform-ish M31 element.
    pub fn m31(&mut self) -> M31 {
        M31::from_u64(self.next() >> 33)
    }
    /// A QM31 element with four random limbs.
    pub fn qm31(&mut self) -> K {
        QM31(CM31(self.m31(), self.m31()), CM31(self.m31(), self.m31()))
    }
}

/// The `i`-th sumcheck challenge (E16-21's formula; fixed so CPU and device agree).
pub fn challenge(i: usize) -> K {
    let m = |v: u64| M31::from_u64(v);
    let i = i as u64;
    QM31(
        CM31(m(1000003 * i + 17), m(7919 * i + 5)),
        CM31(m(104729 * i + 3), m(31337 * i + 11)),
    )
}

/// How a table is made: what the device builds from a small input, and what is uploaded.
pub enum Source {
    /// `scale·eq(point, ·)` at entries `offset..offset + 2^|point|`, zero elsewhere.
    Eq {
        point: Vec<K>,
        scale: Option<K>,
        offset: usize,
    },
    /// `period[i mod |period|]` (a block factor, `zk_lookup` `Gin::Block`).
    Tile { period: Vec<K> },
    /// A committed M31 column (uploaded).
    Column { values: Vec<M31> },
    /// QM31 layer values, repeated over both halves (`zk_lookup` `both`; uploaded).
    Layer { half: Vec<K> },
    /// The mask table `r̃(X_u)` of a `2^|u|`-entry M31 block.
    Mask { block: Vec<M31>, u: Vec<usize> },
}

impl Source {
    /// The table as the CPU producer builds it, over `2^n` entries.
    pub fn cpu(&self, n: usize) -> Vec<K> {
        let len = 1usize << n;
        let embed = |x: &M31| K::from_i64(i64::from(x.as_u32()));
        match self {
            Source::Eq {
                point,
                scale,
                offset,
            } => {
                let eq = eq_table(point).unwrap_or_default();
                let mut out = vec![K::from_i64(0); len];
                for (o, w) in out[*offset..].iter_mut().zip(eq) {
                    *o = scale.map_or(w, |k| k * w);
                }
                out
            }
            Source::Tile { period } => (0..len).map(|i| period[i % period.len()]).collect(),
            Source::Column { values } => values.iter().map(embed).collect(),
            Source::Layer { half } => half.iter().chain(half).copied().collect(),
            Source::Mask { block, u } => mask_table(block, u, n),
        }
    }
    /// Whether the table's entries are M31 (stored as `u32` on the device).
    pub fn is_base(&self) -> bool {
        matches!(self, Source::Column { .. } | Source::Mask { .. })
    }
}

/// One factor: its table and, for a masked factor, the mask table and vanishing variable.
pub struct FactorSpec {
    pub x: Source,
    pub mask: Option<(Source, usize)>,
}

/// One masked summand over `2^n`-entry tables.
pub struct Shape {
    pub name: &'static str,
    pub n: usize,
    pub factors: Vec<FactorSpec>,
    pub terms: Vec<(K, Vec<u32>)>,
    pub degree: usize,
}

/// `c_D` for QM31 (`D = 4`).
const C_D: usize = 2;

fn masked(x: Source, block: Vec<M31>, u: Vec<usize>, v: usize) -> FactorSpec {
    FactorSpec {
        x,
        mask: Some((Source::Mask { block, u }, v)),
    }
}

/// An identity step `Σ_x eq(τ, x)·(V̇_a·V̇_b − V̇_c)`: `a` and `c` vanish on variable 0,
/// `b` on variable 1 (A5 item 2's default), each with `u` the `c_D` lowest others.
/// Degree 4 (`eq`, `a` with `κ`, `b`).
pub fn relation(n: usize, seed: u64) -> Shape {
    assert!(n >= 3);
    let mut rng = Rng::new(seed);
    let len = 1usize << n;
    let tau = (0..n).map(|_| rng.qm31()).collect();
    let column = |rng: &mut Rng| Source::Column {
        values: (0..len).map(|_| rng.m31()).collect(),
    };
    let block = |rng: &mut Rng| (0..1usize << C_D).map(|_| rng.m31()).collect::<Vec<_>>();
    let a = masked(column(&mut rng), block(&mut rng), vec![1, 2], 0);
    let b = masked(column(&mut rng), block(&mut rng), vec![0, 2], 1);
    let c = masked(column(&mut rng), block(&mut rng), vec![1, 2], 0);
    let eq = FactorSpec {
        x: Source::Eq {
            point: tau,
            scale: None,
            offset: 0,
        },
        mask: None,
    };
    Shape {
        name: "relation",
        n,
        factors: vec![eq, a, b, c],
        terms: vec![
            (K::from_i64(1), vec![0, 1, 2]),
            (K::from_i64(-1), vec![0, 3]),
        ],
        degree: 4,
    }
}

/// A ZK-GKR layer step over `n = k + 1` variables `(s, x)` (`zk_lookup` `factors` and
/// `terms`, not first, not a leaf): inputs head, select₀, block₀, select₁, block₁,
/// `p0, p1, q0, q1`; terms `sel₀·blk₀ + λ·sel₁·blk₁ + eq·p0·q1 + eq·p1·q0 + λ·eq·q0·q1`.
/// `p` vanishes on `x`'s first variable, `q` on its second; `u` is `y`, the last
/// `c_D + 1` variables. Degree 5 (`eq·q0·q1` in `q`'s variable).
pub fn gkr_layer(n: usize, seed: u64) -> Shape {
    assert!(n >= 4);
    let mut rng = Rng::new(seed);
    let k = n - 1;
    let half = 1usize << k;
    let y: Vec<usize> = (n - C_D - 1..n).collect();
    let point = |rng: &mut Rng| (0..k).map(|_| rng.qm31()).collect::<Vec<_>>();
    let head = FactorSpec {
        x: Source::Eq {
            point: point(&mut rng),
            scale: None,
            offset: 0,
        },
        mask: None,
    };
    let mut factors = vec![head];
    for _ in 0..2 {
        let u = point(&mut rng);
        let scale = Some(rng.qm31());
        factors.push(FactorSpec {
            x: Source::Eq {
                point: u,
                scale,
                offset: half,
            },
            mask: None,
        });
        // `(1 − t*)·a + t*·b` over the block's two halves: `2^(c_D + 1)` values.
        factors.push(FactorSpec {
            x: Source::Tile {
                period: (0..1usize << (C_D + 1)).map(|_| rng.qm31()).collect(),
            },
            mask: None,
        });
    }
    for v in [1, 1, 2, 2] {
        let layer = Source::Layer {
            half: (0..half).map(|_| rng.qm31()).collect(),
        };
        let block = (0..1usize << (C_D + 1)).map(|_| rng.m31()).collect();
        factors.push(masked(layer, block, y.clone(), v));
    }
    let lambda = rng.qm31();
    let one = K::from_i64(1);
    Shape {
        name: "gkr",
        n,
        factors,
        terms: vec![
            (one, vec![1, 2]),
            (lambda, vec![3, 4]),
            (one, vec![0, 5, 8]),
            (one, vec![0, 6, 7]),
            (lambda, vec![0, 7, 8]),
        ],
        degree: 5,
    }
}

/// A shape by name.
pub fn shape(name: &str, n: usize, seed: u64) -> Option<Shape> {
    match name {
        "relation" => Some(relation(n, seed)),
        "gkr" => Some(gkr_layer(n, seed)),
        _ => None,
    }
}

/// The production CPU summand over the shape's tables.
pub fn cpu(shape: &Shape) -> Masked<K> {
    let tables = shape
        .factors
        .iter()
        .map(|f| Table {
            x: f.x.cpu(shape.n),
            r: f.mask.as_ref().map_or(Vec::new(), |(m, _)| m.cpu(shape.n)),
            v: f.mask.as_ref().map(|(_, v)| *v),
        })
        .collect();
    Masked::new(tables, shape.terms.clone(), shape.degree)
}

/// FNV-1a 64 over the canonical bytes of `values`, chained from `state`.
pub fn fnv(mut state: u64, values: &[K]) -> u64 {
    for v in values {
        for b in v.to_le_bytes() {
            state ^= u64::from(b);
            state = state.wrapping_mul(0x100_0000_01b3);
        }
    }
    state
}

/// FNV-1a 64 offset basis.
pub const FNV_START: u64 = 0xcbf2_9ce4_8422_2325;

#[cfg(test)]
mod tests {
    use super::*;

    /// The CPU's first round polynomial of each shape has `s(0) + s(1)` equal to the
    /// summand's sum over the cube, where the mask terms vanish.
    #[test]
    fn matches_reference_round_sum_over_the_cube() {
        for shape in [relation(6, 7), gkr_layer(6, 9)] {
            let summand = cpu(&shape);
            let round = summand.round().unwrap_or_default();
            assert_eq!(round.len(), shape.degree + 1);
            // Σ over the cube of the summand: mask terms vanish there (κ(0) = κ(1) = 0).
            let tables: Vec<Vec<K>> = summand.tables().map(|(x, _)| x.to_vec()).collect();
            let mut total = K::from_i64(0);
            for i in 0..1usize << shape.n {
                for (c, f) in &shape.terms {
                    total = total + f.iter().fold(*c, |p, k| p * tables[*k as usize][i]);
                }
            }
            assert_eq!(round[0] + round[1], total, "{}", shape.name);
        }
    }
}
