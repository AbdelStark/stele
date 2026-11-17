//! RFC-0014 §5: synthetic round/fold cases from public production geometry.
//! Reduced domains qualify code generation, not factor construction or proof finals.
use crate::{FactorSpec, Field, Rng, Shape, Source, K, M31};
use std::collections::HashSet;

struct Entry {
    kind: &'static str,
    variables: usize,
    degree: usize,
    masks: Vec<Option<usize>>,
    terms: Vec<Vec<u32>>,
    compact: bool,
    retained: Vec<usize>,
}

/// Complete, nonempty input to the bounded 1,000-case campaign.
pub struct Inventory(Vec<Entry>);

/// Synthetic values with the original term lists and ordered mask classes.
pub struct Case {
    /// Original table exponent; this is not the executed table size.
    pub original_variables: usize,
    /// The production shape needs compact-final expansion, which is not tested.
    pub compact: bool,
    /// Base, extension, or alternating factor storage.
    pub representation: &'static str,
    /// The reduced-domain summand passed to both existing implementations.
    pub shape: Shape,
}

fn number(s: &str) -> Result<usize, &'static str> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err("invalid unsigned number");
    }
    s.parse().map_err(|_| "number overflow")
}

impl Inventory {
    /// Parse exactly the declared shape count. Bounds limit this research harness,
    /// not the accepted production relation or future backend.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if text.len() > 8 * 1024 * 1024 {
            return Err("inventory exceeds harness limit");
        }
        let mut lines = text.lines();
        let count = number(
            lines
                .next()
                .and_then(|s| s.strip_prefix("masked-shapes-v1 "))
                .ok_or("missing inventory declaration")?,
        )?;
        if !(1..=256).contains(&count) {
            return Err("inventory count outside harness limit");
        }
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        for line in lines {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() != 8
                || f[0] != "shape"
                || !seen.insert(f.join(" "))
                || entries.len() == count
            {
                return Err("duplicate, extra or malformed shape");
            }
            let kind = match f[1] {
                "relation" => "relation",
                "gkr_first" => "gkr_first",
                "gkr_interior" => "gkr_interior",
                "gkr_leaf" => "gkr_leaf",
                _ => return Err("unknown shape kind"),
            };
            let value =
                |i: usize, prefix: &str| f[i].strip_prefix(prefix).ok_or("wrong field order");
            if value(2, "field=")? != "4" {
                return Err("only QM31 is implemented");
            }
            let variables = number(value(3, "vars=")?)?;
            let degree = number(value(4, "degree=")?)?;
            if !(1..=32).contains(&variables) || !(1..=31).contains(&degree) {
                return Err("variables or degree outside harness limit");
            }
            let masks = value(5, "masks=")?
                .split(',')
                .map(|s| {
                    if s == "-" {
                        Ok(None)
                    } else {
                        let v = number(s)?;
                        if v >= variables {
                            return Err("mask coordinate outside shape");
                        }
                        Ok(Some(v))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            if masks.len() > 4096 {
                return Err("too many factors");
            }
            let terms = value(6, "terms=")?
                .split(',')
                .map(|s| {
                    if s == "-" {
                        return Ok(Vec::new());
                    }
                    let term = s
                        .split('.')
                        .map(|s| {
                            let i = number(s)?;
                            if i >= masks.len() {
                                return Err("term factor outside shape");
                            }
                            Ok(i as u32)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if term.len() > 31 {
                        return Err("term exceeds harness limit");
                    }
                    Ok(term)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if terms.len() > 8192 {
                return Err("too many terms");
            }
            let compact = match value(7, "compact=")? {
                "0" => false,
                "1" => true,
                _ => return Err("invalid compact flag"),
            };
            // Preserve the first round, every mask event, an unmasked predecessor
            // when one exists, and the last round; equal mask coordinates stay equal.
            let mut retained = vec![0, variables - 1];
            for v in masks.iter().flatten() {
                retained.push(*v);
                if *v > 0 {
                    retained.push(v - 1);
                }
            }
            retained.sort_unstable();
            retained.dedup();
            if retained.len() > 8 {
                return Err("reduced domain exceeds harness limit");
            }
            entries.push(Entry {
                kind,
                variables,
                degree,
                masks,
                terms,
                compact,
                retained,
            });
        }
        if entries.len() != count {
            return Err("incomplete inventory");
        }
        Ok(Self(entries))
    }

    /// Number of recorded shapes (including distinct original table sizes).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Successful parsing always makes this false.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Cycle through all shapes, then base/extension/mixed storage. Each call owns
    /// fresh synthetic values; no witness, proof seed or challenge is imported.
    pub fn case(&self, index: usize, seed: u64) -> Case {
        let entry = &self.0[index % self.len()];
        let mode = (index / self.len()) % 3;
        let n = entry.retained.len();
        let mut rng = Rng::new(seed);
        let scalar = |rng: &mut Rng, i: usize| match i {
            0 => M31::from_u64(0),
            1 => M31::from_u64(1),
            2 => M31::from_u64(u64::from(M31::MODULUS) - 1),
            _ => rng.m31(),
        };
        let mut factors = Vec::new();
        for (i, mask) in entry.masks.iter().enumerate() {
            let x = if mode == 0 || (mode == 2 && i % 2 == 0) {
                Source::Column {
                    values: (0..1 << n).map(|j| scalar(&mut rng, j)).collect(),
                }
            } else {
                Source::Tile {
                    period: (0..1 << n)
                        .map(|j| {
                            if j < 3 {
                                K::from_i64(i64::from(scalar(&mut rng, j).as_u32()))
                            } else {
                                rng.qm31()
                            }
                        })
                        .collect(),
                }
            };
            let mask = mask.map(|original| {
                let v = entry
                    .retained
                    .binary_search(&original)
                    .expect("retained mask coordinate");
                let u: Vec<_> = (0..n).filter(|q| *q != v).collect();
                let block = (0..1 << u.len()).map(|j| scalar(&mut rng, j)).collect();
                (Source::Mask { block, u }, v)
            });
            factors.push(FactorSpec { x, mask });
        }
        let terms = entry
            .terms
            .iter()
            .enumerate()
            .map(|(i, factors)| {
                let coefficient = match i % 3 {
                    0 => K::from_i64(1),
                    1 => K::from_i64(-1),
                    _ => rng.qm31(),
                };
                (coefficient, factors.clone())
            })
            .collect();
        Case {
            original_variables: entry.variables,
            compact: entry.compact,
            representation: ["base", "extension", "mixed"][mode],
            shape: Shape {
                name: entry.kind,
                n,
                factors,
                terms,
                degree: entry.degree,
            },
        }
    }
}
