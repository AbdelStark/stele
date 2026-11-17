//! RFC-0008 A7 / RFC-0014 §5: stage genuine compact factors and check every final.
//! Host construction/expansion is explicit; observer values never enter a proof.
use crate::{round::Terms, FactorSpec, Shape, Source, K, M31};
use stele_reductions::zk::claims::bench::{GkrCase, Masked};

/// Convert an unfolded production reference without changing its domain or terms.
pub fn shape(reference: &Masked<K>) -> Result<Shape, &'static str> {
    let len = 1usize
        .checked_shl(reference.variables())
        .ok_or("factor domain")?;
    let degree = reference.degree();
    let nodes = degree.checked_add(1).ok_or("round degree")?;
    let terms: Vec<_> = reference
        .terms()
        .iter()
        .map(|t| (t.coefficient, t.factors.clone()))
        .collect();
    let count = reference.tables().count();
    if count == 0 {
        return Err("empty factors");
    }
    Terms::new(count, &terms, nodes)?;
    for ((x, r), v) in reference.tables().zip(reference.vanishing()) {
        if x.len() != len
            || match v {
                Some(v) => v >= reference.variables() as usize || r.len() != len,
                None => !r.is_empty(),
            }
        {
            return Err("factor dimensions");
        }
    }
    let factors = reference
        .tables()
        .zip(reference.vanishing())
        .map(|((x, r), v)| FactorSpec {
            x: source(x),
            mask: v.map(|v| (source(r), v)),
        })
        .collect();
    Ok(Shape {
        name: "production_gkr",
        n: reference.variables() as usize,
        factors,
        terms,
        degree,
    })
}

fn source(values: &[K]) -> Source {
    if values
        .iter()
        .all(|x| x.0 .1 == M31::ZERO && x.1 .0 == M31::ZERO && x.1 .1 == M31::ZERO)
    {
        Source::Column {
            values: values.iter().map(|x| x.0 .0).collect(),
        }
    } else {
        Source::Tile {
            period: values.to_vec(),
        }
    }
}

/// Compare all compact slots before applying production expansion and routing.
/// `expected` must contain every CPU-folded compact final, including unused slots.
pub fn check_finals(
    step: &GkrCase<'_, K>,
    expected: &[K],
    actual: &[K],
) -> Result<(), &'static str> {
    if expected != actual {
        return Err("compact finals");
    }
    let expanded = step
        .reference()
        .map_err(|_| "factor construction")?
        .expand_at(step.point, actual)
        .map_err(|_| "compact expansion")?;
    if expanded != step.finals {
        return Err("expanded finals");
    }
    if step.route(&expanded).map_err(|_| "claim routing")? != step.routed {
        return Err("routed claims");
    }
    Ok(())
}
