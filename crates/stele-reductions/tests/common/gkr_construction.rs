//! RFC-0008 A7: independent scalar interpretation of borrowed factor inputs.
use stele_field::{Field, QM31};
use stele_reductions::zk::claims::bench::{GkrConstruction, GkrFactor, Masked, Table};

fn gather(coords: &[usize], x: usize, n: usize) -> usize {
    coords
        .iter()
        .fold(0, |at, q| (at << 1) | ((x >> (n - 1 - q)) & 1))
}

pub fn materialize(input: &GkrConstruction<'_, QM31>, seen: &mut [bool; 8]) -> Masked<QM31> {
    let n = input.num_vars as usize;
    let half = 1usize << input.layer_variables;
    let tables = input
        .factors
        .iter()
        .map(|factor| {
            let kind = match factor {
                GkrFactor::RetainedLayer { .. } => {
                    unreachable!("CPU observer requires original layers")
                }
                GkrFactor::Equality { .. } => 0,
                GkrFactor::Block { .. } => 1,
                GkrFactor::Column { .. } => 2,
                GkrFactor::Layer { .. } => 3,
                GkrFactor::Pad { .. } => 4,
                GkrFactor::Selector { .. } => 5,
                GkrFactor::Table { .. } => 6,
                GkrFactor::Combined { .. } => 7,
            };
            seen[kind] = true;
            let v = match factor {
                GkrFactor::Column { mask, .. } | GkrFactor::Layer { mask, .. } => {
                    Some(mask.vanishing)
                }
                GkrFactor::Combined { vanishing, .. } => Some(*vanishing),
                _ => None,
            };
            let mut x = Vec::new();
            let mut r = Vec::new();
            for index in 0..1usize << n {
                let pos = index % half;
                let value = match factor {
                    GkrFactor::RetainedLayer { .. } => unreachable!(),
                    GkrFactor::Equality {
                        point,
                        scale,
                        offset,
                    } => {
                        if index < *offset || index - offset >= 1usize << point.len() {
                            QM31::ZERO
                        } else {
                            point.iter().enumerate().fold(*scale, |a, (q, z)| {
                                a * if ((index - offset) >> (point.len() - 1 - q)) & 1 == 1 {
                                    *z
                                } else {
                                    QM31::ONE - *z
                                }
                            })
                        }
                    }
                    GkrFactor::Block { values, point } => {
                        let half = values.len() / 2;
                        let at = index % half;
                        QM31::from_i64(i64::from(values[at].as_u32())) * (QM31::ONE - *point)
                            + QM31::from_i64(i64::from(values[half + at].as_u32())) * *point
                    }
                    GkrFactor::Column {
                        values,
                        coordinates,
                        ..
                    } => values[gather(coordinates, index, n)],
                    GkrFactor::Layer {
                        values,
                        component,
                        side,
                        ..
                    } => values[2 * pos + side][*component],
                    GkrFactor::Pad { variables } => {
                        QM31::from_i64(i64::from(pos < 1usize << variables))
                    }
                    GkrFactor::Selector { members } => members
                        .iter()
                        .find(|m| m.range.contains(&pos))
                        .map_or(QM31::ZERO, |m| {
                            QM31::from_i64(m.values.map_or(1, |(values, coords)| {
                                values[gather(coords, pos, input.layer_variables)]
                            }))
                        }),
                    GkrFactor::Table {
                        rows,
                        valid,
                        alpha,
                        beta,
                    } => {
                        if pos >= *valid {
                            QM31::ONE
                        } else {
                            let mut power = QM31::ONE;
                            let mut result = *alpha;
                            for value in &rows[pos] {
                                result = result - power * QM31::from_i64(*value);
                                power = power * *beta;
                            }
                            result
                        }
                    }
                    GkrFactor::Combined { members, .. } => members
                        .iter()
                        .rev()
                        .find(|m| m.range.contains(&pos))
                        .map_or(QM31::ZERO, |m| {
                            m.values[gather(m.coordinates, pos, input.layer_variables)]
                                + QM31::from_i64(m.shift)
                        }),
                };
                x.push(value);
                match factor {
                    GkrFactor::Column { mask, .. } | GkrFactor::Layer { mask, .. } => {
                        r.push(QM31::from_i64(i64::from(
                            mask.values[gather(mask.coordinates, index, n)].as_u32(),
                        )));
                    }
                    GkrFactor::Combined { members, .. } => {
                        r.push(
                            members
                                .iter()
                                .find(|m| m.range.contains(&pos))
                                .map_or(QM31::ZERO, |m| {
                                    QM31::from_i64(i64::from(m.mask[pos % m.mask.len()].as_u32()))
                                }),
                        );
                    }
                    _ => {}
                }
            }
            Table { x, r, v }
        })
        .collect();
    Masked::new(
        tables,
        input
            .terms
            .iter()
            .map(|t| (t.coefficient, t.factors.clone()))
            .collect(),
        input.degree,
    )
}
