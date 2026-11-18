//! RFC-0008 A7: production fixtures and exact tree/top controls for E16-40i.
use crate::{Field, Rng, K, M31};
use stele_reductions::zk::claims::{
    bench::LookupCase, Column, Lookup, Member, Public, Read, Statement,
};

pub(crate) const CASES: usize = 1000;
pub(crate) const SEED: u64 = 0x40_1000_0001;

pub(crate) fn fixture(seed: u64) -> (Statement<K>, Vec<Vec<M31>>, K, K) {
    let mut rng = Rng::new(seed);
    let width = 1 + (seed / 2 % 3) as usize;
    let table: Vec<Vec<i64>> = (-1..=1)
        .map(|x| (0..width).map(|c| x + c as i64).collect())
        .chain([vec![0; width]])
        .collect();
    let (mut columns, mut data, mut members) = (Vec::new(), Vec::new(), Vec::new());
    let mut mult = vec![M31::ZERO; 4];
    for member in 0..1 + seed / 6 % 3 {
        let vars = 1 + (seed / 18 + member) as u32 % 5;
        let selected: Vec<i64> = (0..1usize << vars)
            .map(|x| i64::from(!(x as u64 + member + seed).is_multiple_of(3)))
            .collect();
        let rows: Vec<usize> = (0..selected.len())
            .map(|_| (rng.next() % 3) as usize)
            .collect();
        let shifts: Vec<i64> = (0..width)
            .map(|c| (seed as i64 + c as i64) % 5 - 2)
            .collect();
        let mut tuple = Vec::new();
        for (c, shift) in shifts.iter().enumerate() {
            tuple.push(Read {
                column: columns.len(),
                vars: (0..vars).collect(),
            });
            columns.push(Column {
                source: 0,
                log_len: vars,
            });
            data.push(
                rows.iter()
                    .map(|r| M31::from_i64(table[*r][c] - shift))
                    .collect(),
            );
        }
        for (row, s) in rows.iter().zip(&selected) {
            mult[*row] = mult[*row] + M31::from_i64(s * (1 << 3u32.saturating_sub(vars)));
        }
        members.push(Member {
            vars,
            tuple,
            shifts,
            selector: Some(Public {
                vars: (0..vars).collect(),
                values: selected,
            }),
        });
    }
    let multiplicity = columns.len();
    columns.push(Column {
        source: 0,
        log_len: 2,
    });
    data.push(mult);
    let s = Statement {
        sources: 1,
        columns,
        relations: vec![],
        lookups: vec![Lookup {
            members,
            multiplicity,
            table,
            valid: 3,
        }],
    };
    (s, data, rng.qm31(), rng.qm31())
}

#[test]
fn matches_reference_lookup_fixture_and_near_miss() {
    for case in 0..CASES {
        let (s, mut data, beta, alpha) = fixture(SEED + 2 * case as u64);
        let c = LookupCase::new(&s, &data, 0).expect("production plan");
        let t = c
            .reference(beta, alpha)
            .expect("nonzero seeded denominators");
        assert_eq!(t.layers[0][0][0], K::ZERO, "honest case {case}");
        let prepared = crate::lookup::Prepared::new(&c.inputs(beta, alpha)).expect("geometry");
        assert_eq!(prepared.leaves, t.layers.last().unwrap().len());
        assert_eq!(prepared.top, t.top[0].len());
        data[s.lookups[0].multiplicity][0] = data[s.lookups[0].multiplicity][0] + M31::ONE;
        let near = LookupCase::new(&s, &data, 0)
            .unwrap()
            .reference(beta, alpha)
            .unwrap();
        assert_ne!(near.layers[0][0][0], K::ZERO, "one count changed {case}");
    }
}

#[test]
fn rejects_lookup_shape_and_zero_denominator() {
    let (s, data, _, _) = fixture(SEED);
    let c = LookupCase::new(&s, &data, 0).unwrap();
    assert!(matches!(
        c.reference(K::ZERO, K::ZERO),
        Err(stele_reductions::zk::Error::DenominatorZero)
    ));
    let good = || c.inputs(K::ONE, K::from_i64(13));
    for change in 0..7 {
        let mut input = good();
        match change {
            0 => {
                input.table.pop();
            }
            1 => {
                input.selector.pop();
            }
            2 => {
                input.tuples[0].pop();
            }
            3 => {
                input.powers.pop();
            }
            4 => {
                input.selector[0] = 2;
            }
            5 => {
                input.top_variables = usize::BITS as usize;
            }
            _ => {
                input.multiplicity.resize(input.table.len() + 1, K::ZERO);
            }
        }
        assert!(
            matches!(
                crate::lookup::Prepared::new(&input),
                Err(crate::lookup::Error::Shape)
            ),
            "malformed {change}"
        );
    }
}

#[cfg(feature = "cuda")]
pub(crate) fn lazy(words: &mut [u32]) {
    for word in words {
        *word += M31::MODULUS;
    }
}

pub(crate) fn inverse_inputs() -> Vec<u32> {
    let p = M31::MODULUS;
    let edges = [0, 1, p - 1, p, p + 1, 2 * p - 1];
    let mut rng = Rng::new(SEED);
    (0..crate::field_cases::CASES)
        .flat_map(|case| {
            if case < 36 {
                let mut v = [0; 4];
                v[case / 6 % 4] = edges[case % 6];
                v
            } else {
                core::array::from_fn(|_| {
                    (rng.next() % u64::from(if case % 2 == 0 { p } else { 2 * p })) as u32
                })
            }
        })
        .collect()
}

pub(crate) fn verify_inverses(input: &[u32], output: &[u32]) {
    use stele_reductions::stele_field::Inverse;
    assert_eq!(input.len(), 4 * crate::field_cases::CASES);
    assert_eq!(output.len(), input.len());
    for (case, (raw, actual)) in input
        .chunks_exact(4)
        .zip(output.chunks_exact(4))
        .enumerate()
    {
        let m = |i| M31::from_lazy(raw[i]).unwrap();
        let x = crate::QM31(crate::CM31(m(0), m(1)), crate::CM31(m(2), m(3)));
        let expected = crate::lookup::words(x.inverse().unwrap_or(K::ZERO));
        assert_eq!(actual, expected, "inverse case {case}");
    }
}

#[test]
fn matches_reference_lookup_inverse_on_host() {
    let main = r#"
int main() {
  u32 in[4], out[4];
  while (true) {
    auto count = std::fread(in, sizeof(u32), 4, stdin);
    if (!count) return std::ferror(stdin) ? 1 : 0;
    if (count != 4) return 2;
    qstore(out, 0, qinverse(qload(in, 0)));
    if (std::fwrite(out, sizeof(u32), 4, stdout) != 4) return 3;
  }
}
"#;
    let inverse = include_str!("lookup.cu")
        .split_once("// RFC-0008 A7:")
        .expect("inverse boundary")
        .0;
    let source = format!("#include <cstdio>\n#define __device__\n#define __forceinline__ inline\n{}\n{inverse}\n{main}", crate::host_probe::helpers());
    let input = inverse_inputs();
    verify_inverses(&input, &crate::host_probe::run(&source, &input));
}

#[test]
fn matches_reference_lookup_kernels_on_host() {
    use crate::lookup::{Error, Prepared};
    let mut input = Vec::new();
    let mut cases = Vec::new();
    for case in 0..=CASES {
        let (s, data, mut beta, mut alpha) = fixture(SEED + 2 * case as u64);
        if case == CASES {
            beta = K::ZERO;
            alpha = K::ZERO;
        }
        let c = LookupCase::new(&s, &data, 0).unwrap();
        for raw in [0, 1] {
            let p = Prepared::new(&c.inputs(beta, alpha)).unwrap();
            input.extend([
                p.n as u32,
                p.width as u32,
                p.mults as u32,
                p.top as u32,
                raw,
            ]);
            input.extend_from_slice(&p.values);
            input.extend_from_slice(&p.selector);
            cases.push((p, c.reference(beta, alpha)));
        }
    }
    let source = format!("#include <cstdio>\n#include <vector>\n#include <algorithm>\n#define __device__\n#define __global__\n#define __forceinline__ inline\n{}\n#define GRID_STRIDE(j,n) for (u64 j=0; j<(n); ++j)\n{}\n{}", crate::host_probe::helpers(), include_str!("lookup.cu"), include_str!("lookup_host.cuh"));
    let output = crate::host_probe::run(&source, &input);
    let mut rest = &output[..];
    for (case, (p, expected)) in cases.iter().enumerate() {
        let (tree, tail) = rest.split_at(p.tree_words);
        let (h, tail) = tail.split_at(4 * p.top);
        let (flags, tail) = tail.split_at(p.top);
        rest = tail;
        let actual = p.finish(tree, h, flags);
        match expected {
            Ok(expected) => {
                let actual = actual.unwrap();
                assert_eq!(actual.layers, expected.layers, "all layers case {case}");
                assert_eq!(actual.top, expected.top, "top case {case}");
            }
            Err(stele_reductions::zk::Error::DenominatorZero) => {
                assert!(matches!(actual, Err(Error::DenominatorZero)))
            }
            Err(e) => panic!("unexpected reference error {e:?}"),
        }
    }
    assert!(rest.is_empty(), "extra outputs");
    let p = &cases[0].0;
    let (tree, tail) = output.split_at(p.tree_words);
    let (h, tail) = tail.split_at(4 * p.top);
    let flags = &tail[..p.top];
    assert!(matches!(
        p.finish(&tree[..tree.len() - 1], h, flags),
        Err(Error::Shape)
    ));
    let mut bad_tree = tree.to_vec();
    bad_tree[0] = M31::MODULUS;
    assert!(matches!(p.finish(&bad_tree, h, flags), Err(Error::Value)));
    let mut bad_flags = flags.to_vec();
    bad_flags[0] = 2;
    assert!(matches!(p.finish(tree, h, &bad_flags), Err(Error::Value)));
    let mut h = h.to_vec();
    h[0] = M31::MODULUS;
    assert!(matches!(p.finish(tree, &h, flags), Err(Error::Value)));
}
