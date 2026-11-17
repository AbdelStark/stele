//! RFC-0014 §5: execute the actual descriptor expression against production Masked.
use crate::{
    challenge, cpu, inventory::Inventory, round::Terms, FactorSpec, Field, Rng, Shape, Source, K,
    M31,
};

fn words(x: K) -> [u32; 4] {
    [
        x.0 .0.as_u32(),
        x.0 .1.as_u32(),
        x.1 .0.as_u32(),
        x.1 .1.as_u32(),
    ]
}

fn encode(shape: &Shape, raw: bool, input: &mut Vec<u32>, expected: &mut Vec<u32>) {
    let terms = Terms::new(shape.factors.len(), &shape.terms, shape.degree + 1).unwrap();
    let mut reference = cpu(shape);
    for round in 0..shape.n {
        let len = 1 << (shape.n - round);
        let flags: Vec<u32> = shape
            .factors
            .iter()
            .map(|f| {
                u32::from(round == 0 && f.x.is_base())
                    | f.mask
                        .as_ref()
                        .filter(|(_, v)| *v == round)
                        .map_or(0, |(r, _)| 2 | (u32::from(round == 0 && r.is_base()) << 2))
            })
            .collect();
        input.extend([
            shape.factors.len() as u32,
            shape.terms.len() as u32,
            (shape.degree + 1) as u32,
            len as u32,
            terms.factors.len() as u32,
        ]);
        input.extend(&terms.offsets);
        input.extend(&terms.factors);
        let lift = |x: u32| if raw { x + M31::MODULUS } else { x };
        input.extend(shape.terms.iter().flat_map(|(c, _)| words(*c)).map(lift));
        input.extend(&flags);
        for ((x, r), flag) in reference.tables().zip(flags) {
            for v in x {
                input.extend(
                    words(*v)[..if flag & 1 != 0 { 1 } else { 4 }]
                        .iter()
                        .copied()
                        .map(lift),
                );
            }
            if flag & 2 != 0 {
                for v in r {
                    input.extend(
                        words(*v)[..if flag & 4 != 0 { 1 } else { 4 }]
                            .iter()
                            .copied()
                            .map(lift),
                    );
                }
            }
        }
        expected.extend(reference.round().unwrap().into_iter().flat_map(words));
        reference.fold(challenge(round)).unwrap();
    }
}

fn evaluate(input: &[u32]) -> Vec<u32> {
    let main = r#"
#include <vector>
#include <cstdlib>
std::vector<u32> read_words(size_t n) { std::vector<u32> v(n); if (n && std::fread(v.data(),4,n,stdin)!=n) std::abort(); return v; }
int main() {
  u32 h[5];
  while (std::fread(h,4,5,stdin)==5) {
    auto off=read_words(h[1]+1), ids=read_words(h[4]), co=read_words(h[1]*4), flags=read_words(h[0]);
    std::vector<std::vector<u32>> x(h[0]),r(h[0]); std::vector<u64> xp(h[0]),rp(h[0]);
    for (u32 k=0;k<h[0];k++) {
      x[k]=read_words(h[3]*((flags[k]&1)?1:4)); xp[k]=(u64)x[k].data();
      if (flags[k]&2) { r[k]=read_words(h[3]*((flags[k]&4)?1:4)); rp[k]=(u64)r[k].data(); }
    }
    for (u32 t=0;t<h[2];t++) {
      Q acc=qzero();
      for (u64 j=0;j<h[3]/2;j++) acc=qadd(acc,round_entry(xp.data(),rp.data(),flags.data(),off.data(),ids.data(),co.data(),h[1],j,h[3]/2,t));
      if (std::fwrite(&acc,4,4,stdout)!=4) return 1;
    }
  }
  return std::ferror(stdin)?1:0;
}
"#;
    let source = format!(
        "#include <cstdio>\n#define __device__\n#define __forceinline__ inline\n{}\n{}\n{main}",
        crate::host_probe::helpers(),
        include_str!("round.cuh")
    );
    crate::host_probe::run(&source, input)
}

pub(crate) fn synthetic(case: usize, rng: &mut Rng) -> Shape {
    let n = 3 + case % 3;
    let len = 1 << n;
    let factor = |rng: &mut Rng, base| {
        if base {
            Source::Column {
                values: (0..len)
                    .map(|i| match i {
                        0 => M31::from_u64(0),
                        1 => M31::from_u64(1),
                        2 => M31::from_u64(u64::from(M31::MODULUS) - 1),
                        _ => rng.m31(),
                    })
                    .collect(),
            }
        } else {
            Source::Tile {
                period: (0..len).map(|_| rng.qm31()).collect(),
            }
        }
    };
    let factors = (0..4)
        .map(|k| FactorSpec {
            x: factor(rng, (case >> k) & 1 == 0),
            mask: if k == 3 {
                None
            } else {
                Some((factor(rng, (case >> (k + 4)) & 1 == 0), (case + k) % n))
            },
        })
        .collect();
    Shape {
        name: "descriptor",
        n,
        factors,
        degree: if case.is_multiple_of(31) { 31 } else { 8 },
        terms: vec![
            (K::from_i64(1), vec![]),
            (K::from_i64(-1), vec![0]),
            (rng.qm31(), vec![2, 1, 2]),
            (K::from_i64(0), vec![3]),
            (rng.qm31(), vec![0, 1, 3]),
        ],
    }
}

#[test]
fn matches_reference_descriptor_rounds_and_lazy_words() {
    let mut input = Vec::new();
    let mut expected = Vec::new();
    let mut rng = Rng::new(0x40_1001);
    for case in 0..1000 {
        let shape = synthetic(case, &mut rng);
        encode(&shape, case % 2 == 0, &mut input, &mut expected);
    }
    for (text, seed) in [
        (
            include_str!("../tests/fixtures/prepare-case-9.txt"),
            67960851,
        ),
        (
            include_str!("../tests/fixtures/prepare-case-11.txt"),
            67960855,
        ),
    ] {
        let inventory = Inventory::parse(text).unwrap();
        for mode in 0..3 {
            encode(
                &inventory.case(mode, seed).shape,
                mode != 0,
                &mut input,
                &mut expected,
            );
        }
    }
    let actual = evaluate(&input);
    assert_eq!(actual.len(), expected.len());
    for (i, (a, e)) in actual.iter().zip(expected).enumerate() {
        assert!(*a < M31::MODULUS && *a == e, "word {i}: {a} != {e}");
    }
}

#[test]
fn rejects_changed_constant_coefficient() {
    let mut shape = Shape {
        name: "constant",
        n: 1,
        factors: vec![FactorSpec {
            x: Source::Column {
                values: vec![M31::from_u64(0); 2],
            },
            mask: None,
        }],
        terms: vec![(K::from_i64(1), vec![])],
        degree: 0,
    };
    let (mut input, mut expected) = (Vec::new(), Vec::new());
    encode(&shape, false, &mut input, &mut expected);
    assert_eq!(evaluate(&input), expected);
    shape.terms[0].0 = K::from_i64(2);
    input.clear();
    encode(&shape, false, &mut input, &mut Vec::new());
    assert_ne!(evaluate(&input), expected);
}
