//! RFC-0003 §§1/2/6: actual CUDA helper expressions against stele-field.
//! No committed or virtual columns; canonical field equality is the only claim.
use crate::{Field, Rng, CM31, M31, QM31};

pub(crate) const CASES: usize = 1_000_000;
pub(crate) const SEED: u64 = 0x40_0000_0001;
pub(crate) const INPUT_WORDS: usize = 8;
pub(crate) const OUTPUT_WORDS: usize = 28;
pub(crate) const CALLS: &str = include_str!("field_cases.cuh");

pub(crate) fn inputs() -> Vec<u32> {
    let p = M31::MODULUS;
    let edges = [0, 1, p - 1, p, p + 1, 2 * p - 1];
    let mut rng = Rng::new(SEED);
    (0..CASES)
        .flat_map(|case| {
            core::array::from_fn::<_, INPUT_WORDS, _>(|limb| {
                if case < edges.len() * edges.len() {
                    let axis = if limb < 4 { case / 6 } else { case % 6 };
                    edges[(axis + limb % 4) % edges.len()]
                } else {
                    let limit = if case % 2 == 0 { p } else { 2 * p };
                    (rng.next() % u64::from(limit)) as u32
                }
            })
        })
        .collect()
}

fn element(words: &[u32]) -> QM31 {
    let m = |i| M31::from_lazy(words[i]).expect("fixture is in [0,2p)");
    QM31(CM31(m(0), m(1)), CM31(m(2), m(3)))
}

fn limbs(value: QM31) -> [u32; 4] {
    [
        value.0 .0.as_u32(),
        value.0 .1.as_u32(),
        value.1 .0.as_u32(),
        value.1 .1.as_u32(),
    ]
}

pub(crate) fn verify(input: &[u32], output: &[u32]) {
    assert_eq!(input.len(), CASES * INPUT_WORDS);
    assert_eq!(output.len(), CASES * OUTPUT_WORDS);
    for (case, (raw, actual)) in input
        .chunks_exact(INPUT_WORDS)
        .zip(output.chunks_exact(OUTPUT_WORDS))
        .enumerate()
    {
        let (x, y) = (element(&raw[..4]), element(&raw[4..]));
        let (a, b) = (x.0 .0, y.0 .0);
        let mut expected = [0; OUTPUT_WORDS];
        expected[..4].copy_from_slice(&[
            (a + b).as_u32(),
            (a - b).as_u32(),
            (a * b).as_u32(),
            (-a).as_u32(),
        ]);
        for (slot, value) in expected[4..].chunks_exact_mut(4).zip([
            x + y,
            x - y,
            x * QM31::from_i64(i64::from(b.as_u32())),
            x * y,
            x,
            QM31::from_i64(i64::from(a.as_u32())),
        ]) {
            slot.copy_from_slice(&limbs(value));
        }
        assert!(
            actual.iter().all(|word| *word < M31::MODULUS),
            "noncanonical case {case}: {raw:?} -> {actual:?}"
        );
        assert_eq!(actual, expected, "case {case}: {raw:?}");
    }
}

#[test]
fn matches_reference_cuda_field_helpers_on_host() {
    let main = r#"
int main() {
  static_assert(sizeof(u32) == 4, "u32 width");
  u32 in[8], out[28];
  while (true) {
    auto count = std::fread(in, sizeof(u32), 8, stdin);
    if (!count) return std::ferror(stdin) ? 1 : 0;
    if (count != 8) return 2;
    field_case(in, out);
    if (std::fwrite(out, sizeof(u32), 28, stdout) != 28) return 3;
  }
}
"#;
    let input = inputs();
    let source = format!("#include <cstdio>\n#define __device__\n#define __forceinline__ inline\n{}\n{CALLS}\n{main}", crate::host_probe::helpers());
    let output = crate::host_probe::run(&source, &input);
    verify(&input, &output);
}
