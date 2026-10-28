//! RFC-0006 A3 reference: exhaustive residual sums over original slice MLEs.
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{
    message_bytes,
    zerocheck::{Proof, Zerocheck},
    Instance,
};
fn bits<K: ChallengeField>(value: usize, width: usize) -> Vec<K> {
    (0..width)
        .map(|bit| K::from_i64(((value >> (width - bit - 1)) & 1) as i64))
        .collect()
}
fn dot<K: ChallengeField>(a: &[K], b: &[K]) -> K {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .fold(K::from_i64(0), |v, (a, b)| v + *a * *b)
}
fn basis<K: ChallengeField>(u: K, size: usize) -> Vec<K> {
    (0..size)
        .map(|b| {
            let (mut numerator, mut denominator) = (K::from_i64(1), K::from_i64(1));
            for c in 0..size {
                if c != b {
                    numerator = numerator * (u - K::from_i64(c as i64));
                    denominator = denominator * K::from_i64(b as i64 - c as i64);
                }
            }
            numerator * denominator.inverse().expect("distinct fixed nodes")
        })
        .collect()
}
fn slices<K: ChallengeField>(tables: &[Vec<K>], s: usize, point: &[K]) -> Vec<Vec<K>> {
    let eq = stele_poly::eq_table(point).expect("small reference shape");
    tables
        .iter()
        .map(|table| {
            assert_eq!(table.len(), s * eq.len());
            table
                .chunks_exact(eq.len())
                .map(|slice| dot(slice, &eq))
                .collect()
        })
        .collect()
}
fn residual<K: ChallengeField>(
    i: &Instance<K>,
    tables: &[Vec<K>],
    weights: &[K],
    prefix: &[K],
    alpha: &[K],
) -> K {
    let remaining = alpha.len() - prefix.len();
    (0..1usize << remaining).fold(K::from_i64(0), |sum, vertex| {
        let tail = bits::<K>(vertex, remaining);
        let point: Vec<_> = prefix.iter().chain(&tail).copied().collect();
        let values: Vec<_> = slices(tables, weights.len(), &point)
            .iter()
            .map(|row| dot(weights, row))
            .collect();
        let relation = i.terms.iter().fold(K::from_i64(0), |sum, term| {
            sum + term
                .factors
                .iter()
                .fold(term.coefficient, |v, index| v * values[*index as usize])
        });
        sum + stele_poly::eq_evaluate(&alpha[prefix.len()..], &tail).expect("equal shapes")
            * relation
    })
}
/// Honest reference prover: no dense hybrid construction or tail-table folding.
pub fn prove<K: ChallengeField + Eq>(
    z: &Zerocheck<'_, K>,
    tables: &[Vec<K>],
    t: &mut Transcript<K>,
) -> Proof<K> {
    let i = z.instance;
    let (s, j) = (1usize << z.skip, i.num_vars as usize - z.skip as usize);
    let degree = i.terms.iter().map(|t| t.factors.len()).max().unwrap_or(0);
    t.absorb(AbsorbLabel::Zero, &z.encode().expect("descriptor"))
        .expect("absorb");
    let alpha: Vec<_> = (0..j)
        .map(|_| t.challenge(ChallengeLabel::ZeroWeight).expect("weight"))
        .collect();
    let skip_values: Vec<_> = if z.skip == 0 {
        vec![]
    } else {
        (s..=degree * (s - 1))
            .map(|node| residual(i, tables, &basis(K::from_i64(node as i64), s), &[], &alpha))
            .collect()
    };
    let weights = if z.skip == 0 {
        vec![K::from_i64(1)]
    } else {
        t.absorb(
            AbsorbLabel::ZeroSkip,
            &message_bytes(i.id, skip_values.len() as u32, &skip_values).expect("message"),
        )
        .expect("absorb");
        basis(
            t.challenge(ChallengeLabel::Sumcheck)
                .expect("skip challenge"),
            s,
        )
    };
    let (mut rounds, mut point) = (vec![], vec![]);
    for h in 0..j {
        let row: Vec<_> = (0..=degree)
            .map(|node| {
                let mut prefix = point.clone();
                prefix.push(K::from_i64(node as i64));
                residual(i, tables, &weights, &prefix, &alpha)
            })
            .collect();
        t.absorb(
            AbsorbLabel::Round,
            &message_bytes(i.id, h as u32, &row).expect("message"),
        )
        .expect("absorb");
        point.push(
            t.challenge(ChallengeLabel::Sumcheck)
                .expect("round challenge"),
        );
        rounds.push(row);
    }
    let final_values: Vec<_> = slices(tables, s, &point).into_iter().flatten().collect();
    let mut bytes = message_bytes::<K>(i.id, tables.len() as u32, &[]).expect("message");
    bytes.extend_from_slice(&(s as u32).to_le_bytes());
    for value in &final_values {
        bytes.extend_from_slice(value.to_le_bytes().as_ref());
    }
    t.absorb(AbsorbLabel::ZeroFinal, &bytes).expect("absorb");
    Proof {
        skip_values,
        rounds,
        final_values,
    }
}
