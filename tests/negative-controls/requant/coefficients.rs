//! RFC-0023 §5: one false sigma claim after an actual accepting A3.
use super::*;
use stele_field::Field;
use stele_hash::AbsorbLabel;
use stele_negative_controls::{check_control, ProverHook};
use stele_reductions::lookup;
use stele_sumcheck::zerocheck;

pub(super) fn rejects_sigma<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
    c: &Value,
    schema: &Schema,
    input: &VerifiedCertificate<K>,
    advice: &VerifiedCertificate<K>,
    mu: [&[&VerifiedCertificate<K>]; 2],
    descriptor: &Descriptor<'_, '_, K>,
    wire: &[u8],
) where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    assert_eq!(c["n"], 2);
    assert_eq!(c["parameters"], json!({"bits":8,"mantissa":1,"shift":1}));
    assert_eq!(c["repetitions"], 1);
    let base = 31u64 << 40;
    let public = unhex(&c["public_hex"]);
    let prefix = || {
        let mut t = Transcript::<K>::new(&public).expect("fixed prefix");
        t.absorb(
            AbsorbLabel::RequantStatement,
            &descriptor.encode().expect("statement"),
        )
        .expect("actual absorb");
        let mut at = 34
            + advice
                .record()
                .source()
                .proof_size(ProofKind::Certificate)
                .expect("advice packet size");
        let mut local = 1; // The closed verifier also hashes the advice packet identity.
        let table = lookup::Table::range(8).expect("range8");
        for (b, certificate) in [input, advice].into_iter().enumerate() {
            let source = certificate.record().source();
            let m = (source.rows() * source.columns()).ilog2() as u8;
            let originals = [certificate];
            let selectors = vec![1; 1 << m];
            let layouts = [lookup::Layout {
                id: base + 16 + 2 * b as u64,
                ell: 0,
                blowup: 1,
            }];
            let child = lookup::Descriptor::new(
                lookup::Statement {
                    id: base / 16 + 8 + b as u64,
                    m,
                    b: m,
                    table: &table,
                    selector: &selectors,
                    originals: &originals,
                    multiplicities: &layouts,
                },
                Limits {
                    positions: 4096,
                    public_bytes: 32_000_000,
                    proof_bytes: 32_000_000,
                },
            )
            .expect("actual fixed A5");
            let end = at + child.proof_size();
            let (_, usage) = child
                .verify(&mut t, mu[b], &wire[at..end])
                .expect("genuine saved A5");
            local += usage.non_transcript.hash_evaluations;
            at = end;
        }
        t.absorb(
            AbsorbLabel::RequantConstraints,
            &descriptor.encode_constraints().expect("constraints"),
        )
        .expect("actual absorb");
        let constraints = schema.constraints::<K>().expect("fixed polynomials");
        let mut terms = Vec::new();
        for equation in constraints.equations() {
            let weight = t
                .challenge(ChallengeLabel::RequantWeight)
                .expect("independent draw");
            for term in equation {
                assert!(!term.factors.is_empty(), "zero tables satisfy every term");
                assert!(
                    term.factors.iter().filter(|&&f| f == 0).count() <= 1,
                    "the fixed aggregate is affine in sigma"
                );
                terms.push(Term {
                    coefficient: weight * term.coefficient,
                    factors: term.factors.clone(),
                });
            }
        }
        let inputs = core::iter::once(base + (1 << 28))
            .chain((0..4 + schema.rows()).map(|i| base + (1 << 24) + i as u64))
            .collect();
        (
            t,
            Instance {
                id: base + 1024,
                num_vars: 1,
                inputs,
                terms,
                claimed_sum: K::from_i64(0),
            },
            at,
            local,
        )
    };
    let (mut t, aggregate, at, local) = prefix();
    let engine = zerocheck::Zerocheck {
        instance: &aggregate,
        skip: 0,
    };
    // Actual zero-table A3 gives the candidate's round point, not source authority.
    let mut packet = engine
        .prove(&vec![vec![K::from_i64(0); 2]; 5 + schema.rows()], &mut t)
        .expect("actual zero-table producer");
    let (mut t, _, _, _) = prefix();
    let zero = engine
        .verify(&packet, &mut t)
        .expect("actual zero-table A3");
    let point = &zero.claims[0].point;
    assert_eq!(point.len(), 1);
    let z = point[0];
    // Genuine two-column input/advice planes, independently reconstructed from
    // the pinned signed-tie witnesses and checked against their original roots.
    let u = [255u8, 1, 255, 0, 255, 0, 127, 128];
    let left = fixture("control-tie-negative.bin");
    let right = fixture("control-tie-positive.bin");
    assert_eq!((left.len(), right.len()), (schema.rows(), schema.rows()));
    let bytes: Vec<_> = left
        .iter()
        .zip(&right)
        .flat_map(|(&a, &b)| [a, b])
        .collect();
    for (raw, certificate) in [(&u[..], input), (&bytes[..], advice)] {
        let source = certificate.record().source();
        let message: Vec<_> = raw
            .iter()
            .map(|&b| stele_field::M31::from_i64(i64::from(b)))
            .collect();
        let prepared = stele_pcs::PreparedSource::<K>::new(
            source.descriptor().id,
            source.rows().ilog2() as u8,
            1,
            1,
            &message,
            &mut HashUsage::default(),
        )
        .expect("actual source");
        assert_eq!(prepared.source().bytes(), source.bytes());
    }
    let mut values = vec![K::from_i64(0)];
    for pair in u.chunks_exact(2).chain(bytes.chunks_exact(2)) {
        values.push(
            K::from_i64(i64::from(pair[0])) * (K::from_i64(1) - z)
                + K::from_i64(i64::from(pair[1])) * z,
        );
    }
    let evaluate = |values: &[K]| {
        aggregate.terms.iter().fold(K::from_i64(0), |sum, term| {
            sum + term
                .factors
                .iter()
                .fold(term.coefficient, |product, &i| product * values[i as usize])
        })
    };
    let intercept = evaluate(&values);
    values[0] = K::from_i64(1);
    let slope = evaluate(&values) - intercept;
    let false_sigma = -intercept * slope.inverse().expect("fixed nonzero slope; never retry");
    assert_ne!(
        false_sigma,
        K::from_i64(1),
        "fixed false sigma; never retry"
    );
    values[0] = false_sigma;
    assert_eq!(evaluate(&values), K::from_i64(0));
    packet.final_values = values;
    let (mut t, _, _, _) = prefix();
    let accepted = engine
        .verify(&packet, &mut t)
        .expect("real A3 accepts the false public claim");
    assert_eq!(accepted.claims[0].point, *point);
    for (claim, value) in accepted.claims.iter().zip(&packet.final_values) {
        assert_eq!(claim.point, *point);
        assert_eq!(claim.value, *value);
    }
    let prefix_usage = t.usage();
    let replacement: Vec<_> = packet
        .rounds
        .iter()
        .flatten()
        .chain(&packet.final_values)
        .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
        .collect();
    assert_eq!(
        replacement.len(),
        4 * usize::from(<K as CodeField>::DEGREE) * (4 + 5 + schema.rows())
    );
    let mut candidate = wire.to_vec();
    candidate[at..at + replacement.len()].copy_from_slice(&replacement);
    assert_eq!(&candidate[..at], &wire[..at]);
    assert_eq!(
        &candidate[at + replacement.len()..],
        &wire[at + replacement.len()..]
    );
    struct Sigma<K>(K);
    impl<K: Copy + Eq + core::fmt::Debug> ProverHook<K> for Sigma<K> {
        fn tamper(&self, claim: &mut K) {
            assert_ne!(*claim, self.0);
            *claim = self.0;
        }
    }
    // One semantic coefficient changes; rounds/source finals are dependent messages.
    // The saved suffix is canonical and unreachable, not later-consumer evidence.
    check_control(
        &K::from_i64(1),
        &Sigma(false_sigma),
        |sigma| {
            assert!(*sigma == K::from_i64(1) || *sigma == false_sigma);
            Ok::<_, String>(if *sigma == K::from_i64(1) {
                wire.to_vec()
            } else {
                candidate.clone()
            })
        },
        |proof| {
            let mut t = Transcript::new(&public).expect("fixed prefix");
            descriptor
                .verify(&mut t, mu, proof)
                .map(|_| ())
                .map_err(|failure| {
                    assert_eq!(failure.usage.transcript, prefix_usage);
                    assert_eq!(
                        failure.usage.non_transcript,
                        HashUsage {
                            hash_evaluations: local,
                            ..HashUsage::default()
                        }
                    );
                    failure.cause
                })
        },
        stele_reductions::requant::Error::CoefficientMismatch,
    )
    .expect("actual sigma A7 rejects");
}
