//! RFC-0023 §6: actual binding controls, separate from every verifier crate.
use crate::{check_control, check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};
use stele_reductions::{
    lookup::TableField,
    requant::{Descriptor, Format, Schema, Statement},
};
use stele_sumcheck::Proof;
#[path = "requant_composer.rs"]
mod composer;
use composer::{compose, following, verify, verify_wire, Attack, Packet, LIMITS};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/requant")
            .join(name),
    )
    .expect("pinned fixture file")
}
#[derive(Clone, PartialEq, Eq)]
struct Witness {
    input_view: i32,
    advice: Vec<u8>,
}
enum Change {
    Input(i32),
    Byte(usize, u8),
}
impl ProverHook<Witness> for Change {
    fn tamper(&self, w: &mut Witness) {
        match *self {
            Self::Input(value) => {
                assert_ne!(w.input_view, value);
                w.input_view = value;
            }
            Self::Byte(row, value) => {
                assert_ne!(w.advice[row], value);
                w.advice[row] = value;
            }
        }
    }
}
struct Row {
    at: usize,
    value: Vec<u8>,
}
impl ProverHook<Vec<u8>> for Row {
    fn tamper(&self, wire: &mut Vec<u8>) {
        let end = self.at + self.value.len();
        assert_ne!(&wire[self.at..end], self.value);
        wire[self.at..end].copy_from_slice(&self.value);
    }
}
struct Final<K>(K);
impl<K: Copy + Eq + core::fmt::Debug> ProverHook<Proof<K>> for Final<K> {
    fn tamper(&self, proof: &mut Proof<K>) {
        assert_eq!(proof.final_values.len(), 1);
        assert_ne!(proof.final_values[0], self.0);
        proof.final_values[0] = self.0;
    }
}
fn verify_following<K: ChallengeField + CodeField + TableField + Eq>(
    p: &Packet<K>,
    s: &Schema,
    value: i64,
    public: &[u8],
    proof: &Proof<K>,
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let d = Descriptor::new(
        Statement {
            stage: 31,
            n: 1,
            schema: s,
            repetitions: 1,
            advice_blowup: 1,
            point: &[],
            value: K::from_i64(value),
            input: &p.input,
        },
        &p.advice,
        LIMITS,
    )
    .expect("fixed statement");
    let (mu, _) = d
        .register_multiplicities(&p.wire, 32_000_000)
        .expect("real registrations");
    let refs = mu.each_ref().map(|v| v.iter().collect::<Vec<_>>());
    let mut t = Transcript::new(public).expect("fixed public prefix");
    let (_record, _) = d
        .verify(&mut t, [&refs[0], &refs[1]], &p.wire)
        .map_err(|f| format!("Requant:{:?}", f.cause))?;
    stele_sumcheck::verify_public(
        &composer::next(),
        proof,
        &[vec![K::from_i64(1), K::from_i64(2)]],
        &mut t,
    )
    .map(|_| ())
    .map_err(|e| format!("{e:?}"))
}
fn input_padding<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    // Independently expected [-1,0,1] offset bytes, with literal zero padding.
    let input_view: Vec<u8> = vec![255, 0, 1, 0, 255, 0, 0, 0, 255, 0, 0, 0, 127, 128, 128, 0];
    let message: Vec<_> = input_view
        .iter()
        .map(|&b| M31::from_i64(i64::from(b)))
        .collect();
    let prepared = PreparedSource::<K>::new(73, 2, 2, 1, &message, &mut HashUsage::default())
        .expect("genuine fixed input");
    let certificate = prepared
        .certificate()
        .expect("actual certificate production")
        .0;
    let input = verify_certificate(*prepared.source(), &certificate)
        .expect("actual input import")
        .0;
    let degree = <K as CodeField>::DEGREE;
    let baseline = fixture(&format!("padded-K{degree}.bin"));
    let candidate = fixture(&format!("input-padding-K{degree}.bin"));
    let schema = Schema::new(1, 2, Format::Int8).expect("fixed schema");
    let root = baseline[2..34].try_into().expect("root width");
    let source = schema
        .advice_source::<K>(31, 3, 1, root)
        .expect("expected advice context");
    let end = 34
        + source
            .proof_size(ProofKind::Certificate)
            .expect("certificate size");
    let width = 4 * usize::from(degree);
    let zero_bytes = width * (4 * 2 + 5 + schema.rows());
    let output_bytes = width * (4 * 2 + 2 + schema.values()[2].value().len());
    let after_zero = baseline.len()
        - output_bytes
        - 2 * source
            .proof_size(ProofKind::Opening)
            .expect("advice opening size")
        - prepared
            .source()
            .proof_size(ProofKind::Opening)
            .expect("input opening size");
    let before_zero = after_zero - zero_bytes;
    assert_eq!(candidate.len(), baseline.len());
    assert_eq!(&candidate[..before_zero], &baseline[..before_zero]);
    assert_eq!(&candidate[after_zero..], &baseline[after_zero..]);
    assert_ne!(
        &candidate[before_zero..after_zero],
        &baseline[before_zero..after_zero]
    );
    let advice = schema
        .register_advice::<K>(31, 3, 1, root, &baseline[34..end], 32_000_000)
        .expect("genuine fixed advice")
        .0;
    let point: Vec<K> = (0..2)
        .map(|k| {
            let bytes: Vec<u8> = (0..u32::from(degree))
                .flat_map(|i| (3 + k + i).to_le_bytes())
                .collect();
            K::from_le_bytes(
                K::Bytes::try_from(bytes.as_slice())
                    .ok()
                    .expect("field width"),
            )
            .expect("canonical fixed point")
        })
        .collect();
    let d = Descriptor::new(
        Statement {
            stage: 31,
            n: 3,
            schema: &schema,
            repetitions: 1,
            advice_blowup: 1,
            point: &point,
            value: K::from_i64(0),
            input: &input,
        },
        &advice,
        LIMITS,
    )
    .expect("unchanged expected statement");
    let mut public = b"RFC0023/batched/independent-reference/v1/padded".to_vec();
    public.push(degree);
    // The two pinned artifacts were produced from exactly this one arithmetic-view
    // byte change by input_padding_fixture.py, using the actual reference A3.
    // Expected original/advice handles and all A5 packets remain unchanged.
    check_control(
        &input_view,
        &Row {
            at: 3,
            value: vec![1],
        },
        |view| {
            assert_eq!(view.len(), input_view.len());
            assert!(view
                .iter()
                .zip(&input_view)
                .enumerate()
                .all(|(i, (a, b))| if i == 3 { *a <= 1 && *b == 0 } else { a == b }));
            Ok::<_, String>(if view == &input_view {
                baseline.clone()
            } else {
                candidate.clone()
            })
        },
        |wire| {
            let (mu, _) = d
                .register_multiplicities(wire, 32_000_000)
                .map_err(|f| format!("import:{:?}", f.cause))?;
            let refs = mu.each_ref().map(|v| v.iter().collect::<Vec<_>>());
            let mut t = Transcript::new(&public).expect("original public prefix");
            d.verify(&mut t, [&refs[0], &refs[1]], wire)
                .map(|_| ())
                .map_err(|f| format!("{:?}", f.cause))
        },
        "Sumcheck(RoundSumMismatch)".to_owned(),
    )
    .map_err(|e| format!("input padding: {e:?}"))
}
fn check<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
    id: u16,
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let cases: &[(&str, i32, u32, i64)] = match id {
        100 | 101 => &[("tie-negative", -1, 1, -1), ("tie-positive", 1, 1, 1)],
        308 => &[("zero-31", 0, 31, 0)],
        313 => &[("zero-0", 0, 0, 0)],
        310 => &[("one-0", 1, 0, 1)],
        _ => &[("negative-h", -128, 0, -128)],
    };
    for &(name, acc, shift, value) in cases {
        let schema = Schema::new(1, shift, Format::Int8).expect("fixed schema");
        let mut public = b"RFC0023/batched/independent-reference/v1/scalar".to_vec();
        public.push(<K as CodeField>::DEGREE);
        let advice = fixture(&format!("control-{name}.bin"));
        let honest = Witness {
            input_view: acc,
            advice,
        };
        let mut baseline = compose::<K>(
            &schema,
            acc,
            acc,
            &honest.advice,
            value,
            &public,
            Attack::Honest,
            None,
        );
        verify(&baseline, &schema, value, &public).map_err(|f| format!("honest:{:?}", f.cause))?;
        if name == "negative-h" {
            assert_eq!(
                baseline.wire,
                fixture(&format!("scalar-K{}.bin", <K as CodeField>::DEGREE)),
                "actual scalar producer matches independent full wire"
            );
        }
        if id == 109 {
            // RFC-0023 §6 / RFC-0022 §6: the actual expected static validator.
            // This is a forged bound scalar, not a claimed inference proof.
            let bytes = schema.bounds().as_bytes();
            let scalars = b"stele/v0.1/cqis/bounds".len() + 4 + 1 + 2 + 4 + 4 + 1 + 1;
            let product = scalars + 2 * 20;
            let change = Row {
                at: product,
                value: vec![0; 20],
            };
            check_proof_control(
                || Ok::<_, String>(bytes.to_vec()),
                &change,
                |raw| {
                    schema
                        .bounds()
                        .validate_encoding(raw)
                        .map_err(|e| format!("{e:?}"))
                },
                "Encoding".to_owned(),
            )
            .map_err(|e| format!("static Requant bound: {e:?}"))?;
            continue;
        }
        if id == 802 {
            let next = following(&mut baseline.transcript);
            let response = &baseline.wire[baseline.group_offsets[2]..];
            let mut replay = compose::<K>(
                &schema,
                acc,
                acc,
                &honest.advice,
                value,
                &public,
                Attack::ReplayResponses,
                Some(response),
            );
            assert_eq!(replay.wire, baseline.wire);
            assert_eq!(following(&mut replay.transcript), next);
            for frame in 0..6 {
                let mut other = compose::<K>(
                    &schema,
                    acc,
                    acc,
                    &honest.advice,
                    value,
                    &public,
                    Attack::OmitFrame(frame),
                    Some(response),
                );
                let wrong = following(&mut other.transcript);
                assert_eq!(wrong.rounds, next.rounds);
                check_proof_control(
                    || Ok::<_, String>(next.clone()),
                    &Final(wrong.final_values[0]),
                    |proof| verify_following(&baseline, &schema, value, &public, proof),
                    "FinalEvaluationMismatch".to_owned(),
                )
                .map_err(|e| format!("frame {frame}: {e:?}"))?;
            }
            continue;
        }
        if id == 312 || id == 610 {
            let variants: Vec<_> = if id == 312 {
                vec![Attack::WrongPlane]
            } else {
                (0..4)
                    .flat_map(|p| [Attack::SwapWeights(p), Attack::OmitWeight(p)])
                    .collect()
            };
            for attack in variants {
                let other = compose::<K>(
                    &schema,
                    acc,
                    acc,
                    &honest.advice,
                    value,
                    &public,
                    attack,
                    None,
                );
                let group = match attack {
                    Attack::WrongPlane => 2,
                    Attack::SwapWeights(p) | Attack::OmitWeight(p) => {
                        usize::from(p.saturating_sub(1))
                    }
                    _ => unreachable!("fixed source variants"),
                };
                let width = 4 * usize::from(<K as CodeField>::DEGREE);
                let from = other.group_offsets[group] + 1;
                let at = baseline.group_offsets[group] + 1;
                let row = Row {
                    at,
                    value: other.wire[from..from + width].to_vec(),
                };
                check_proof_control(
                    || Ok::<_, String>(baseline.wire.clone()),
                    &row,
                    |wire| {
                        verify_wire(&baseline, wire, &schema, value, &public)
                            .map(|_| ())
                            .map_err(|f| format!("{:?}", f.cause))
                    },
                    "Pcs(ValueMismatch)".to_owned(),
                )
                .map_err(|e| format!("{attack:?}: {e:?}"))?;
            }
            continue;
        }
        let hook = match id {
            308 => Change::Input(2147483647),
            310 => Change::Input(65537),
            311 => {
                let row = schema.values()[0].carry().start;
                Change::Byte(row, honest.advice[row] ^ 1)
            }
            309 => Change::Byte(0, honest.advice[0] ^ 1),
            313 => Change::Byte(0, 1),
            314 => Change::Byte(schema.allocated_rows(), 1),
            100 => Change::Byte(schema.values()[2].value().start, 0),
            101 => Change::Byte(schema.values()[4].value().start, 2),
            _ => return Err(format!("unsupported Requant control {id}")),
        };
        check_control(
            &honest,
            &hook,
            |w| {
                let dependent = match id {
                    308 if w.input_view != acc => Some(fixture("control-p-31.bin")),
                    310 if w.input_view != acc => Some(fixture("control-high-tail.bin")),
                    _ => None,
                };
                let advice = dependent.as_deref().unwrap_or(&w.advice);
                let attack = if w == &honest || id == 308 {
                    Attack::Honest
                } else {
                    Attack::ScalarFinals
                };
                Ok::<_, String>(compose::<K>(
                    &schema,
                    acc,
                    w.input_view,
                    advice,
                    value,
                    &public,
                    attack,
                    None,
                ))
            },
            |p| {
                verify_wire(
                    p,
                    if id == 309 { &baseline.wire } else { &p.wire },
                    &schema,
                    value,
                    &public,
                )
                .map(|_| ())
                .map_err(|f| format!("{:?}", f.cause))
            },
            match id {
                308 => "Pcs(ValueMismatch)",
                309 => "CertificateContext",
                _ => "Sumcheck(FinalEvaluationMismatch)",
            }
            .to_owned(),
        )
        .map_err(|e| format!("{name} NC{id:04}: {e:?}"))?;
    }
    if id == 314 {
        input_padding::<K>()?;
    }
    Ok(())
}

/// Run one scalar control in both canonical fields through the closed native verifier.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(id)?;
    check::<OM31>(id)
}
