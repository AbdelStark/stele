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

/// Actual late producer A3/A1 failures, preserving full observed prefix work.
pub fn run_producer_failures() -> Result<(), String> {
    producer_failures::<QM31>()?;
    producer_failures::<OM31>()
}
fn producer_failures<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let schema = Schema::new(1, 0, Format::Int8).expect("fixed scalar schema");
    let honest = schema
        .witness(&[1], schema.rows() + 4)
        .expect("honest source bytes");
    let public = b"RFC0023/producer-failed-prefix/v1";
    for attack in [Attack::ScalarFinals, Attack::OutputFinals] {
        let mut bytes: Vec<_> = honest.advice().iter().map(|v| v.as_u32() as u8).collect();
        let value = if attack == Attack::OutputFinals { 2 } else { 1 };
        if attack == Attack::ScalarFinals {
            bytes[schema.values()[0].carry().start] ^= 1;
        }
        let packet = compose::<K>(&schema, 1, 1, &bytes, value, public, attack, None);
        let failed =
            verify(&packet, &schema, value, public).expect_err("actual closed consumer rejects");
        assert_eq!(
            failed.cause,
            stele_reductions::requant::Error::Sumcheck(
                stele_sumcheck::Error::FinalEvaluationMismatch
            )
        );
        let message: Vec<_> = bytes.iter().map(|v| M31::from_i64(i64::from(*v))).collect();
        let sources = [
            PreparedSource::<K>::new(73, 2, 0, 1, honest.input(), &mut HashUsage::default())
                .expect("input preparation"),
            PreparedSource::<K>::new(
                composer::BASE + 2,
                schema.rows().ilog2() as u8,
                0,
                1,
                &message,
                &mut HashUsage::default(),
            )
            .expect("advice preparation"),
        ];
        let advice_packet = sources[1].certificate().expect("genuine packet").0;
        let descriptor = Descriptor::new(
            Statement {
                stage: 31,
                n: 1,
                schema: &schema,
                repetitions: 1,
                advice_blowup: 1,
                point: &[],
                value: K::from_i64(value),
                input: &packet.input,
            },
            &packet.advice,
            LIMITS,
        )
        .expect("expected descriptor");
        let limits = stele_reductions::requant::ProducerLimits {
            public_bytes: descriptor.producer_public_bytes().expect("payload bound"),
            dense_elements: descriptor.producer_dense_elements().expect("dense bound"),
        };
        let mut t = Transcript::new(public).expect("fixed prefix");
        let f = descriptor
            .prove(&mut t, [&sources[0], &sources[1]], &advice_packet, limits)
            .expect_err("no partial producer wire");
        assert_eq!(f.cause, failed.cause);
        // Scalar A3 absorbs Zero then rejects; scalar A1 absorbs Instance then
        // rejects. Neither failing final frame is absorbed by the actual engine.
        let mut prefix = packet.transcript.usage();
        prefix.hash_evaluations += 1;
        prefix.state_updates += 1;
        assert_eq!(f.usage.transcript, prefix);
        assert_eq!(f.usage.transcript, t.usage());
        assert_eq!(f.usage.transcript, failed.usage.transcript);
        assert_eq!(
            f.usage.registrations,
            packet.producer_lookups.map(|u| u.registrations)
        );
        assert_eq!(
            f.usage.non_transcript,
            HashUsage {
                hash_evaluations: 1 + packet
                    .producer_lookups
                    .iter()
                    .map(|u| u.non_transcript.hash_evaluations)
                    .sum::<u64>(),
                ..HashUsage::default()
            }
        );
    }
    Ok(())
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/requant")
            .join(name),
    )
    .expect("pinned fixture file")
}

fn positive_target<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    for (bits, format) in [(8, Format::Int8), (16, Format::Int16)] {
        let schema = Schema::new(1, 0, format).expect("fixed target boundary");
        let h = 1i32 << (bits - 1);
        let baseline = schema
            .witness(&[h - 1], schema.rows() + 4)
            .expect("positive target endpoint");
        let honest = Witness {
            input_view: h - 1,
            advice: baseline.advice().iter().map(|v| v.as_u32() as u8).collect(),
        };
        let candidate = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("fixtures/requant-production/positive-h-{bits}.bin")),
        )
        .expect("independent positive-H candidate");
        // The sole nonzero arithmetic equation is target, at +1. Source finals
        // use the changed view; later source consumers are unreachable here.
        let row: Vec<K> = core::iter::once(K::from_i64(1))
            .chain(
                (i64::from(h) + (1 << 31)).to_le_bytes()[..4]
                    .iter()
                    .chain(&candidate)
                    .map(|v| K::from_i64(i64::from(*v))),
            )
            .collect();
        let residuals: Vec<_> = schema
            .constraints::<K>()
            .expect("closed constraints")
            .equations()
            .iter()
            .map(|terms| {
                terms.iter().fold(K::from_i64(0), |sum, t| {
                    sum + t
                        .factors
                        .iter()
                        .fold(t.coefficient, |v, f| v * row[*f as usize])
                })
            })
            .filter(|v| *v != K::from_i64(0))
            .collect();
        assert_eq!(residuals, [K::from_i64(1)]);
        let public = b"RFC0023/positive-target-boundary/v1";
        check_control(
            &honest,
            &Change::Input(h),
            |w| {
                let changed = w.input_view != h - 1;
                Ok::<_, String>(compose::<K>(
                    &schema,
                    h - 1,
                    w.input_view,
                    if changed { &candidate } else { &w.advice },
                    i64::from(h - 1),
                    public,
                    if changed {
                        Attack::ScalarFinals
                    } else {
                        Attack::Honest
                    },
                    None,
                ))
            },
            |p| {
                verify(p, &schema, i64::from(h - 1), public)
                    .map(|_| ())
                    .map_err(|f| format!("{:?}", f.cause))
            },
            "Sumcheck(FinalEvaluationMismatch)".to_owned(),
        )
        .map_err(|e| format!("positive H bits={bits}: {e:?}"))?;
    }
    Ok(())
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
    if id == 313 {
        positive_target::<K>()?;
    }
    Ok(())
}

/// Run one control in both canonical fields through the closed native verifier.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(id)?;
    check::<OM31>(id)
}

/// RFC-0023 §5: a zero result cannot make the public output Eq final unconstrained.
pub fn run_output_coefficient() -> Result<(), String> {
    fn check<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
    ) -> Result<(), String>
    where
        for<'b> K::Bytes: TryFrom<&'b [u8]>,
    {
        let schema = Schema::new(1, 0, Format::Int8).expect("fixed zero schema");
        let mut public = b"RFC0023/batched/independent-reference/v1/scalar".to_vec();
        public.push(<K as CodeField>::DEGREE);
        let baseline = compose::<K>(
            &schema,
            0,
            0,
            &fixture("control-zero-0.bin"),
            0,
            &public,
            Attack::Honest,
            None,
        );
        let width = 4 * usize::from(<K as CodeField>::DEGREE);
        let at = baseline.group_offsets[2] - width * (2 + schema.values()[2].value().len());
        assert_eq!(
            &baseline.wire[at..at + width],
            K::from_i64(1).to_le_bytes().as_ref()
        );
        // Only Eq changes. q=0 keeps the actual A1 final identity equal to zero;
        // the unchanged source prefix passes before the actual output A7 rejects.
        check_proof_control(
            || Ok::<_, String>(baseline.wire.clone()),
            &Row {
                at,
                value: K::from_i64(0).to_le_bytes().as_ref().to_vec(),
            },
            |wire| {
                verify_wire(&baseline, wire, &schema, 0, &public)
                    .map(|_| ())
                    .map_err(|f| f.cause)
            },
            stele_reductions::requant::Error::CoefficientMismatch,
        )
        .map_err(|e| format!("output equality: {e:?}"))
    }
    check::<QM31>()?;
    check::<OM31>()
}
