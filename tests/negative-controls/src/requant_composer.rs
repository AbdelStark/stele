//! RFC-0023 §6: scalar adversarial producer; every consumer stays unchanged.
//! This separate control binary composes actual A5/A3/A1/A9 engines at m=0.
use stele_field::{Field, M31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{
    verify_certificate, CodeField, Functional, PreparedSource, ProofKind, VerifiedCertificate,
};
use stele_reductions::{
    lookup,
    requant::{self, Descriptor, Limits, Schema, Statement},
};
use stele_sumcheck::{zerocheck, Dense, Instance, Proof, Term};

pub(super) const BASE: u64 = 31u64 << 40;
pub(super) const LIMITS: Limits = Limits {
    positions: 4096,
    public_bytes: 32_000_000,
    proof_bytes: 32_000_000,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Attack {
    Honest,
    OmitFrame(u8), // Statement, Constraints, three Claims, final A9 responses.
    ReplayResponses,
    SwapWeights(u8),
    OmitWeight(u8),
    WrongPlane,
    ScalarFinals, // Untrusted false A3 packet, never an accepting verifier hook.
}
pub(super) struct Packet<K: ChallengeField> {
    pub wire: Vec<u8>,
    pub input: VerifiedCertificate<K>,
    pub advice: VerifiedCertificate<K>,
    pub transcript: Transcript<K>,
    pub group_offsets: [usize; 3],
}
fn fields<K: ChallengeField>(out: &mut Vec<u8>, values: &[K]) {
    for value in values {
        out.extend_from_slice(value.to_le_bytes().as_ref());
    }
}
fn input(accumulator: i32) -> Vec<M31> {
    (i64::from(accumulator) + (1 << 31)).to_le_bytes()[..4]
        .iter()
        .map(|b| M31::from_i64(i64::from(*b)))
        .collect()
}
fn weights<K: ChallengeField>(
    t: &mut Transcript<K>,
    phase: u8,
    n: usize,
    attack: Attack,
) -> Vec<K> {
    let mut weights: Vec<_> = (0..n)
        .map(|i| {
            if attack == Attack::OmitWeight(phase) && i == 0 {
                K::from_i64(0)
            } else {
                t.challenge(ChallengeLabel::RequantWeight)
                    .expect("actual independent draw")
            }
        })
        .collect();
    if attack == Attack::SwapWeights(phase) {
        // Input's first/last bytes differ; advice sign/v and output sign/q differ.
        let other = if phase == 1 { n - 1 } else { 1 };
        weights.swap(0, other);
    }
    weights
}
fn absorb<K: ChallengeField>(
    t: &mut Transcript<K>,
    label: AbsorbLabel,
    phase: u8,
    raw: &[u8],
    attack: Attack,
) {
    if attack != Attack::OmitFrame(phase) {
        t.absorb(label, raw).expect("actual frame");
    }
}
fn empty_opening<K: ChallengeField>(source: &stele_pcs::Source<K>) -> Vec<u8> {
    let mut packet = vec![0; source.proof_size(ProofKind::Opening).expect("fixed shape")];
    packet[0] = 1;
    packet
}
pub(super) fn following<K: ChallengeField + Eq>(t: &mut Transcript<K>) -> Proof<K> {
    let instance = next();
    let dense = Dense::new(&instance, vec![vec![K::from_i64(1), K::from_i64(2)]])
        .expect("following tables");
    stele_sumcheck::prove(&instance, dense, t).expect("actual following A1")
}
pub(super) fn next<K: ChallengeField>() -> Instance<K> {
    Instance {
        id: BASE + (1 << 29),
        num_vars: 1,
        inputs: vec![BASE + (1 << 29) + 1],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0],
        }],
        claimed_sum: K::from_i64(3),
    }
}

// All witness/view arguments are producer inputs only. verify() below receives
// genuine certificates, bytes and independently expected public parameters.
#[allow(clippy::too_many_arguments)]
pub(super) fn compose<K: ChallengeField + CodeField + lookup::TableField + Eq + core::fmt::Debug>(
    schema: &Schema,
    expected_input: i32,
    input_view: i32,
    advice_bytes: &[u8],
    value: i64,
    public: &[u8],
    attack: Attack,
    response_template: Option<&[u8]>,
) -> Packet<K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    assert_eq!(advice_bytes.len(), schema.rows());
    let original = input(expected_input);
    let logical = input(input_view);
    let advice_values: Vec<M31> = advice_bytes
        .iter()
        .map(|v| M31::from_i64(i64::from(*v)))
        .collect();
    let sources = [
        PreparedSource::<K>::new(73, 2, 0, 1, &original, &mut HashUsage::default())
            .expect("actual input preparation"),
        PreparedSource::<K>::new(
            BASE + 2,
            schema.rows().ilog2() as u8,
            0,
            1,
            &advice_values,
            &mut HashUsage::default(),
        )
        .expect("actual advice preparation"),
    ];
    let input_packet = sources[0]
        .certificate()
        .expect("actual input certificate")
        .0;
    let advice_packet = sources[1]
        .certificate()
        .expect("actual advice certificate")
        .0;
    let input = verify_certificate(*sources[0].source(), &input_packet)
        .expect("genuine input")
        .0;
    let advice = verify_certificate(*sources[1].source(), &advice_packet)
        .expect("genuine advice")
        .0;
    let d = Descriptor::new(
        Statement {
            stage: 31,
            n: 1,
            schema,
            repetitions: 1,
            advice_blowup: 1,
            point: &[],
            value: K::from_i64(value),
            input: &input,
        },
        &advice,
        LIMITS,
    )
    .expect("fixed scalar descriptor");
    let mut t = Transcript::new(public).expect("public prefix");
    absorb(
        &mut t,
        AbsorbLabel::RequantStatement,
        0,
        &d.encode().expect("statement"),
        attack,
    );
    let mut wire = vec![1, <K as CodeField>::DEGREE];
    wire.extend_from_slice(&advice.record().source().root());
    wire.extend_from_slice(&advice_packet);
    let table = lookup::Table::range(8).expect("actual range8 table");
    for (b, certificate) in [&input, &advice].into_iter().enumerate() {
        let m = certificate.record().source().rows().ilog2() as u8;
        let originals = [certificate];
        let selector = vec![1; 1 << m];
        let layouts = [lookup::Layout {
            id: BASE + 16 + 2 * b as u64,
            ell: 0,
            blowup: 1,
        }];
        let lookup = lookup::Descriptor::new(
            lookup::Statement {
                id: BASE / 16 + 8 + b as u64,
                m,
                b: m,
                table: &table,
                selector: &selector,
                originals: &originals,
                multiplicities: &layouts,
            },
            LIMITS,
        )
        .expect("actual A5 descriptor");
        let limits = lookup::ProducerLimits {
            public_bytes: lookup.producer_public_bytes().expect("payload bound"),
            dense_elements: lookup.producer_dense_elements().expect("dense bound"),
        };
        wire.extend(
            lookup
                .prove(&mut t, &[&sources[b]], limits)
                .expect("actual complete A5 producer")
                .0,
        );
    }
    let constraints = schema.constraints::<K>().expect("static constraints");
    absorb(
        &mut t,
        AbsorbLabel::RequantConstraints,
        1,
        &d.encode_constraints().expect("constraints"),
        attack,
    );
    let gamma = weights(&mut t, 0, constraints.equations().len(), attack);
    let terms = constraints
        .equations()
        .iter()
        .zip(gamma)
        .flat_map(|(terms, g)| {
            terms.iter().map(move |term| Term {
                coefficient: g * term.coefficient,
                factors: term.factors.clone(),
            })
        })
        .collect();
    let ids: Vec<_> = core::iter::once(BASE + (1 << 28))
        .chain((0..4 + schema.rows()).map(|i| BASE + (1 << 24) + i as u64))
        .collect();
    let aggregate = Instance {
        id: BASE + 1024,
        num_vars: 0,
        inputs: ids,
        terms,
        claimed_sum: K::from_i64(0),
    };
    let values: Vec<K> = core::iter::once(K::from_i64(1))
        .chain(
            logical
                .iter()
                .chain(&advice_values)
                .map(|v| K::from_i64(i64::from(v.as_u32()))),
        )
        .collect();
    if attack == Attack::ScalarFinals {
        // Deliberately untrusted m=0 finals. The actual A3 verifier must reject;
        // suffixes are shape-canonical, unreachable packets, not accepting proofs.
        fields(&mut wire, &values);
        wire.extend(empty_opening(sources[0].source()));
        wire.extend(empty_opening(sources[1].source()));
        fields(
            &mut wire,
            &vec![K::from_i64(0); 2 + schema.values()[2].value().len()],
        );
        wire.extend(empty_opening(sources[1].source()));
        d.preflight(&wire).expect("complete canonical false wire");
        return Packet {
            wire,
            input,
            advice,
            transcript: t,
            group_offsets: [0; 3],
        };
    }
    let tables: Vec<_> = values.iter().map(|v| vec![*v]).collect();
    let zero = zerocheck::Zerocheck {
        instance: &aggregate,
        skip: 0,
    }
    .prove(&tables, &mut t)
    .expect("actual scalar A3");
    assert!(zero.rounds.is_empty() && zero.skip_values.is_empty());
    fields(&mut wire, &zero.final_values);
    let mut offsets = [0; 3];
    for group in 0..3 {
        let (rows, ids, claims) = if group < 2 {
            let (start, count) = if group == 0 {
                (1, 4)
            } else {
                (5, schema.rows())
            };
            (
                (0..count).collect::<Vec<_>>(),
                aggregate.inputs[start..start + count].to_vec(),
                zero.final_values[start..start + count].to_vec(),
            )
        } else {
            let rows: Vec<_> = core::iter::once(0)
                .chain(schema.values()[2].value())
                .collect();
            let mut ids = vec![BASE + (1 << 28) + 1];
            ids.extend(rows.iter().map(|row| BASE + (1 << 24) + 4 + *row as u64));
            let mut terms = Vec::new();
            let mut power = K::from_i64(1);
            for k in 0..rows.len() - 1 {
                terms.push(Term {
                    coefficient: power,
                    factors: vec![0, 2 + k as u32],
                });
                terms.push(Term {
                    coefficient: K::from_i64(-2) * power,
                    factors: vec![0, 1, 2 + k as u32],
                });
                power = power * K::from_i64(256);
            }
            let instance = Instance {
                id: BASE + 2048,
                num_vars: 0,
                inputs: ids,
                terms,
                claimed_sum: K::from_i64(value),
            };
            let tables: Vec<_> = core::iter::once(vec![K::from_i64(1)])
                .chain(
                    rows.iter()
                        .map(|r| vec![K::from_i64(i64::from(advice_bytes[*r]))]),
                )
                .collect();
            let proof = stele_sumcheck::prove(
                &instance,
                Dense::new(&instance, tables).expect("output tables"),
                &mut t,
            )
            .expect("actual output A1");
            fields(&mut wire, &proof.final_values);
            (
                rows,
                instance.inputs[1..].to_vec(),
                proof.final_values[1..].to_vec(),
            )
        };
        let b = usize::from(group != 0);
        let certificate = if b == 0 { &input } else { &advice };
        let mut frame = 31u32.to_le_bytes().to_vec();
        frame.push(group as u8);
        frame.extend_from_slice(&certificate.record().source().bytes());
        frame.extend_from_slice(&certificate.record().id());
        frame.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        frame.push(0);
        for ((row, id), claim) in rows.iter().zip(&ids).zip(&claims) {
            frame.extend_from_slice(&(*row as u32).to_le_bytes());
            frame.extend_from_slice(&id.to_le_bytes());
            fields(&mut frame, &[*claim]);
        }
        absorb(
            &mut t,
            AbsorbLabel::RequantClaims,
            2 + group as u8,
            &frame,
            attack,
        );
        let eta = weights(&mut t, 1 + group as u8, rows.len(), attack);
        let mut a = vec![K::from_i64(0); certificate.record().source().rows()];
        for (i, (row, weight)) in rows.iter().zip(&eta).enumerate() {
            let actual = if attack == Attack::WrongPlane && group == 2 && i == 0 {
                schema.values()[0].value().start
            } else {
                *row
            };
            a[actual] = *weight;
        }
        let message = if b == 0 { &original } else { &advice_values };
        let actual = a.iter().zip(message).fold(K::from_i64(0), |s, (a, v)| {
            s + *a * K::from_i64(i64::from(v.as_u32()))
        });
        let claimed = eta
            .iter()
            .zip(&claims)
            .fold(K::from_i64(0), |s, (a, v)| s + *a * *v);
        if (group == 0 && expected_input != input_view)
            || (group == 2 && attack == Attack::WrongPlane)
        {
            assert_ne!(
                actual, claimed,
                "the one substituted source/plane must change this fixed scalar; never retry"
            );
        }
        let one = [K::from_i64(1)];
        let functional = Functional {
            id: BASE + 3072 + group as u64,
            a: &a,
            b: &one,
            value: actual,
        };
        offsets[group] = wire.len();
        if group == 2 && matches!(attack, Attack::OmitFrame(5) | Attack::ReplayResponses) {
            // Actual A9 transcript operations, as the existing NC0802 composer.
            // The no-omission replay must match the real producer byte for byte.
            let packet = response_template.expect("genuine baseline response template");
            let parsed = certificate
                .record()
                .source()
                .parse(ProofKind::Opening, packet)
                .expect("actual A9 parser");
            let mut frame = functional.id.to_le_bytes().to_vec();
            frame.extend_from_slice(&certificate.record().source().bytes());
            frame.extend_from_slice(&certificate.record().id());
            fields(&mut frame, &a);
            fields(&mut frame, &one);
            fields(&mut frame, &[actual]);
            t.absorb(AbsorbLabel::Opening, &frame)
                .expect("actual opening frame");
            t.absorb(AbsorbLabel::OpeningRow, parsed.row_bytes())
                .expect("actual opening row");
            for _ in 0..certificate.record().source().queries(ProofKind::Opening) {
                t.opening_column(certificate.record().source().code().codeword_len() as u64)
                    .expect("actual query draw");
            }
            if attack == Attack::ReplayResponses {
                t.absorb(AbsorbLabel::OpeningColumns, parsed.response_bytes())
                    .expect("actual response frame");
            }
            wire.extend_from_slice(packet);
        } else {
            wire.extend(
                sources[b]
                    .opening(&mut t, certificate, functional)
                    .expect("actual A9 producer")
                    .0,
            );
        }
        if group == 0 && expected_input != input_view {
            // Source authority control: the real input opening must reject its
            // false claimed scalar. Do not claim unreachable output acceptance.
            wire.extend(empty_opening(sources[1].source()));
            fields(
                &mut wire,
                &vec![K::from_i64(0); 2 + schema.values()[2].value().len()],
            );
            wire.extend(empty_opening(sources[1].source()));
            d.preflight(&wire)
                .expect("canonical unreachable source-control suffix");
            return Packet {
                wire,
                input,
                advice,
                transcript: t,
                group_offsets: offsets,
            };
        }
    }
    d.preflight(&wire).expect("full canonical scalar wire");
    Packet {
        wire,
        input,
        advice,
        transcript: t,
        group_offsets: offsets,
    }
}

pub(super) fn verify<K: ChallengeField + CodeField + lookup::TableField + Eq>(
    packet: &Packet<K>,
    schema: &Schema,
    value: i64,
    public: &[u8],
) -> Result<stele_pcs::Usage, requant::Failure>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    verify_wire(packet, &packet.wire, schema, value, public)
}
pub(super) fn verify_wire<K: ChallengeField + CodeField + lookup::TableField + Eq>(
    packet: &Packet<K>,
    wire: &[u8],
    schema: &Schema,
    value: i64,
    public: &[u8],
) -> Result<stele_pcs::Usage, requant::Failure>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let d = Descriptor::new(
        Statement {
            stage: 31,
            n: 1,
            schema,
            repetitions: 1,
            advice_blowup: 1,
            point: &[],
            value: K::from_i64(value),
            input: &packet.input,
        },
        &packet.advice,
        LIMITS,
    )
    .expect("expected scalar statement");
    let (mu, _) = d
        .register_multiplicities(wire, 32_000_000)
        .expect("actual standalone imports");
    let refs = mu.each_ref().map(|v| v.iter().collect::<Vec<_>>());
    let mut t = Transcript::new(public).expect("independent expected public prefix");
    d.verify(&mut t, [&refs[0], &refs[1]], wire)
        .map(|(_, usage)| usage)
}
