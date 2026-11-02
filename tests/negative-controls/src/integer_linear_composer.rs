//! RFC-0024 §6: control-only composition through actual A5/A3/A1/A4/A9 engines.
//! The closed verifier never receives an attack, witness or transcript override.
use super::LIMITS;
use crate::matmul::composer as mm;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{CodeField, Functional, PreparedSource, ProofKind, VerifiedCertificate};
use stele_reductions::{integer_linear as linear, lookup, matmul, requant::EmbeddedSchema};
use stele_sumcheck::{zerocheck, Dense, Instance, Proof, Summand, Term};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Attack {
    Honest,
    // Statement, constraints, groups 0..2, original X/W OpeningColumns.
    OmitFrame(u8),
    ReplayResponses,
    SwapWeights(u8),
    OmitWeight(u8),
}
pub(super) struct Packet<K: ChallengeField> {
    pub wire: Vec<u8>,
    pub transcript: Transcript<K>,
    pub original_offsets: [usize; 2],
    pub group_offsets: [usize; 3],
    pub group_prefix: [HashUsage; 3],
}
fn weights<K: ChallengeField>(
    t: &mut Transcript<K>,
    phase: u8,
    count: usize,
    attack: Attack,
) -> Vec<K> {
    let mut values: Vec<_> = (0..count)
        .map(|index| {
            if attack == Attack::OmitWeight(phase) && index == 0 {
                K::from_i64(0)
            } else {
                t.challenge(ChallengeLabel::RequantWeight)
                    .expect("actual independent draw")
            }
        })
        .collect();
    if attack == Attack::SwapWeights(phase) {
        // The fixed scalar U endpoints differ; advice sign/v and output sign/q differ.
        values.swap(0, if phase == 1 { count - 1 } else { 1 });
    }
    values
}
fn fields<K: ChallengeField>(out: &mut Vec<u8>, values: &[K]) {
    for value in values {
        out.extend_from_slice(value.to_le_bytes().as_ref());
    }
}
fn arithmetic<K: ChallengeField>(out: &mut Vec<u8>, proof: &Proof<K>) {
    for round in &proof.rounds {
        fields(out, round);
    }
    fields(out, &proof.final_values);
}
fn absorb<K: ChallengeField>(
    t: &mut Transcript<K>,
    label: AbsorbLabel,
    phase: u8,
    bytes: &[u8],
    attack: Attack,
) {
    if attack != Attack::OmitFrame(phase) {
        t.absorb(label, bytes).expect("actual frame");
    }
}
struct Capture<'a, K> {
    dense: Dense<K>,
    point: &'a mut Vec<K>,
}
impl<K: ChallengeField> Summand<K> for Capture<'_, K> {
    fn shape(&self) -> (u32, usize) {
        self.dense.shape()
    }
    fn round(&self, instance: &Instance<K>) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.round(instance)
    }
    fn fold(&mut self, value: K) -> Result<(), stele_sumcheck::Error> {
        self.dense.fold(value)?;
        self.point.push(value);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, stele_sumcheck::Error> {
        self.dense.final_values()
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compose<K: ChallengeField + CodeField + lookup::TableField + Eq>(
    descriptor: &linear::Descriptor<'_, '_, K>,
    expected: &linear::Statement<'_, '_, K>,
    schema: &EmbeddedSchema,
    originals: [&PreparedSource<'_, K>; 2],
    advice: &PreparedSource<'_, K>,
    certificate: &VerifiedCertificate<K>,
    certificate_packet: &[u8],
    public: &[u8],
    attack: Attack,
    response_template: Option<&Packet<K>>,
) -> Packet<K>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    let base = u64::from(expected.stage) << 40;
    let [h, a, b, c] = expected.bits;
    let m = h + a + c;
    let n = 1usize << m;
    let mut t = Transcript::<K>::new(public).expect("actual transcript");
    let mut wire = vec![1, <K as CodeField>::DEGREE];
    wire.extend_from_slice(&advice.source().root());
    wire.extend_from_slice(certificate_packet);
    absorb(
        &mut t,
        AbsorbLabel::LinearStatement,
        0,
        &descriptor.encode().expect("statement"),
        attack,
    );
    let table = lookup::Table::range(8).expect("range8");
    let selector = vec![1; schema.rows() * n];
    let owners = [certificate];
    let layouts: Vec<_> = (0..expected.repetitions)
        .map(|j| lookup::Layout {
            id: base + 18 + u64::from(j),
            ell: 0,
            blowup: 1,
        })
        .collect();
    let total = m + schema.rows().ilog2() as u8;
    let lookup = lookup::Descriptor::new(
        lookup::Statement {
            id: base / 16 + 9,
            m: total,
            b: total,
            table: &table,
            selector: &selector,
            originals: &owners,
            multiplicities: &layouts,
        },
        LIMITS,
    )
    .expect("actual whole-cut A5");
    wire.extend(
        lookup
            .prove(
                &mut t,
                &[advice],
                lookup::ProducerLimits {
                    public_bytes: lookup.producer_public_bytes().expect("payload"),
                    dense_elements: lookup.producer_dense_elements().expect("dense"),
                },
            )
            .expect("actual A5 producer")
            .0,
    );
    absorb(
        &mut t,
        AbsorbLabel::RequantConstraints,
        1,
        &descriptor.encode_constraints().expect("constraints"),
        attack,
    );
    let constraints = schema
        .constraints::<K>()
        .expect("static embedded constraints");
    let mut terms = Vec::new();
    for (equation, weight) in constraints.equations().iter().zip(weights(
        &mut t,
        0,
        constraints.equations().len(),
        attack,
    )) {
        terms.extend(equation.iter().map(|term| Term {
            coefficient: weight * term.coefficient,
            factors: term.factors.clone(),
        }));
    }
    let aggregate = Instance {
        id: base + 1024,
        num_vars: u32::from(m),
        inputs: core::iter::once(base + (1 << 28))
            .chain((0..schema.rows()).map(|row| base + (1 << 24) + row as u64))
            .collect(),
        terms,
        claimed_sum: K::from_i64(0),
    };
    let tables: Vec<_> = core::iter::once(vec![K::from_i64(1); n])
        .chain(advice.message().chunks_exact(n).map(|row| {
            row.iter()
                .map(|v| K::from_i64(i64::from(v.as_u32())))
                .collect()
        }))
        .collect();
    let (zero, join_point) = zerocheck::Zerocheck {
        instance: &aggregate,
        skip: 0,
    }
    .prove_with_point(&tables, &mut t)
    .expect("actual A3");
    for round in &zero.rounds {
        fields(&mut wire, round);
    }
    fields(&mut wire, &zero.final_values);
    let mut power = K::from_i64(1);
    let mut join_value = K::from_i64(-(1i64 << 31));
    for value in &zero.final_values[1..5] {
        join_value = join_value + power * *value;
        power = power * K::from_i64(256);
    }
    let mut group_offsets = [0; 3];
    let mut group_prefix = [HashUsage::default(); 3];
    for group in 0..3 {
        let (rows, ids, values, point) = if group < 2 {
            let rows: Vec<_> = if group == 0 {
                (0..4).collect()
            } else {
                (4..schema.rows()).collect()
            };
            let ids = rows.iter().map(|row| aggregate.inputs[1 + row]).collect();
            let values = rows.iter().map(|row| zero.final_values[1 + row]).collect();
            (rows, ids, values, join_point.clone())
        } else {
            let rows: Vec<_> = core::iter::once(0)
                .chain(schema.semantic().values()[2].value())
                .map(|row| row + 4)
                .collect();
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
                id: base + 2048,
                num_vars: u32::from(m),
                inputs: core::iter::once(base + (1 << 28) + 1)
                    .chain(rows.iter().map(|row| aggregate.inputs[1 + row]))
                    .collect(),
                terms,
                claimed_sum: expected.value,
            };
            let output_tables = core::iter::once(mm::weights(expected.point))
                .chain(rows.iter().map(|row| tables[1 + row].clone()))
                .collect();
            let mut point = Vec::new();
            let proof = stele_sumcheck::prove(
                &instance,
                Capture {
                    dense: Dense::new(&instance, output_tables).expect("actual output tables"),
                    point: &mut point,
                },
                &mut t,
            )
            .expect("actual output A1");
            arithmetic(&mut wire, &proof);
            (
                rows,
                instance.inputs[1..].to_vec(),
                proof.final_values[1..].to_vec(),
                point,
            )
        };
        let mut frame = expected.stage.to_le_bytes().to_vec();
        frame.push(group);
        frame.extend_from_slice(&certificate.record().source().bytes());
        frame.extend_from_slice(&certificate.record().id());
        frame.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        frame.push(m);
        fields(&mut frame, &point);
        for ((row, id), value) in rows.iter().zip(&ids).zip(&values) {
            frame.extend_from_slice(&(*row as u32).to_le_bytes());
            frame.extend_from_slice(&id.to_le_bytes());
            fields(&mut frame, &[*value]);
        }
        absorb(
            &mut t,
            AbsorbLabel::RequantClaims,
            2 + group,
            &frame,
            attack,
        );
        let eta = weights(&mut t, group + 1, rows.len(), attack);
        let mut weights = vec![K::from_i64(0); schema.rows()];
        let mut value = K::from_i64(0);
        for ((row, claim), eta) in rows.iter().zip(&values).zip(eta) {
            weights[*row] = eta;
            value = value + eta * *claim;
        }
        group_offsets[usize::from(group)] = wire.len();
        group_prefix[usize::from(group)] = t.usage();
        wire.extend(
            advice
                .opening(
                    &mut t,
                    certificate,
                    Functional {
                        id: base + 3072 + u64::from(group),
                        a: &weights,
                        b: &mm::weights(&point),
                        value,
                    },
                )
                .expect("actual advice opening")
                .0,
        );
    }
    let certs = expected.originals.map(|range| range.original());
    let statement = matmul::Statement {
        id: base + (1 << 22),
        output_id: base + (1 << 21),
        coefficient_id: base + (1 << 28) + 2,
        inputs: certs.map(|c| c.record().source().descriptor().id),
        bits: expected.bits,
        point: &join_point,
        value: join_value,
    };
    let mut frame = vec![2, <K as CodeField>::DEGREE];
    for id in [statement.id, statement.output_id, statement.coefficient_id] {
        frame.extend_from_slice(&id.to_le_bytes());
    }
    frame.extend_from_slice(&[h, a, b, c]);
    fields(&mut frame, &join_point);
    fields(&mut frame, &[join_value]);
    for cert in certs {
        frame.extend_from_slice(&cert.record().source().bytes());
        frame.extend_from_slice(&cert.record().id());
    }
    t.absorb(AbsorbLabel::MatmulStatement, &frame)
        .expect("actual centered frame");
    let rows = mm::rows(&statement, originals, &join_point);
    let signed = rows.each_ref().map(|row| {
        row.iter()
            .map(|v| *v - K::from_i64(128))
            .collect::<Vec<_>>()
    });
    let (proof, point) = mm::with_kernel(&statement, |p| {
        let mut dense = p
            .strategy(&[&signed[0], &signed[1]])
            .expect("actual A4 strategy");
        let proof = dense.prove(&mut t).expect("actual A4 prover");
        (proof, dense.into_point().expect("actual A4 point"))
    });
    wire.push(1);
    arithmetic(&mut wire, &proof);
    let mut offsets = [0; 2];
    for side in 0..2 {
        let a = mm::weights(mm::outer(&statement, &join_point, side));
        let b = mm::weights(&point);
        let sum = |values: &[K]| values.iter().fold(K::from_i64(0), |s, v| s + *v);
        let functional = Functional {
            id: statement.inputs[side],
            a: &a,
            b: &b,
            value: proof.final_values[side] + K::from_i64(128) * sum(&a) * sum(&b),
        };
        offsets[side] = wire.len();
        if attack == Attack::ReplayResponses || attack == Attack::OmitFrame(5 + side as u8) {
            let template = response_template.expect("genuine original response template");
            let end = if side == 0 {
                template.original_offsets[1]
            } else {
                template.wire.len()
            };
            let bytes = &template.wire[template.original_offsets[side]..end];
            let parsed = certs[side]
                .record()
                .source()
                .parse(ProofKind::Opening, bytes)
                .expect("actual parser");
            let mut frame = functional.id.to_le_bytes().to_vec();
            frame.extend_from_slice(&certs[side].record().source().bytes());
            frame.extend_from_slice(&certs[side].record().id());
            fields(&mut frame, &a);
            fields(&mut frame, &b);
            fields(&mut frame, &[functional.value]);
            t.absorb(AbsorbLabel::Opening, &frame)
                .expect("actual frame");
            t.absorb(AbsorbLabel::OpeningRow, parsed.row_bytes())
                .expect("actual row");
            for _ in 0..certs[side].record().source().queries(ProofKind::Opening) {
                t.opening_column(certs[side].record().source().descriptor().count)
                    .expect("actual query");
            }
            absorb(
                &mut t,
                AbsorbLabel::OpeningColumns,
                5 + side as u8,
                parsed.response_bytes(),
                attack,
            );
            wire.extend_from_slice(bytes);
        } else {
            wire.extend(mm::untrusted_opening(
                &mut t,
                originals[side],
                certs[side],
                functional,
                &rows[side],
            ));
        }
    }
    descriptor
        .preflight(&wire)
        .expect("canonical complete wire");
    Packet {
        wire,
        transcript: t,
        original_offsets: offsets,
        group_offsets,
        group_prefix,
    }
}
