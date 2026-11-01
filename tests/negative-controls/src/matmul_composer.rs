//! Control-only untrusted matmul composer; RFC-0007 A2 / native-matmul §§2–4,7.
//! Never linked into production. It grants no source authority or pass-count credit.
use stele_field::{Field, M31};
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked,
};
use stele_hash::{AbsorbLabel, ChallengeField, HashUsage, Transcript};
use stele_pcs::{
    CodeField, Functional, PreparedSource, ProofKind, RetainedRow, VerifiedCertificate,
};
use stele_reductions::matmul::Statement;
use stele_sumcheck::{Proof, Term};

pub(super) const LIMITS: stacked::Limits = stacked::Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1024,
    partial_entries: 1024,
    axis_entries: 1024,
};
pub(super) fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"closed matmul native controls").expect("fixture transcript")
}
pub(super) fn certificate<K: ChallengeField + CodeField>(
    p: &PreparedSource<'_, K>,
) -> VerifiedCertificate<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bytes = p.certificate().expect("genuine certificate producer").0;
    stele_pcs::verify_certificate(*p.source(), &bytes)
        .expect("genuine certificate verification")
        .0
}
pub(super) fn weights<K: ChallengeField>(point: &[K]) -> Vec<K> {
    stele_poly::eq_table(point).expect("bounded fixture eq table")
}
pub(super) fn outer<'a, K>(s: &Statement<'_, K>, point: &'a [K], side: usize) -> &'a [K] {
    let [h, a, _, c] = s.bits.map(usize::from);
    if side == 0 {
        &point[h..h + a]
    } else {
        &point[h + a..h + a + c]
    }
}
pub(super) fn rows<K: ChallengeField>(
    s: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    point: &[K],
) -> [Vec<K>; 2] {
    core::array::from_fn(|i| {
        let a = weights(outer(s, point, i));
        RetainedRow::new(sources[i], &a)
            .expect("actual checked row")
            .values()
            .to_vec()
    })
}
pub(super) fn original_value<K: ChallengeField>(source: &PreparedSource<'_, K>, point: &[K]) -> K {
    let a = weights(point);
    assert_eq!(a.len(), source.message().len());
    source
        .message()
        .iter()
        .zip(a)
        .fold(K::from_i64(0), |sum, (v, a)| {
            sum + K::from_i64(i64::from(v.as_u32())) * a
        })
}
pub(super) fn statement<K>(bits: [u8; 4], point: &[K], value: K) -> Statement<'_, K> {
    Statement {
        id: 105,
        output_id: 103,
        coefficient_id: 104,
        inputs: [101, 102],
        bits,
        point,
        value,
    }
}
pub(super) fn sources<'a, K: ChallengeField>(
    bits: [u8; 4],
    messages: &'a [Vec<M31>; 2],
) -> [PreparedSource<'a, K>; 2] {
    let [h, a, b, c] = bits;
    [
        PreparedSource::new(101, a, h + b, 1, &messages[0], &mut HashUsage::default())
            .expect("X preparation"),
        PreparedSource::new(102, c, h + b, 2, &messages[1], &mut HashUsage::default())
            .expect("W preparation"),
    ]
}
// Source rows are outer i/j; columns are (layer,inner). Other factor is identically zero.
pub(super) fn fixture<K: ChallengeField>(bits: [u8; 4], side: usize) -> ([Vec<M31>; 2], Vec<K>) {
    let [h, a, b, c] = bits.map(usize::from);
    let messages = core::array::from_fn(|source| {
        (0..1usize << if source == 0 { a } else { c })
            .flat_map(|row| {
                (0..1usize << (h + b)).map(move |column| {
                    let layer = column >> b;
                    let inner = column & ((1 << b) - 1);
                    let value = if source != side {
                        0
                    } else if h + b == 0 {
                        row
                    } else {
                        row * 13 + layer * 5 + inner * 7 + layer * inner * 3
                    };
                    M31::from_i64(value as i64)
                })
            })
            .collect()
    });
    let point = (0..h + a + c).map(|i| K::from_i64(2 + i as i64)).collect();
    (messages, point)
}
fn append<K: ChallengeField>(out: &mut Vec<u8>, values: &[K]) {
    for value in values {
        out.extend_from_slice(value.to_le_bytes().as_ref());
    }
}
pub(super) fn bind<K: ChallengeField>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    certs: [&VerifiedCertificate<K>; 2],
) {
    let mut bytes = vec![1, K::DEGREE as u8];
    for id in [s.id, s.output_id, s.coefficient_id] {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes.extend_from_slice(&s.bits);
    append(&mut bytes, s.point);
    append(&mut bytes, &[s.value]);
    for c in certs {
        bytes.extend_from_slice(&c.record().source().bytes());
        bytes.extend_from_slice(&c.record().id());
    }
    assert_eq!(bytes.len(), 304 + 4 * K::DEGREE * (s.point.len() + 1));
    t.absorb(AbsorbLabel::MatmulStatement, &bytes)
        .expect("real new label");
}
fn with_kernel<K: ChallengeField + Eq, T>(
    s: &Statement<'_, K>,
    f: impl FnOnce(&stacked::Prepared<'_, K>) -> T,
) -> T {
    let [h, a, b, c] = s.bits;
    let axis = |bits| Axis {
        bits,
        real: 1u64 << bits,
    };
    let axes = [axis(h), axis(b)];
    let outputs = [axis(h), axis(a), axis(c)];
    let terms = [Term {
        coefficient: K::from_i64(1),
        factors: vec![0, 1],
    }];
    let selectors = [Some(&s.point[..usize::from(h)]), None];
    let inner = stacked::Statement {
        id: s.id,
        axes: &axes,
        order: stacked::Order::LayerFirst,
        output: stacked::Claim {
            id: s.output_id,
            axes: &outputs,
            point: s.point,
            value: s.value,
        },
        coefficient_id: s.coefficient_id,
        inputs: &s.inputs,
        terms: &terms,
        selectors: &selectors,
        kind: Kind::Eq,
        source_id: None,
    };
    let prepared =
        stacked::Prepared::for_certified_sources(&inner, LIMITS).expect("actual A4 preparation");
    f(&prepared)
}
pub(super) fn kernel<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    proof: &Proof<K>,
) -> Vec<K> {
    with_kernel(s, |p| {
        p.verify_reduction(t, proof)
            .expect("actual A1 and A7 must pass")
            .0
            .point
    })
}
pub(super) fn a1_only<K: ChallengeField + Eq>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    proof: &Proof<K>,
) {
    with_kernel(s, |p| {
        t.absorb(AbsorbLabel::Stack, p.bytes())
            .expect("actual Stack absorb");
        let _ = stele_sumcheck::verify(p.instance(), proof, t)
            .expect("actual A1 must pass before A7 rejects");
    });
}
fn opening_frame<K: ChallengeField>(
    t: &mut Transcript<K>,
    c: &VerifiedCertificate<K>,
    f: Functional<'_, K>,
) {
    let mut bytes = f.id.to_le_bytes().to_vec();
    bytes.extend_from_slice(&c.record().source().bytes());
    bytes.extend_from_slice(&c.record().id());
    append(&mut bytes, f.a);
    append(&mut bytes, f.b);
    append(&mut bytes, &[f.value]);
    t.absorb(AbsorbLabel::Opening, &bytes)
        .expect("actual Opening absorb");
}
// Only the control producer accepts arbitrary u or a different response owner.
// Every query and path is generated by production Transcript/PreparedSource.
fn untrusted_opening<K: ChallengeField>(
    t: &mut Transcript<K>,
    owner: &PreparedSource<'_, K>,
    c: &VerifiedCertificate<K>,
    f: Functional<'_, K>,
    row: &[K],
) -> Vec<u8> {
    assert_eq!(row.len(), c.record().source().columns());
    assert_eq!(
        owner.source().descriptor().count,
        c.record().source().descriptor().count
    );
    opening_frame(t, c, f);
    let mut proof = vec![1];
    append(&mut proof, row);
    t.absorb(AbsorbLabel::OpeningRow, &proof[1..])
        .expect("actual row absorb");
    let start = proof.len();
    for _ in 0..c.record().source().queries(ProofKind::Opening) {
        let index = t
            .opening_column(c.record().source().descriptor().count)
            .expect("actual sampler");
        let response = owner.response(index).expect("genuine path producer");
        proof.extend_from_slice(response.payload);
        for sibling in response.siblings {
            proof.extend_from_slice(&sibling);
        }
    }
    t.absorb(AbsorbLabel::OpeningColumns, &proof[start..])
        .expect("actual response absorb");
    proof
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Artifact<K> {
    pub proof: Proof<K>,
    pub openings: [Vec<u8>; 2],
    pub point: Vec<K>,
}
impl<K: ChallengeField> Artifact<K> {
    pub fn wire(&self) -> Vec<u8> {
        let mut wire = vec![1];
        for round in &self.proof.rounds {
            append(&mut wire, round);
        }
        append(&mut wire, &self.proof.final_values);
        for opening in &self.openings {
            wire.extend_from_slice(opening);
        }
        wire
    }
}
fn finish<K: ChallengeField>(
    t: &mut Transcript<K>,
    s: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    certs: [&VerifiedCertificate<K>; 2],
    rows: &[Vec<K>; 2],
    proof: Proof<K>,
    point: Vec<K>,
) -> Artifact<K> {
    let b = weights(&point);
    let openings = core::array::from_fn(|i| {
        let a = weights(outer(s, s.point, i));
        untrusted_opening(
            t,
            sources[i],
            certs[i],
            Functional {
                id: s.inputs[i],
                a: &a,
                b: &b,
                value: proof.final_values[i],
            },
            &rows[i],
        )
    });
    Artifact {
        proof,
        openings,
        point,
    }
}
pub(super) fn produce<K: ChallengeField + Eq>(
    s: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    certs: [&VerifiedCertificate<K>; 2],
    rows: &[Vec<K>; 2],
) -> (Artifact<K>, Transcript<K>) {
    let mut t = transcript();
    bind(&mut t, s, certs);
    let (proof, point) = with_kernel(s, |p| {
        let mut dense = p
            .strategy(&[&rows[0], &rows[1]])
            .expect("actual dense strategy");
        let proof = dense.prove(&mut t).expect("actual A4 producer");
        (proof, dense.into_point().expect("actual captured point"))
    });
    (finish(&mut t, s, sources, certs, rows, proof, point), t)
}
// Independently anchor every baseline serializer to the actual ordinary A9 producer.
// Its extra source scans are control setup, never a retained-producer pass claim.
pub(super) fn honest<K: ChallengeField + Eq>(
    s: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    certs: [&VerifiedCertificate<K>; 2],
    rows: &[Vec<K>; 2],
) -> Artifact<K> {
    let (artifact, untrusted) = produce(s, sources, certs, rows);
    let mut ordinary = transcript();
    bind(&mut ordinary, s, certs);
    let point = kernel(&mut ordinary, s, &artifact.proof);
    let b = weights(&point);
    for i in 0..2 {
        let a = weights(outer(s, s.point, i));
        let (wire, _) = sources[i]
            .opening(
                &mut ordinary,
                certs[i],
                Functional {
                    id: s.inputs[i],
                    a: &a,
                    b: &b,
                    value: artifact.proof.final_values[i],
                },
            )
            .expect("actual ordinary A9 baseline producer");
        assert_eq!(wire, artifact.openings[i]);
    }
    assert_eq!(ordinary.usage(), untrusted.usage());
    artifact
}
pub(super) fn rebuild<K: ChallengeField + Eq>(
    s: &Statement<'_, K>,
    sources: [&PreparedSource<'_, K>; 2],
    certs: [&VerifiedCertificate<K>; 2],
    rows: &[Vec<K>; 2],
    proof: &Proof<K>,
) -> Artifact<K> {
    let mut t = transcript();
    bind(&mut t, s, certs);
    let point = kernel(&mut t, s, proof);
    finish(&mut t, s, sources, certs, rows, proof.clone(), point)
}
// Independently authenticate the complete preceding original before targeting W.
pub(super) fn prefix<K: ChallengeField + CodeField + Eq>(
    s: &Statement<'_, K>,
    certs: [&VerifiedCertificate<K>; 2],
    artifact: &Artifact<K>,
    side: usize,
) -> (Transcript<K>, HashUsage)
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut t = transcript();
    bind(&mut t, s, certs);
    let point = kernel(&mut t, s, &artifact.proof);
    assert!(point == artifact.point);
    let mut hashes = HashUsage::default();
    if side == 1 {
        let a = weights(outer(s, s.point, 0));
        let b = weights(&point);
        hashes = stele_pcs::verify_opening(
            &mut t,
            certs[0],
            Functional {
                id: s.inputs[0],
                a: &a,
                b: &b,
                value: artifact.proof.final_values[0],
            },
            &artifact.openings[0],
        )
        .expect("preceding actual X consumer must pass")
        .1
        .non_transcript;
    }
    (t, hashes)
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Omit {
    Nothing,
    Statement,
    Responses(usize),
}
// Control-prover replay of a fixed scalar closed artifact: one absent absorb.
// Does not authenticate the stale replay or alter the honest artifact given to verify.
pub(super) fn omitted<K: ChallengeField + Eq>(
    s: &Statement<'_, K>,
    certs: [&VerifiedCertificate<K>; 2],
    artifact: &Artifact<K>,
    omit: Omit,
) -> Transcript<K> {
    assert!(artifact.proof.rounds.is_empty());
    let mut t = transcript();
    if !matches!(omit, Omit::Statement) {
        bind(&mut t, s, certs);
    }
    let point = kernel(&mut t, s, &artifact.proof);
    let b = weights(&point);
    for (i, c) in certs.into_iter().enumerate() {
        let a = weights(outer(s, s.point, i));
        opening_frame(
            &mut t,
            c,
            Functional {
                id: s.inputs[i],
                a: &a,
                b: &b,
                value: artifact.proof.final_values[i],
            },
        );
        let wire = c
            .record()
            .source()
            .parse(ProofKind::Opening, &artifact.openings[i])
            .expect("complete original wire");
        t.absorb(AbsorbLabel::OpeningRow, wire.row_bytes())
            .expect("original row absorb");
        for _ in 0..c.record().source().queries(ProofKind::Opening) {
            t.opening_column(c.record().source().descriptor().count)
                .expect("actual sampler");
        }
        if !matches!(omit, Omit::Responses(j) if j == i) {
            t.absorb(AbsorbLabel::OpeningColumns, wire.response_bytes())
                .expect("original response absorb");
        }
    }
    t
}
