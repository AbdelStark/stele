//! RFC-0024: complete native composition, independent original range events.
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked;
use stele_hash::{ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};
use stele_reductions::{
    byte_range, integer_linear as linear, lookup,
    requant::{EmbeddedSchema, Format},
};

const LIMITS: lookup::Limits = lookup::Limits {
    positions: 1 << 16,
    public_bytes: 64 << 20,
    proof_bytes: 64 << 20,
};
const MATMUL: stacked::Limits = stacked::Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1 << 16,
    partial_entries: 1 << 16,
    axis_entries: 0,
};

fn check<K: ChallengeField + CodeField + lookup::TableField + Eq>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    for (bits, repetitions) in [([0, 0, 0, 0], 1), ([1, 1, 1, 1], 2)] {
        let [h, a, b, c] = bits;
        let [layers, rows, inner, columns] = bits.map(|n| 1usize << n);
        let size = layers * inner;
        let x: Vec<_> = (0..rows * size)
            .map(|i| M31::from_i64(125 + (i % 7) as i64))
            .collect();
        let w: Vec<_> = (0..columns * size)
            .map(|i| M31::from_i64(126 + (i % 5) as i64))
            .collect();
        let mut captured = Vec::new();
        for l in 0..layers {
            for i in 0..rows {
                for j in 0..columns {
                    captured.push(
                        (0..inner)
                            .map(|k| {
                                (x[i * size + l * inner + k].as_u32() as i32 - 128)
                                    * (w[j * size + l * inner + k].as_u32() as i32 - 128)
                            })
                            .sum(),
                    );
                }
            }
        }
        let px = PreparedSource::<K>::new(101, a, h + b, 1, &x, &mut HashUsage::default())
            .expect("valid fixed fixture");
        let pw = PreparedSource::<K>::new(102, c, h + b, 2, &w, &mut HashUsage::default())
            .expect("valid fixed fixture");
        let cx = verify_certificate(
            *px.source(),
            &px.certificate().expect("valid fixed fixture").0,
        )
        .expect("valid fixed fixture")
        .0;
        let cw = verify_certificate(
            *pw.source(),
            &pw.certificate().expect("valid fixed fixture").0,
        )
        .expect("valid fixed fixture")
        .0;
        let dx = byte_range::Descriptor::new(&cx, 9, &[111, 112][..repetitions], LIMITS)
            .expect("valid fixed fixture");
        let dw = byte_range::Descriptor::new(&cw, 10, &[121, 122][..repetitions], LIMITS)
            .expect("valid fixed fixture");
        let produce_range = |d: &byte_range::Descriptor<'_, K>, source: &PreparedSource<'_, K>| {
            d.prove(
                source,
                lookup::ProducerLimits {
                    public_bytes: d.producer_public_bytes().expect("valid fixed fixture"),
                    dense_elements: d.producer_dense_elements().expect("valid fixed fixture"),
                },
            )
            .expect("valid fixed fixture")
            .0
        };
        let rx = produce_range(&dx, &px);
        let rw = produce_range(&dw, &pw);
        let mx = dx
            .register_multiplicities(&rx, usize::MAX)
            .expect("valid fixed fixture")
            .0;
        let mw = dw
            .register_multiplicities(&rw, usize::MAX)
            .expect("valid fixed fixture")
            .0;
        let mxr: Vec<_> = mx.iter().collect();
        let mwr: Vec<_> = mw.iter().collect();
        let xr = dx.verify(&mxr, &rx).expect("valid fixed fixture");
        let wr = dw.verify(&mwr, &rw).expect("valid fixed fixture");
        let schema = EmbeddedSchema::new(b, 1, 1, Format::Int8).expect("valid fixed fixture");
        let witness = schema
            .witness(&captured, 1 << 16)
            .expect("valid fixed fixture");
        let stage = 31;
        let pa = PreparedSource::<K>::new(
            ((stage as u64) << 40) + 2,
            schema.rows().trailing_zeros() as u8,
            h + a + c,
            1,
            witness.advice(),
            &mut HashUsage::default(),
        )
        .expect("valid fixed fixture");
        let packet = pa.certificate().expect("valid fixed fixture").0;
        let ca = verify_certificate(*pa.source(), &packet)
            .expect("valid fixed fixture")
            .0;
        let point: Vec<_> = (0..h + a + c)
            .map(|i| K::from_i64(i64::from(i) + 2))
            .collect();
        let eq = stele_poly::eq_table(&point).expect("valid fixed fixture");
        let value = eq
            .iter()
            .zip(witness.output())
            .fold(K::from_i64(0), |s, (e, v)| {
                s + *e * K::from_i64(i64::from(*v))
            });
        let statement = linear::Statement {
            stage,
            bits,
            mantissa: 1,
            shift: 1,
            format: Format::Int8,
            repetitions: repetitions as u8,
            advice_blowup: 1,
            point: &point,
            value,
            originals: [&xr, &wr],
        };
        let descriptor =
            linear::Descriptor::new(statement, &ca, LIMITS, MATMUL).expect("valid fixed fixture");
        let transcript = || {
            Transcript::<K>::new(b"complete centered integer linear").expect("valid fixed fixture")
        };
        let mut pt = transcript();
        let (proof, produced) = descriptor
            .prove(
                &mut pt,
                [&px, &pw],
                &pa,
                &packet,
                linear::ProducerLimits {
                    public_bytes: descriptor
                        .producer_public_bytes()
                        .expect("valid fixed fixture"),
                    dense_elements: descriptor
                        .producer_dense_elements()
                        .expect("valid fixed fixture"),
                    retained_row_entries: descriptor.retained_row_entries(),
                },
            )
            .expect("valid fixed fixture");
        assert_eq!(proof.len(), descriptor.proof_size());
        let (mu, _) = descriptor
            .register_multiplicities(&proof, usize::MAX)
            .expect("valid fixed fixture");
        let refs: Vec<_> = mu.iter().collect();
        let mut vt = transcript();
        let (record, consumed) = descriptor
            .verify(&mut vt, &refs, &proof)
            .expect("valid fixed fixture");
        assert_eq!(produced.transcript, consumed.transcript);
        assert!(pt.challenge(ChallengeLabel::Sumcheck) == vt.challenge(ChallengeLabel::Sumcheck));
        assert_eq!(record.point_equality().numerator(), u64::from(h + a + c));
        assert_eq!(record.rlc().len(), 4);
        assert!(record.point_equality().point() == record.groups()[0].point());
        assert!(core::ptr::eq(record.originals()[0], &xr));
        assert!(core::ptr::eq(record.originals()[1], &wr));
        for group in record.groups() {
            assert!(core::ptr::eq(group.opening().certificate(), ca.record()));
        }
        // Static shape/policy/cap failures never acquire proof authority.
        for (s, limits, expected) in [
            (
                linear::Statement {
                    bits: [h, a, 16, c],
                    ..statement
                },
                LIMITS,
                linear::Error::Bounds(stele_cqis::bounds::Error::FieldBound),
            ),
            (
                linear::Statement {
                    repetitions: 3 - repetitions as u8,
                    ..statement
                },
                LIMITS,
                linear::Error::SourceRoster,
            ),
            (
                linear::Statement {
                    originals: [&xr, &xr],
                    ..statement
                },
                LIMITS,
                linear::Error::SourceRoster,
            ),
            (
                statement,
                lookup::Limits {
                    public_bytes: descriptor.public_bytes() - 1,
                    ..LIMITS
                },
                linear::Error::ResourceLimit,
            ),
            (
                statement,
                lookup::Limits {
                    proof_bytes: descriptor.proof_size() - 1,
                    ..LIMITS
                },
                linear::Error::ResourceLimit,
            ),
            (
                statement,
                lookup::Limits {
                    positions: (schema.rows() * captured.len() + x.len() + w.len() - 1) as u64,
                    ..LIMITS
                },
                linear::Error::ResourceLimit,
            ),
        ] {
            assert_eq!(
                linear::Descriptor::new(s, &ca, limits, MATMUL)
                    .err()
                    .expect("invalid expected statement"),
                expected
            );
        }
        let width = core::mem::size_of::<K>();
        let suffix = 1
            + width * (4 * usize::from(h + b) + 3)
            + px.source()
                .proof_size(ProofKind::Opening)
                .expect("X opening size")
            + pw.source()
                .proof_size(ProofKind::Opening)
                .expect("W opening size");
        let mut cases = Vec::new();
        cases.push((
            proof[..proof.len() - 1].to_vec(),
            linear::Error::ProofShape,
            0,
        ));
        for at in [0, 1] {
            let mut changed = proof.clone();
            changed[at] ^= 1;
            cases.push((changed, linear::Error::ProofShape, 0));
        }
        let mut changed = proof.clone();
        let at = proof.len() - suffix + 1;
        changed[at..at + 4].copy_from_slice(&M31::MODULUS.to_le_bytes());
        cases.push((changed, linear::Error::NoncanonicalField, 0));
        let mut changed = proof.clone();
        changed[2] ^= 1;
        cases.push((changed, linear::Error::CertificateContext, 0));
        let mut changed = proof.clone();
        changed[34 + packet.len() - 1] ^= 1;
        cases.push((changed, linear::Error::CertificateIdentity, 1));
        for (changed, expected, hashes) in cases {
            let mut t = transcript();
            let before = t.usage();
            let failure = descriptor
                .verify(&mut t, &refs, &changed)
                .err()
                .expect("preflight rejection");
            assert_eq!(failure.cause, expected);
            assert_eq!(failure.usage.transcript, before);
            assert_eq!(t.usage(), before);
            assert_eq!(failure.usage.non_transcript.hash_evaluations, hashes);
        }
    }
}
#[test]
fn accepts_qm31_integer_linear() {
    check::<QM31>();
}
#[test]
fn accepts_om31_integer_linear() {
    check::<OM31>();
}
