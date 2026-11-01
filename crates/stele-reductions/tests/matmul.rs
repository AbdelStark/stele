//! RFC-0007 A2 / formal/native-matmul §§1,3,6: reject before transcript mutation.
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked::Limits;
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};
use stele_reductions::matmul::{self, Error, Statement};

fn preflight<K: ChallengeField + CodeField + Eq>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = [M31::from_i64(1)];
    let x = PreparedSource::<K>::new(101, 0, 0, 1, &message, &mut HashUsage::default())
        .expect("X preparation");
    let w = PreparedSource::<K>::new(102, 0, 0, 2, &message, &mut HashUsage::default())
        .expect("W preparation");
    let xc = verify_certificate(*x.source(), &x.certificate().expect("X proof").0)
        .expect("X certificate")
        .0;
    let wc = verify_certificate(*w.source(), &w.certificate().expect("W proof").0)
        .expect("W certificate")
        .0;
    let statement = Statement {
        id: 105,
        output_id: 103,
        coefficient_id: 104,
        inputs: [101, 102],
        bits: [0, 0, 0, 0],
        point: &[],
        value: K::from_i64(1),
    };
    let limits = Limits {
        descriptor_bytes: 1 << 20,
        proof_bytes: 1 << 20,
        prepared_entries: 1 << 10,
        partial_entries: 1 << 10,
        // Eq evaluates selected coordinates directly and requests no A7 axis tables.
        axis_entries: 0,
    };
    let point = [K::from_i64(2)];
    for (expected, cause) in [
        (
            Statement {
                output_id: 104,
                ..statement
            },
            Error::InvalidMatmul,
        ),
        (
            Statement {
                inputs: [101, 101],
                ..statement
            },
            Error::InvalidMatmul,
        ),
        (
            Statement {
                bits: [u8::MAX, 0, 0, 0],
                ..statement
            },
            Error::InvalidMatmul,
        ),
        (
            Statement {
                point: &point,
                ..statement
            },
            Error::InvalidMatmul,
        ),
        (
            Statement {
                inputs: [102, 101],
                ..statement
            },
            Error::SourceRoster,
        ),
        (
            Statement {
                bits: [0, 1, 0, 0],
                point: &point,
                ..statement
            },
            Error::SourceRoster,
        ),
    ] {
        let mut t = Transcript::<K>::new(b"matmul preflight").expect("transcript");
        let before = t.usage();
        let failure = matmul::verify(&mut t, &expected, [&xc, &wc], &[], limits)
            .err()
            .expect("expected context rejection");
        assert_eq!(failure.cause, cause);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
        assert_eq!(t.usage(), before);
    }
    // Static maximum geometry is distinguished from a mismatched actual source;
    // no enormous matrix or fabricated VerifiedCertificate is constructed.
    for (bits, cause) in [
        ([29, 30, 0, 4], Error::SourceRoster),
        ([29, 30, 0, 5], Error::InvalidMatmul),
        ([30, 0, 0, 0], Error::InvalidMatmul),
        ([0, 31, 0, 0], Error::InvalidMatmul),
        ([0, 0, 0, 31], Error::InvalidMatmul),
    ] {
        let point = vec![K::from_i64(2); usize::from(bits[0] + bits[1] + bits[3])];
        let expected = Statement {
            bits,
            point: &point,
            ..statement
        };
        let mut t = Transcript::<K>::new(b"matmul static maximum").expect("transcript");
        let before = t.usage();
        let failure = matmul::verify(&mut t, &expected, [&xc, &wc], &[], limits)
            .err()
            .expect("expected geometry rejection");
        assert_eq!(failure.cause, cause);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
    }
    // Canonically shaped untrusted bytes isolate each cap from wire-length rejection.
    let first = 1 + 3 * 4 * usize::from(<K as CodeField>::DEGREE);
    let second = first + x.source().proof_size(ProofKind::Opening).expect("X size");
    let mut wire = vec![0; second + w.source().proof_size(ProofKind::Opening).expect("W size")];
    wire[0] = 1;
    wire[first] = 1;
    wire[second] = 1;
    for offset in [1, first + 1, second + 1] {
        let mut changed = wire.clone();
        changed[offset..offset + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        let mut t = Transcript::<K>::new(b"matmul canonical limbs").expect("transcript");
        let before = t.usage();
        let failure = matmul::verify(&mut t, &statement, [&xc, &wc], &changed, limits)
            .err()
            .expect("canonical preflight");
        assert_eq!(failure.cause, Error::NoncanonicalField);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
        assert_eq!(t.usage(), before);
    }
    for offset in [0, first, second] {
        let mut changed = wire.clone();
        changed[offset] = 2;
        let mut t = Transcript::<K>::new(b"matmul versions").expect("transcript");
        let before = t.usage();
        let failure = matmul::verify(&mut t, &statement, [&xc, &wc], &changed, limits)
            .err()
            .expect("outer and nested versions");
        assert_eq!(failure.cause, Error::ProofShape);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
    }
    for changed in [
        wire[..wire.len() - 1].to_vec(),
        [wire.as_slice(), &[0]].concat(),
    ] {
        let mut t = Transcript::<K>::new(b"matmul complete wire").expect("transcript");
        let before = t.usage();
        let failure = matmul::verify(&mut t, &statement, [&xc, &wc], &changed, limits)
            .err()
            .expect("complete wire");
        assert_eq!(failure.cause, Error::ProofShape);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(t.usage(), before);
    }
    for limited in [
        Limits {
            descriptor_bytes: 0,
            ..limits
        },
        Limits {
            proof_bytes: 0,
            ..limits
        },
        Limits {
            prepared_entries: 0,
            ..limits
        },
        Limits {
            partial_entries: 0,
            ..limits
        },
        // A4's existing id/index prefixes remain budgeted in addition to the outer wire.
        Limits {
            proof_bytes: wire.len(),
            ..limits
        },
    ] {
        let mut t = Transcript::<K>::new(b"matmul capacity").expect("transcript");
        let before = t.usage();
        let failure = matmul::verify(&mut t, &statement, [&xc, &wc], &wire, limited)
            .err()
            .expect("cap rejection");
        assert_eq!(failure.cause, Error::Capacity);
        assert_eq!(failure.usage.transcript, before);
        assert_eq!(failure.usage.non_transcript, HashUsage::default());
        assert_eq!(t.usage(), before);
    }
}

#[test]
fn rejects_qm31_matmul_preflight() {
    preflight::<QM31>();
}

#[test]
fn rejects_om31_matmul_preflight() {
    preflight::<OM31>();
}
