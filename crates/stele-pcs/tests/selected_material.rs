//! RFC-0010 A16. The unchanged verifier authenticates externally prepared columns.
use std::borrow::Cow;
use stele_field::{Field, M31, QM31};
use stele_hash::{merkle, HashUsage, Transcript};
use stele_pcs::{
    hiding_message, verify_certificate, verify_point, ColumnMaterial, ColumnResponse, Error,
    HidingUse, Policy, PreparedSource, Source,
};

#[derive(Clone, Copy)]
enum Change {
    Honest,
    WrongId,
    WrongRoot,
    Long,
    ShortPath,
    Short,
    ExtraSibling,
    FlipSibling,
}

struct Provider<'a> {
    host: PreparedSource<'a, QM31>,
    change: Change,
}
impl ColumnMaterial for Provider<'_> {
    fn descriptor(&self) -> merkle::Descriptor {
        let mut d = self.host.source().descriptor();
        if matches!(self.change, Change::WrongId) {
            d.id += 1;
        }
        d
    }
    fn root(&self) -> merkle::Digest {
        let mut root = self.host.source().root();
        if matches!(self.change, Change::WrongRoot) {
            root[0] ^= 1;
        }
        root
    }
    fn selected(&self, index: u64) -> Result<ColumnResponse<'_>, Error> {
        let response = self.host.response(index)?;
        let mut siblings = response.siblings;
        let mut bytes = response.payload.to_owned();
        match self.change {
            Change::Short => {
                bytes.pop();
            }
            Change::ExtraSibling => siblings.push([0; 32]),
            Change::Long => bytes.push(0),
            Change::ShortPath => {
                siblings.pop();
            }
            Change::FlipSibling => siblings[0][0] ^= 1,
            _ => {}
        }
        Ok((Cow::Owned(bytes), siblings))
    }
}

const ID: u64 = 41;
const SEED: [u8; 32] = [9; 32];
fn external<'a>(
    message: &'a [M31],
    change: Change,
    usage: HidingUse<QM31>,
) -> Result<PreparedSource<'a, QM31, Provider<'a>>, Error> {
    PreparedSource::hiding_material(
        ID,
        3,
        9,
        message,
        &SEED,
        usage,
        &mut HashUsage::default(),
        |context, input, seed, hashes| {
            assert_eq!(context.root(), [0; 32]);
            assert_eq!(context.descriptor().id, ID);
            let host = PreparedSource::hiding_with(ID, 3, 9, 2, input, seed, hashes, Policy::Two)?;
            Ok(Provider { host, change })
        },
    )
}
fn message() -> Vec<M31> {
    let data: Vec<_> = (0..1 << 12).map(|i| M31::from_i64(i % 97)).collect();
    hiding_message(ID, 3, 9, &data, &SEED).expect("hiding message")
}

#[test]
fn matches_reference_certificate_opening_and_single_spend() {
    let message = message();
    let host = PreparedSource::<QM31>::hiding_with(
        ID,
        3,
        9,
        2,
        &message,
        &SEED,
        &mut HashUsage::default(),
        Policy::Two,
    )
    .expect("scalar hiding source");
    let candidate = external(&message, Change::Honest, HidingUse::Single).expect("selected source");
    assert_eq!(host.source().bytes(), candidate.source().bytes());
    let (cert, hashes) = host.certificate().expect("scalar certificate");
    assert_eq!(
        candidate.certificate().expect("material certificate"),
        (cert.clone(), hashes)
    );
    let (verified, _) = verify_certificate(*host.source(), &cert).expect("authenticated source");
    let element = |seed: u64| {
        let limb = |i: u64| M31::from_u64(seed * 7919 + i * 104729 + 3);
        stele_field::QM31(
            stele_field::CM31(limb(0), limb(1)),
            stele_field::CM31(limb(2), limb(3)),
        )
    };
    let mut point = vec![element(1)];
    point.extend((10..13).map(element));
    point.push(QM31::from_i64(0)); // Y=0 on the A15 data face.
    point.extend((40..49).map(element));
    let weights = stele_poly::eq_table(&point).expect("point weights");
    let value = weights
        .iter()
        .zip(&message)
        .fold(QM31::from_i64(0), |sum, (w, x)| {
            sum + *w * QM31::from_i64(i64::from(x.as_u32()))
        });
    let transcript = || Transcript::<QM31>::new(b"external material").expect("new transcript");
    let expected = host
        .opening_point(&mut transcript(), &verified, 3, &point, value)
        .expect("scalar opening")
        .0;
    let actual = candidate
        .opening_point(&mut transcript(), &verified, 3, &point, value)
        .expect("material opening")
        .0;
    assert_eq!(expected, actual);
    verify_point(&mut transcript(), &verified, 3, &point, value, &actual)
        .expect("verified opening");
    // A malformed download after the row was absorbed still spends this prepared opening.
    let damaged =
        external(&message, Change::Short, HidingUse::Single).expect("malformed response provider");
    for cause in [Error::Merkle(merkle::Error::InvalidLeaf), Error::MaskBudget] {
        assert!(
            matches!(damaged.opening_point(&mut transcript(), &verified, 3, &point, value), Err(f) if f.cause == cause)
        );
    }
    assert!(
        matches!(candidate.opening_point(&mut transcript(), &verified, 3, &point, value), Err(f) if f.cause == Error::MaskBudget)
    );
}

#[test]
fn rejects_malformed_material_and_changed_authentication() {
    let message = message();
    assert!(matches!(
        external(&message, Change::WrongId, HidingUse::Single),
        Err(Error::CertificateContext)
    ));
    for (mutation, failure) in [
        (Change::Short, merkle::Error::InvalidLeaf),
        (Change::ExtraSibling, merkle::Error::InvalidPath),
        (Change::Long, merkle::Error::InvalidLeaf),
        (Change::ShortPath, merkle::Error::InvalidPath),
    ] {
        let source =
            external(&message, mutation, HidingUse::Single).expect("malformed response provider");
        assert!(matches!(source.certificate(), Err(f) if f.cause == Error::Merkle(failure)));
    }
    for corruption in [Change::FlipSibling, Change::WrongRoot] {
        let source =
            external(&message, corruption, HidingUse::Single).expect("changed tree provider");
        let (certificate, _) = source.certificate().expect("unverified certificate bytes");
        assert!(
            matches!(verify_certificate(*source.source(), &certificate), Err(f) if f.cause == Error::Merkle(merkle::Error::RootMismatch))
        );
    }
    assert!(
        !Source::<QM31>::hiding_with(ID, 3, 9, 2, [0; 32], Policy::Two)
            .expect("valid geometry")
            .admits_lifetime(usize::MAX)
    );
}

#[test]
fn rejects_exhausted_or_rank_deficient_material_history() {
    let data = vec![M31::ONE; 1 << 14];
    let message = hiding_message(ID, 4, 10, &data, &SEED).expect("lifetime hiding message");
    let prepare = |revealed| {
        PreparedSource::hiding_material(
            ID,
            4,
            10,
            &message,
            &SEED,
            HidingUse::Lifetime {
                budget: 2,
                revealed,
            },
            &mut HashUsage::default(),
            |_, input, seed, hashes| {
                Ok(Provider {
                    host: PreparedSource::hiding_with(
                        ID,
                        4,
                        10,
                        2,
                        input,
                        seed,
                        hashes,
                        Policy::Two,
                    )?,
                    change: Change::Honest,
                })
            },
        )
    };
    assert!(matches!(
        prepare(vec![vec![], vec![]]),
        Err(Error::MaskBudget)
    ));
    // An already revealed row must participate in the next opening's rank check.
    let mut point: Vec<_> = (1..=16)
        .map(|i| {
            stele_field::QM31(
                stele_field::CM31(M31::from_i64(i), M31::ONE),
                stele_field::CM31(M31::ZERO, M31::from_i64(i + 2)),
            )
        })
        .collect();
    point[5] = QM31::from_i64(0);
    let prior = stele_poly::eq_table(&point[..5]).expect("row weights");
    let value = stele_poly::eq_table(&point)
        .expect("point weights")
        .iter()
        .zip(&message)
        .fold(QM31::from_i64(0), |sum, (w, x)| {
            sum + *w * QM31::from_i64(i64::from(x.as_u32()))
        });
    let make_proof = |source: &PreparedSource<'_, QM31, Provider<'_>>| {
        let certificate = source.certificate().expect("certificate").0;
        let verified = verify_certificate(*source.source(), &certificate)
            .expect("verified certificate")
            .0;
        source.opening_point(
            &mut Transcript::new(b"A6 prior row").expect("opening transcript"),
            &verified,
            1,
            &point,
            value,
        )
    };
    assert!(make_proof(&prepare(vec![]).expect("fresh material")).is_ok());
    assert!(
        matches!(make_proof(&prepare(vec![prior]).expect("persisted prior opening")), Err(f) if f.cause == Error::MaskRank)
    );
}
