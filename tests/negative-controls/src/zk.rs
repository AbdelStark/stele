//! RFC-0013 A2 and RFC-0010 A14: hiding-source controls through the actual A9
//! certificate verifier (NC-0902, NC-0903).
use crate::{check_control, check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage};
use stele_pcs::{hiding_message, verify_certificate, CodeField, Error, PreparedSource, Source};

const SEED: [u8; 32] = [3; 32];

fn layout(degree: u8) -> (u8, u8, u8) {
    // R >= 2D and q_c + q_o <= C - 1 at Circle (10, 2).
    if degree == 8 {
        (4, 9, 2)
    } else {
        (3, 9, 2)
    }
}

fn prepared<K: ChallengeField + CodeField>(
    message: &[M31],
) -> Result<PreparedSource<'_, K>, Error> {
    let (ell, m, b) = layout(<K as CodeField>::DEGREE);
    PreparedSource::<K>::hiding(7, ell, m, b, message, &SEED, &mut HashUsage::default())
}

fn message(degree: u8) -> Vec<M31> {
    let (ell, m, _) = layout(degree);
    let x: Vec<M31> = (0..1i64 << (ell + m))
        .map(|i| M31::from_i64(i % 17 - 8))
        .collect();
    hiding_message(7, ell, m, &x, &SEED).expect("layout")
}

/// Flip one salt byte in the first certificate response.
struct Salt(usize);
impl ProverHook<Vec<u8>> for Salt {
    fn tamper(&self, proof: &mut Vec<u8>) {
        proof[self.0] ^= 1;
    }
}

/// NC-0902: one salt byte changed after the root; the payload no longer
/// authenticates at its derived index.
fn nc_0902<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = message(<K as CodeField>::DEGREE);
    let p = prepared::<K>(&message).map_err(|e| format!("{e:?}"))?;
    let source = *p.source();
    // The first response starts after the version byte and the 2C-element row.
    let salt = 1 + source.columns() * 4 * usize::from(<K as CodeField>::DEGREE);
    check_proof_control(
        || p.certificate().map(|(proof, _)| proof).map_err(|f| f.cause),
        &Salt(salt),
        |proof| {
            verify_certificate(source, proof)
                .map(|_| ())
                .map_err(|f| f.cause)
        },
        Error::Merkle(stele_hash::merkle::Error::RootMismatch),
    )
    .map_err(|e| format!("{e:?}"))
}

/// Replace the expected statement bytes.
struct Replace(Vec<u8>);
impl ProverHook<Vec<u8>> for Replace {
    fn tamper(&self, bytes: &mut Vec<u8>) {
        assert_ne!(*bytes, self.0);
        bytes.clone_from(&self.0);
    }
}

/// NC-0903: a version-3 context with R < 2D, or with q_c + q_o > C - 1, rejects
/// as UnsupportedSource before any transcript work.
fn nc_0903<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message = message(<K as CodeField>::DEGREE);
    let p = prepared::<K>(&message).map_err(|e| format!("{e:?}"))?;
    let proof = p.certificate().map_err(|f| format!("{:?}", f.cause))?.0;
    let honest = p.source().bytes().to_vec();
    // Version-1 Circle layout: ell at 33, m at 53 (code byte 19).
    for (offset, delta) in [(33usize, 1u8), (53, 1)] {
        let mut changed = honest.clone();
        changed[offset] -= delta;
        check_control(
            &honest,
            &Replace(changed),
            |bytes| Ok::<_, Error>(bytes.clone()),
            |bytes| {
                let source = Source::<K>::from_bytes(bytes)?;
                verify_certificate(source, &proof)
                    .map(|_| ())
                    .map_err(|f| f.cause)
            },
            Error::UnsupportedSource,
        )
        .map_err(|e| format!("{e:?}"))?;
    }
    Ok(())
}

/// Execute one hiding-source control in both challenge fields.
pub fn run(id: u16) -> Result<(), String> {
    match id {
        902 => nc_0902::<QM31>().and_then(|()| nc_0902::<OM31>()),
        903 => nc_0903::<QM31>().and_then(|()| nc_0903::<OM31>()),
        _ => Err(format!("unknown control {id}")),
    }
}
