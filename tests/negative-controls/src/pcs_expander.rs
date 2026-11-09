//! RFC-0010 A3 items 2,8,9 and A6 item 4: version-2 source and expansion controls
//! through the actual native certificate/opening verifiers (NC-0612..0614).
use crate::{check_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_pcs::{
    expand, verify_certificate, verify_point, CodeField, Embedding, Error, PreparedSource,
    ProofKind, Source,
};

const PUBLIC: &[u8] = b"stele/v0.1/pcs-certificate/public";

fn manifest(j: u8, seed: u8) -> Vec<u8> {
    let mut id = b"stele/expander-seed/v2".to_vec();
    id.push(j);
    id.extend_from_slice(&[seed; 32]);
    id
}

/// Independent A9 §3 certificate composer for `expected`: t from `rows` (raw u32
/// limbs, reduced for arithmetic, serialized as given) and responses from `columns`.
fn compose<K: ChallengeField>(
    expected: &Source<K>,
    rows: &[u32],
    columns: &PreparedSource<'_, K>,
) -> Result<Vec<u8>, Error> {
    let mut public = PUBLIC.to_vec();
    public.extend_from_slice(&expected.bytes());
    let mut t = Transcript::<K>::new(&public).map_err(Error::Transcript)?;
    let ell = expected.rows().trailing_zeros() as usize;
    let point = (0..ell)
        .map(|_| t.challenge(ChallengeLabel::CertificateWeight))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::Transcript)?;
    let a = stele_poly::eq_table(&point).map_err(|_| Error::Capacity)?;
    let c = expected.columns();
    let mut proof = vec![1];
    for column in 0..c {
        let mut value = K::from_i64(0);
        for (row, weight) in a.iter().enumerate() {
            value = value + *weight * K::from_i64(i64::from(rows[row * c + column]));
        }
        let mut bytes = value.to_le_bytes().as_ref().to_vec();
        if ell == 0 {
            // R=1, a=(1): t is the row itself; keep a noncanonical limb verbatim.
            bytes[..4].copy_from_slice(&rows[column].to_le_bytes());
        }
        proof.extend_from_slice(&bytes);
    }
    t.absorb(AbsorbLabel::CertificateRow, &proof[1..])
        .map_err(Error::Transcript)?;
    let start = proof.len();
    for _ in 0..expected.queries(ProofKind::Certificate) {
        let index = t
            .certificate_column(expected.descriptor().count)
            .map_err(Error::Transcript)?;
        let response = columns.response(index)?;
        proof.extend_from_slice(response.payload);
        for sibling in response.siblings {
            proof.extend_from_slice(&sibling);
        }
    }
    t.absorb(AbsorbLabel::CertificateColumns, &proof[start..])
        .map_err(Error::Transcript)?;
    Ok(proof)
}

fn limbs(message: &[M31]) -> Vec<u32> {
    message.iter().map(|x| x.as_u32()).collect()
}

fn certify<K: ChallengeField + CodeField>(
    p: &PreparedSource<'_, K>,
) -> Result<stele_pcs::VerifiedCertificate<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let bytes = p.certificate().map_err(|f| f.cause)?.0;
    // The composer is the producer: identical bytes on every honest source.
    assert_eq!(compose(p.source(), &limbs(p.message()), p)?, bytes);
    verify_certificate(*p.source(), &bytes)
        .map(|(c, _)| c)
        .map_err(|f| f.cause)
}

struct Replace<T>(T);
impl<T: Clone + PartialEq + core::fmt::Debug> ProverHook<T> for Replace<T> {
    fn tamper(&self, w: &mut T) {
        assert_ne!(*w, self.0);
        *w = self.0.clone();
    }
}

/// NC-0612: handle substitution (CertificateContext), rows encoded under another
/// seed for the expected context (ColumnMismatch), edited registry (InvalidRegistry).
fn nc_0612<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message: Vec<M31> = (0..64).map(|i| M31::from_i64(3 * i + 1)).collect();
    let prepare = |code: &[u8]| {
        PreparedSource::<K>::from_code_id(41, 0, code, &message, &mut HashUsage::default())
    };
    let circle = Source::<K>::new(41, 0, 6, 1, [0; 32]).map_err(|e| format!("{e:?}"))?;
    let codes = [manifest(3, 1), manifest(3, 2), circle.code_id().to_vec()];
    let prepared = codes
        .iter()
        .map(|code| prepare(code))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{e:?}"))?;
    let handles = prepared
        .iter()
        .map(certify)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{e:?}"))?;
    let expected = *prepared[0].source();
    let point: Vec<K> = (0..6).map(|i| K::from_i64(i + 5)).collect();
    let b = stele_poly::eq_table(&point).map_err(|e| format!("{e:?}"))?;
    let value = message.iter().zip(&b).fold(K::from_i64(0), |v, (x, w)| {
        v + *w * K::from_i64(i64::from(x.as_u32()))
    });
    let mut producer = Transcript::<K>::new(b"nc-0612").map_err(|e| format!("{e:?}"))?;
    let (opening, _) = prepared[0]
        .opening_point(&mut producer, &handles[0], 12, &point, value)
        .map_err(|f| format!("{:?}", f.cause))?;
    for other in [1usize, 2] {
        check_control(
            &0usize,
            &Replace(other),
            |i| Ok::<_, Error>(*i),
            |i| {
                // The consumer's expected context is fixed before the offered handle.
                handles[*i].record().check_source(&expected)?;
                let mut t = Transcript::<K>::new(b"nc-0612").map_err(Error::Transcript)?;
                verify_point(&mut t, &handles[*i], 12, &point, value, &opening)
                    .map(|_| ())
                    .map_err(|f| f.cause)
            },
            Error::CertificateContext,
        )
        .map_err(|e| format!("{e:?}"))?;
    }
    // Expected seed-1 identity whose committed columns were encoded under seed 2.
    // J=4: at J=3 the base-only map ignores the seed, so only the context differs.
    let rows: Vec<M31> = (0..256).map(|i| M31::from_i64(7 * i + 2)).collect();
    let seeded = [manifest(4, 1), manifest(4, 2)];
    let columns = seeded
        .iter()
        .map(|code| {
            PreparedSource::<K>::from_code_id(41, 0, code, &rows, &mut HashUsage::default())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{e:?}"))?;
    check_control(
        &0usize,
        &Replace(1usize),
        |i| {
            let columns = &columns[*i];
            let expected = Source::<K>::from_code_id(41, 0, &seeded[0], columns.source().root())?;
            Ok::<_, Error>((expected, compose(&expected, &limbs(&rows), columns)?))
        },
        |(expected, proof)| {
            verify_certificate(*expected, proof)
                .map(|_| ())
                .map_err(|f| f.cause)
        },
        Error::ColumnMismatch,
    )
    .map_err(|e| format!("{e:?}"))?;
    // A1 configuration validator (conditional variant): no proof byte reaches it.
    let export = stele_pcs::registry::CATALOG_EXPORT.to_owned();
    check_control(
        &export,
        &Replace(export.replacen("rfc-0010-a1/finite-v2", "rfc-0010-a1/finite-v3", 1)),
        |text| Ok::<_, ()>(text.clone()),
        |text| stele_pcs::registry::check_export(text.as_bytes()).map_err(|e| format!("{e:?}")),
        "InvalidRegistry".to_owned(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// NC-0613: J=15 (N=2^31) or policy byte 2 in the expected statement bytes rejects
/// as UnsupportedSource before any transcript or Merkle work.
fn nc_0613<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let message: Vec<M31> = (0..64).map(|i| M31::from_i64(i + 2)).collect();
    let p = PreparedSource::<K>::from_code_id(
        41,
        0,
        &manifest(3, 7),
        &message,
        &mut HashUsage::default(),
    )
    .map_err(|e| format!("{e:?}"))?;
    let proof = p.certificate().map_err(|f| format!("{:?}", f.cause))?.0;
    let honest = p.source().bytes().to_vec();
    // Offsets in the 139-byte version-2 layout: J at 56, policy at 106.
    for (offset, value) in [(56usize, 15u8), (106, 2)] {
        let mut changed = honest.clone();
        changed[offset] = value;
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
    if Source::<K>::from_code_id(41, 0, &manifest(15, 7), [0; 32]).err()
        != Some(Error::UnsupportedSource)
    {
        return Err("J=15 identity admitted".into());
    }
    Ok(())
}

/// NC-0614: one typed value expanded into two message elements under the expected
/// one-element context (ColumnMismatch); an expanded row with the limb p
/// (NoncanonicalField). Both run the actual certificate verifier.
fn nc_0614<K: ChallengeField + CodeField>() -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let values: Vec<i16> = (0..128).map(|i| (i * 517 - 30000) as i16).collect();
    let message = expand(&values, Embedding::Offset).map_err(|e| format!("{e:?}"))?;
    let honest = PreparedSource::<K>::from_code_id(
        41,
        1,
        &manifest(3, 5),
        &message,
        &mut HashUsage::default(),
    )
    .map_err(|e| format!("{e:?}"))?;
    let expected = *honest.source();
    check_control(
        &None::<usize>,
        &Replace(Some(9usize)),
        |split| {
            let mut rows = limbs(&message);
            if let Some(i) = split {
                // Value i becomes two limbs (low byte, high byte); later values shift.
                let x = rows[*i];
                rows.insert(*i + 1, x >> 8);
                rows[*i] = x & 0xff;
                rows.truncate(message.len());
            }
            compose(&expected, &rows, &honest)
        },
        |proof| {
            verify_certificate(expected, proof)
                .map(|_| ())
                .map_err(|f| f.cause)
        },
        Error::ColumnMismatch,
    )
    .map_err(|e| format!("{e:?}"))?;
    // Offset int8 -128 expands to 0; its noncanonical alias is the limb p.
    let bytes: Vec<i8> = (0..64).map(|i| (i * 4 - 128) as i8).collect();
    let row = expand(&bytes, Embedding::Offset).map_err(|e| format!("{e:?}"))?;
    assert_eq!(row[0], M31::from_i64(0));
    let single =
        PreparedSource::<K>::from_code_id(42, 0, &manifest(3, 5), &row, &mut HashUsage::default())
            .map_err(|e| format!("{e:?}"))?;
    let mut tampered = limbs(&row);
    tampered[0] = M31::MODULUS;
    check_control(
        &limbs(&row),
        &Replace(tampered),
        |rows| compose(single.source(), rows, &single),
        |proof| {
            verify_certificate(*single.source(), proof)
                .map(|_| ())
                .map_err(|f| f.cause)
        },
        Error::NoncanonicalField,
    )
    .map_err(|e| format!("{e:?}"))
}

/// Execute one version-2/expansion control in both challenge fields.
pub fn run(id: u16) -> Result<(), String> {
    match id {
        612 => nc_0612::<QM31>().and_then(|()| nc_0612::<OM31>()),
        613 => nc_0613::<QM31>().and_then(|()| nc_0613::<OM31>()),
        614 => nc_0614::<QM31>().and_then(|()| nc_0614::<OM31>()),
        _ => Err(format!("unknown control {id}")),
    }
}
