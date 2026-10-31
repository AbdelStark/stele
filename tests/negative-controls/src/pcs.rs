//! RFC-0010 A9: one-value certificate attacks through the actual native verifier.
use crate::{check_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{merkle, AbsorbLabel, ChallengeField, Transcript};
use stele_pcs::{verify_certificate, Error, ProofKind, Source};

#[derive(Clone, PartialEq)]
struct Witness {
    leaves: [u32; 2],
    root_bit: u8,
    import_bit: u8,
    query_change: u16,
}
struct Change(u16);
impl ProverHook<Witness> for Change {
    fn tamper(&self, w: &mut Witness) {
        match self.0 {
            600 => w.leaves[1] = 7,
            601 | 803 => w.query_change = self.0,
            606 => w.root_bit = 1,
            607 => w.leaves[0] = M31::MODULUS,
            608 => w.import_bit = 1,
            _ => unreachable!(),
        }
        assert_eq!(
            usize::from(w.leaves[0] != 6)
                + usize::from(w.leaves[1] != 6)
                + usize::from(w.root_bit != 0)
                + usize::from(w.import_bit != 0)
                + usize::from(w.query_change != 0),
            1
        );
    }
}
fn build<K: ChallengeField>(
    leaves: [u32; 2],
    query_change: u16,
) -> Result<(Source<K>, Vec<u8>), Error> {
    let payloads = leaves.map(u32::to_le_bytes);
    let spec = merkle::Descriptor {
        kind: merkle::Kind::Columns,
        id: 41,
        count: 2,
        width: 4,
    };
    let tree = merkle::Tree::new(spec, &[&payloads[0], &payloads[1]]).map_err(Error::Merkle)?;
    let source = Source::<K>::new(41, 0, 0, 1, tree.root())?;
    let mut public = b"stele/v0.1/pcs-certificate/public".to_vec();
    public.extend_from_slice(&source.bytes());
    let mut t = Transcript::<K>::new(&public).map_err(Error::Transcript)?;
    let mut stale = Transcript::<K>::new(&public).map_err(Error::Transcript)?;
    let row = K::from_i64(6).to_le_bytes(); // R=C=1: no row-weight draw; constant codeword.
    t.absorb(AbsorbLabel::CertificateRow, row.as_ref())
        .map_err(Error::Transcript)?;
    let mut proof = vec![1];
    proof.extend_from_slice(row.as_ref());
    let start = proof.len();
    let mut changed = false;
    for _ in 0..source.queries(ProofKind::Certificate) {
        let mut index = t.certificate_column(2).map_err(Error::Transcript)?;
        let stale_index = stale.certificate_column(2).map_err(Error::Transcript)?;
        if !changed && (query_change == 601 || (query_change == 803 && stale_index != index)) {
            // Exactly one logical index changes; all honest draws and other responses remain.
            index = if query_change == 601 {
                index ^ 1
            } else {
                stale_index
            };
            changed = true;
        }
        proof.extend_from_slice(&payloads[index as usize]);
        for sibling in tree.path(index).map_err(Error::Merkle)? {
            proof.extend_from_slice(&sibling);
        }
    }
    assert_eq!(changed, query_change != 0);
    t.absorb(AbsorbLabel::CertificateColumns, &proof[start..])
        .map_err(Error::Transcript)?;
    Ok((source, proof))
}
fn check<K: ChallengeField>(
    id: u16,
    verify: impl Fn(Source<K>, &[u8]) -> Result<(), Error>,
) -> Result<(), String> {
    let expected = match id {
        600 => Error::ColumnMismatch,
        607 => Error::NoncanonicalField,
        _ => Error::Merkle(merkle::Error::RootMismatch),
    };
    check_control(
        &Witness {
            leaves: [6; 2],
            root_bit: 0,
            import_bit: 0,
            query_change: 0,
        },
        &Change(id),
        |w| {
            // A9: changing one authenticated limb requires rebuilding its tree and dependent queries.
            let (mut source, mut proof) = build::<K>(w.leaves, w.query_change)?;
            if w.root_bit != 0 {
                let mut root = source.root();
                root[0] ^= w.root_bit;
                source = Source::new(41, 0, 0, 1, root)?;
            }
            if w.import_bit != 0 {
                verify(source, &proof)?; // An earlier honest verification cannot authorize changed import bytes.
                proof[1 + 4 * K::DEGREE] ^= w.import_bit;
            }
            Ok::<_, Error>((source, proof))
        },
        |(source, proof)| verify(*source, proof),
        expected,
    )
    .map_err(|error| format!("{error:?}"))
}
/// Execute the actual certificate consumer for both challenge fields.
pub fn run(id: u16) -> Result<(), String> {
    check::<QM31>(id, |s, p| {
        verify_certificate(s, p).map(|_| ()).map_err(|e| e.cause)
    })?;
    check::<OM31>(id, |s, p| {
        verify_certificate(s, p).map(|_| ()).map_err(|e| e.cause)
    })
}
