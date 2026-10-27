//! RFC-0012 A3: one changed leaf byte or sibling, actual tree/path verifier.
use stele_hash::merkle::{verify, Descriptor, Error, Kind, Opening, Tree};
use stele_negative_controls::{check_proof_control, ProverHook};

type Proof = (Vec<u8>, Vec<[u8; 32]>);
struct Change(bool);
impl ProverHook<Proof> for Change {
    fn tamper(&self, p: &mut Proof) {
        let before = p.clone();
        if self.0 {
            p.0[0] ^= 1;
        } else {
            p.1[0][0] ^= 1;
        }
        assert_eq!(
            before
                .0
                .iter()
                .chain(before.1.iter().flatten())
                .zip(p.0.iter().chain(p.1.iter().flatten()))
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
    }
}
/// Execute both kinds through the same production authentication boundary.
pub fn run() -> Result<(), String> {
    for kind in [Kind::Columns, Kind::Roots] {
        let spec = Descriptor {
            kind,
            id: 17,
            count: 3,
            width: 32,
        };
        // The first two leaves differ in exactly one byte: the leaf mutation is a wrong-leaf opening.
        let mut leaves = vec![vec![0; 32]; 3];
        leaves[1][0] = 1;
        let tree = Tree::new(spec, &leaves.iter().map(Vec::as_slice).collect::<Vec<_>>())
            .map_err(|e| format!("{e:?}"))?;
        let root = tree.root();
        for leaf in [true, false] {
            check_proof_control(
                || Ok::<_, Error>((leaves[0].clone(), tree.path(0)?)),
                &Change(leaf),
                |p| {
                    verify(
                        spec,
                        &root,
                        0,
                        Opening {
                            payload: &p.0,
                            siblings: &p.1,
                        },
                    )
                },
                Error::RootMismatch,
            )
            .map_err(|e| format!("{e:?}"))?;
        }
    }
    Ok(())
}
#[test]
fn rejects_nc_0602() {
    run().expect("NC-0602 must reject at the production verifier");
}
