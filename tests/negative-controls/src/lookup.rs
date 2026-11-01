//! RFC-0008 A5 §7: actual closed lookup controls; no production bypasses.
use crate::{check_control, check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind, VerifiedCertificate};
use stele_reductions::lookup::{
    Descriptor, Error, Layout, Limits, ProducerLimits, Statement, Table, TableDescriptor,
    TableField,
};

#[path = "lookup_composer.rs"]
mod composer;
use composer::{compose, transcript, Attack, Packet};

const LIMITS: Limits = Limits {
    positions: 16,
    public_bytes: 16_000_000,
    proof_bytes: 16_000_000,
};
struct Logical(Attack);
impl ProverHook<Attack> for Logical {
    fn tamper(&self, attack: &mut Attack) {
        assert_eq!(*attack, Attack::Honest);
        assert_ne!(self.0, Attack::Honest);
        *attack = self.0;
    }
}
struct Outside;
impl ProverHook<i64> for Outside {
    fn tamper(&self, source: &mut i64) {
        assert_eq!(*source, 7);
        *source = 256;
    }
}
#[derive(Clone)]
struct Attempt<'a, K: ChallengeField> {
    certificate: &'a VerifiedCertificate<K>,
    proof: Vec<u8>,
}
impl<K: ChallengeField> PartialEq for Attempt<'_, K> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.certificate, other.certificate) && self.proof == other.proof
    }
}
struct Different<'a, K: ChallengeField>(&'a VerifiedCertificate<K>);
impl<'a, K: ChallengeField> ProverHook<Attempt<'a, K>> for Different<'a, K> {
    fn tamper(&self, attempt: &mut Attempt<'a, K>) {
        let before = attempt.proof.clone();
        let (old, new) = (
            attempt.certificate.record().source(),
            self.0.record().source(),
        );
        assert_eq!(old.descriptor(), new.descriptor());
        assert_ne!(old.root(), new.root());
        attempt.certificate = self.0;
        assert_eq!(attempt.proof, before);
    }
}
struct Scalar<K> {
    offset: usize,
    marker: core::marker::PhantomData<K>,
}
impl<K: ChallengeField + Eq> ProverHook<Vec<u8>> for Scalar<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    fn tamper(&self, bytes: &mut Vec<u8>) {
        let before = bytes.clone();
        let range = self.offset..self.offset + 4 * K::DEGREE;
        let v = K::from_le_bytes(
            K::Bytes::try_from(&bytes[range.clone()])
                .ok()
                .expect("width"),
        )
        .expect("canonical");
        bytes[range.clone()].copy_from_slice((v + K::from_i64(1)).to_le_bytes().as_ref());
        assert_eq!(before[..range.start], bytes[..range.start]);
        assert_eq!(before[range.end..], bytes[range.end..]);
        assert_ne!(before[range.clone()], bytes[range]);
    }
}
fn local<K: ChallengeField>(cert: &stele_pcs::VerifiedCertificate<K>) -> u64 {
    let s = cert.record().source();
    u64::from(s.queries(ProofKind::Opening)) * (1 + s.path_height() as u64)
}
fn exercise<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
    id: u16,
) -> Result<(), String>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let partial = matches!(id, 417 | 610 | 802 | 420);
    let table = if partial {
        Table::generate(TableDescriptor::new("exp_q/hi", 1, &[7, 0, 0, 6]).expect("shape"))
            .expect("partial table")
    } else {
        Table::range(8).expect("range")
    };
    let (m, b, r) = if partial {
        (2, 0, if id == 420 { 2 } else { 1 })
    } else {
        (0, 0, if id == 403 { 2 } else { 1 })
    };
    let c = table.descriptor().shape().columns() as usize;
    // A5 fixes the false source for 401/419. The preceding source7 run is a
    // separate accepted sanity statement, never authority for the false source.
    let sources = if id == 401 {
        let mut changed = 7;
        Outside.tamper(&mut changed);
        vec![7, changed]
    } else if id == 419 {
        vec![7, 256]
    } else {
        vec![7]
    };
    for source in sources {
        let messages: Vec<Vec<M31>> = (0..c)
            .map(|a| {
                (0..1 << m)
                    .map(|i| {
                        M31::from_i64(if id == 420 {
                            256
                        } else if partial {
                            i64::from(table.entries()[(i % 3) * c + a])
                        } else {
                            source
                        })
                    })
                    .collect()
            })
            .collect();
        let prepared: Vec<_> = messages
            .iter()
            .enumerate()
            .map(|(a, message)| {
                PreparedSource::<K>::new(10 + a as u64, 0, m, 1, message, &mut HashUsage::default())
                    .expect("actual original preparation")
            })
            .collect();
        let certificates: Vec<_> = prepared
            .iter()
            .map(|p| {
                verify_certificate(*p.source(), &p.certificate().expect("actual certificate").0)
                    .expect("actual original registration")
                    .0
            })
            .collect();
        let originals: Vec<_> = certificates.iter().collect();
        let material: Vec<_> = prepared.iter().collect();
        let selector = vec![u8::from(!matches!(id, 402 | 420)); 1 << m];
        let layouts = [
            Layout {
                id: 20,
                ell: if partial { 1 } else { 4 },
                blowup: 1,
            },
            Layout {
                id: 21,
                ell: if partial { 0 } else { 4 },
                blowup: 2,
            },
        ];
        let s = Statement {
            id: 7,
            m,
            b,
            table: &table,
            selector: &selector,
            originals: &originals,
            multiplicities: &layouts[..r],
        };
        let descriptor = Descriptor::new(s, LIMITS).expect("expected descriptor");
        if source == 256 {
            let mut attack = Attack::Honest;
            Logical(if id == 401 {
                Attack::Outside
            } else {
                Attack::Early
            })
            .tamper(&mut attack);
            let packet = compose(&descriptor, s, &material, attack);
            let mu: Vec<_> = packet.handles.iter().collect();
            let mut t = transcript();
            let failure = descriptor
                .verify(&mut t, &mu, &packet.bytes)
                .err()
                .expect("fixed false statement rejected");
            assert_eq!(
                failure.cause,
                Error::Fraction(stele_lookup::fraction::Error::RootMismatch)
            );
            assert_eq!(failure.usage.transcript, packet.trees[0]);
            assert_eq!(failure.usage.transcript, t.usage());
            assert_eq!(
                failure.usage.non_transcript,
                HashUsage {
                    hash_evaluations: 1 + r as u64,
                    ..HashUsage::default()
                }
            );
            continue;
        }
        let baseline = compose(&descriptor, s, &material, Attack::Honest);
        let mut production = transcript();
        let (wire, _) = descriptor
            .prove(
                &mut production,
                &material,
                ProducerLimits {
                    public_bytes: descriptor.producer_public_bytes().expect("public cap"),
                    dense_elements: descriptor.producer_dense_elements().expect("dense cap"),
                },
            )
            .expect("real honest producer");
        assert_eq!(baseline.bytes, wire);
        assert_eq!(baseline.transcript.usage(), production.usage());
        let mu: Vec<_> = baseline.handles.iter().collect();
        let mut verified = transcript();
        let (record, usage) = descriptor
            .verify(&mut verified, &mu, &wire)
            .expect("real honest verifier");
        assert_eq!(usage.transcript, production.usage());
        assert_eq!(
            usage.non_transcript.hash_evaluations,
            descriptor.max_local_hashes()
        );
        assert_eq!(record.repetitions().len(), r);
        let next = crate::sumcheck::instance::<K>(88, false);
        let next_proof =
            crate::sumcheck::produce(&next, &mut production).expect("actual continuation");
        let mut composed = baseline.transcript;
        assert_eq!(
            next_proof,
            crate::sumcheck::produce(&next, &mut composed).expect("composer continuation")
        );
        let _ = stele_sumcheck::verify_public(
            &next,
            &next_proof,
            &[vec![K::from_i64(3), K::from_i64(5)]],
            &mut verified,
        )
        .expect("accepted continuation");
        if matches!(id, 401 | 419) {
            continue;
        }
        if id == 415 {
            let before = transcript::<K>().usage();
            let rejected = Descriptor::new(
                Statement { m: 31, b: 31, ..s },
                Limits {
                    positions: u64::MAX,
                    ..LIMITS
                },
            )
            .err()
            .expect("static group bound");
            assert_eq!(rejected, Error::GroupBound);
            assert_eq!(transcript::<K>().usage(), before);
        } else if id == 420 {
            let packet = compose(&descriptor, s, &material, Attack::Tail);
            let mu: Vec<_> = packet.handles.iter().collect();
            let (record, usage) = descriptor
                .verify(&mut transcript(), &mu, &packet.bytes)
                .expect("nonzero physical tails accepted");
            assert_eq!(usage.transcript, packet.transcript.usage());
            assert_eq!(
                usage.non_transcript.hash_evaluations,
                descriptor.max_local_hashes()
            );
            for (j, rep) in record.repetitions().iter().enumerate() {
                assert_eq!(rep.originals().len(), 2);
                assert_eq!(
                    rep.multiplicities()
                        .iter()
                        .map(|o| o.id())
                        .collect::<Vec<_>>(),
                    if j == 0 { vec![0, 1] } else { vec![1] }
                );
                for opening in rep.multiplicities() {
                    assert_eq!(opening.certificate().id(), mu[j].record().id());
                }
            }
        } else if matches!(id, 417 | 610) {
            let (offset, expected) = if id == 417 {
                (baseline.value_offset, Error::PieceSumMismatch)
            } else {
                (
                    baseline.row_offset,
                    Error::Pcs(stele_pcs::Error::ValueMismatch),
                )
            };
            check_proof_control(
                || Ok::<_, String>(wire.clone()),
                &Scalar::<K> {
                    offset,
                    marker: core::marker::PhantomData,
                },
                |bytes| {
                    let mut t = transcript();
                    let result = descriptor.verify(&mut t, &mu, bytes);
                    if let Err(f) = &result {
                        let mut prefix = if id == 417 {
                            baseline.originals[0]
                        } else {
                            baseline.claims[0]
                        };
                        if id == 610 {
                            prefix.hash_evaluations += 2;
                            prefix.state_updates += 2;
                        }
                        assert_eq!(f.usage.transcript, prefix);
                        assert_eq!(f.usage.transcript, t.usage());
                        assert_eq!(
                            f.usage.non_transcript,
                            HashUsage {
                                hash_evaluations: 1
                                    + r as u64
                                    + certificates.iter().map(local).sum::<u64>(),
                                ..HashUsage::default()
                            }
                        );
                    }
                    result.map(|_| ()).map_err(|f| f.cause)
                },
                expected,
            )
            .map_err(|e| format!("{e:?}"))?;
        } else if id == 418 {
            let src = mu[0].record().source();
            let message = vec![M31::from_i64(17); src.rows() * src.columns()];
            let p = PreparedSource::<K>::new(
                20,
                layouts[0].ell,
                src.columns().trailing_zeros() as u8,
                1,
                &message,
                &mut HashUsage::default(),
            )
            .expect("different physical source");
            let other = verify_certificate(
                *p.source(),
                &p.certificate().expect("different certificate").0,
            )
            .expect("genuine different handle")
            .0;
            assert_ne!(src.root(), other.record().source().root());
            check_proof_control(
                || {
                    Ok::<_, String>(Attempt {
                        certificate: mu[0],
                        proof: wire.clone(),
                    })
                },
                &Different(&other),
                |attempt| {
                    let t = &mut transcript();
                    let before = t.usage();
                    let result = descriptor.verify(t, &[attempt.certificate], &attempt.proof);
                    if let Err(f) = &result {
                        assert_eq!(f.usage.transcript, before);
                        assert_eq!(f.usage.non_transcript, HashUsage::default());
                    }
                    result.map(|_| ()).map_err(|f| f.cause)
                },
                Error::CertificateContext,
            )
            .map_err(|e| format!("{e:?}"))?;
        } else if id == 802 {
            for attack in [
                Attack::OmitStatement,
                Attack::OmitMultiplicities,
                Attack::OmitClaims,
            ] {
                let mut omitted = compose(&descriptor, s, &material, attack);
                let wrong = crate::sumcheck::produce(&next, &mut omitted.transcript)
                    .expect("omitted frame continuation");
                assert_eq!(wrong.rounds, next_proof.rounds);
                check_proof_control(
                    || Ok::<_, String>(vec![next_proof.clone()]),
                    &crate::sumcheck::Change {
                        round: false,
                        value: wrong.final_values[0],
                    },
                    |proofs| {
                        let mut t = transcript();
                        let _ = descriptor
                            .verify(&mut t, &mu, &wire)
                            .expect("honest lookup closes first");
                        stele_sumcheck::verify_public(
                            &next,
                            &proofs[0],
                            &[vec![K::from_i64(3), K::from_i64(5)]],
                            &mut t,
                        )
                        .map(|_| ())
                    },
                    stele_sumcheck::Error::FinalEvaluationMismatch,
                )
                .map_err(|e| format!("{e:?}"))?;
            }
        } else {
            let (attack, expected) = match id {
                400 => (
                    Attack::Increment,
                    Error::Fraction(stele_lookup::fraction::Error::RootMismatch),
                ),
                402 => (
                    Attack::Select,
                    Error::Fraction(stele_lookup::fraction::Error::SelectorMismatch),
                ),
                403 => (Attack::ReusePair, Error::TableDenominatorMismatch),
                416 => (
                    Attack::Pole,
                    Error::Fraction(stele_lookup::fraction::Error::Pole),
                ),
                _ => return Err(format!("unknown lookup control {id}")),
            };
            check_control(
                &Attack::Honest,
                &Logical(attack),
                |attack| Ok::<_, String>(compose(&descriptor, s, &material, *attack)),
                |packet: &Packet<K>| {
                    let mu: Vec<_> = packet.handles.iter().collect();
                    let mut t = transcript();
                    let result = descriptor.verify(&mut t, &mu, &packet.bytes);
                    if let Err(f) = &result {
                        let j = usize::from(id == 403);
                        assert_eq!(f.usage.transcript, packet.trees[j]);
                        assert_eq!(f.usage.transcript, t.usage());
                        let earlier = if j == 1 {
                            certificates.iter().map(local).sum::<u64>() + local(mu[0])
                        } else {
                            0
                        };
                        assert_eq!(
                            f.usage.non_transcript,
                            HashUsage {
                                hash_evaluations: 1 + r as u64 + earlier,
                                ..HashUsage::default()
                            }
                        );
                    }
                    result.map(|_| ()).map_err(|f| f.cause)
                },
                expected,
            )
            .map_err(|e| format!("{e:?}"))?;
        }
    }
    Ok(())
}
/// Conditional lookup variants and the existing composed PCS/transcript controls.
pub fn run(id: u16) -> Result<(), String> {
    exercise::<QM31>(id)?;
    exercise::<OM31>(id)
}

#[test]
fn accepts_qm31_nonzero_lookup_tail() {
    exercise::<QM31>(420).expect("actual projected tail");
}
#[test]
fn accepts_om31_nonzero_lookup_tail() {
    exercise::<OM31>(420).expect("actual projected tail");
}
