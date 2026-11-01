//! RFC-0008 A5 §7: separate adversarial composition of the real A3/A9 producers.
use stele_field::{Field, Serialize, M31};
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, HashUsage, Transcript};
use stele_lookup::fraction::{self, LeafDescriptor, SelectedProduct};
use stele_pcs::{verify_certificate, CodeField, Functional, PreparedSource, VerifiedCertificate};
use stele_reductions::lookup::{Descriptor, Statement, TableField};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Attack {
    Honest,
    Outside,
    Increment,
    Select,
    ReusePair,
    Pole,
    Early,
    Tail,
    OmitStatement,
    OmitMultiplicities,
    OmitClaims,
}
pub(super) struct Packet<K: ChallengeField> {
    pub bytes: Vec<u8>,
    pub handles: Vec<VerifiedCertificate<K>>,
    pub transcript: Transcript<K>,
    pub trees: Vec<HashUsage>,
    pub originals: Vec<HashUsage>,
    pub claims: Vec<HashUsage>,
    pub value_offset: usize,
    pub row_offset: usize,
}
pub(super) fn transcript<K: ChallengeField>() -> Transcript<K> {
    Transcript::new(b"closed lookup controls/v1").expect("fixture prefix")
}
fn phase(id: u64, j: usize, tag: u8) -> Vec<u8> {
    let mut bytes = id.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[j as u8, tag]);
    bytes
}
fn frame<K: ChallengeField>(
    t: &mut Transcript<K>,
    label: AbsorbLabel,
    bytes: &[u8],
    attack: Attack,
) {
    if !matches!(
        (attack, label),
        (Attack::OmitStatement, AbsorbLabel::LookupStatement)
            | (
                Attack::OmitMultiplicities,
                AbsorbLabel::LookupMultiplicities
            )
            | (Attack::OmitClaims, AbsorbLabel::LookupMultiplicityClaims)
    ) {
        t.absorb(label, bytes).expect("actual frame");
    }
}
// Direct MSB equality products independently define the prefix functionals.
fn weights<K: Field>(point: &[K]) -> Vec<K> {
    (0..1usize << point.len())
        .map(|i| {
            point
                .iter()
                .enumerate()
                .fold(K::from_i64(1), |v, (bit, x)| {
                    v * if i >> (point.len() - bit - 1) & 1 == 1 {
                        *x
                    } else {
                        K::from_i64(1) - *x
                    }
                })
        })
        .collect()
}
pub(super) fn compose<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>(
    descriptor: &Descriptor<'_, '_, K>,
    s: Statement<'_, '_, K>,
    originals: &[&PreparedSource<'_, K>],
    attack: Attack,
) -> Packet<K>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let (r, c) = (s.multiplicities.len(), originals.len());
    let d = usize::from(<K as CodeField>::DEGREE);
    let n = s.table.descriptor().shape().padded() as usize;
    let real = s.table.descriptor().shape().rows() as usize;
    let mut t = transcript();
    let statement = descriptor
        .encode(&mut HashUsage::default())
        .expect("expected statement");
    frame(&mut t, AbsorbLabel::LookupStatement, &statement, attack);
    let theta: Vec<Vec<K>> = (0..r)
        .map(|j| {
            t.absorb(AbsorbLabel::LookupUnits, &phase(s.id, j, 0)[..9])
                .expect("Units");
            (0..s.m - s.b)
                .map(|_| t.challenge(ChallengeLabel::LookupUnit).expect("unit"))
                .collect()
        })
        .collect();
    let mut sigma: Vec<K> = s
        .selector
        .iter()
        .map(|v| K::from_i64(i64::from(*v)))
        .collect();
    if attack == Attack::Select {
        assert_eq!(sigma, [K::from_i64(0)]);
        sigma[0] = K::from_i64(1);
    }
    let xs: Vec<Vec<K>> = originals
        .iter()
        .map(|p| {
            p.message()
                .iter()
                .map(|v| K::from_i64(i64::from(v.as_u32())))
                .collect()
        })
        .collect();
    let mut mu = vec![vec![K::from_i64(0); n]; r];
    for (j, values) in mu.iter_mut().enumerate() {
        let w = weights(&theta[j]);
        for (i, selected) in sigma.iter().enumerate() {
            if *selected == K::from_i64(0) {
                continue;
            }
            for (row, tuple) in s.table.entries().chunks_exact(c).take(real).enumerate() {
                if tuple
                    .iter()
                    .enumerate()
                    .all(|(a, x)| originals[a].message()[i] == M31::from_i64(i64::from(*x)))
                {
                    values[row] = values[row] + w[i >> s.b];
                }
            }
        }
    }
    if attack == Attack::Increment {
        assert_eq!(mu[0][7], K::from_i64(1));
        mu[0][7] = mu[0][7] + K::from_i64(1);
    }
    let early = if attack == Attack::Early {
        // The incorrect ordering exists only in this independent adversarial replay.
        let mut early = transcript::<K>();
        early
            .absorb(AbsorbLabel::LookupStatement, &statement)
            .expect("Statement");
        early
            .absorb(AbsorbLabel::LookupUnits, &phase(s.id, 0, 0)[..9])
            .expect("Units");
        assert_eq!((s.m, s.b, r), (0, 0, 1));
        early
            .absorb(AbsorbLabel::LookupRepetition, &phase(s.id, 0, 0))
            .expect("Repetition");
        let _ = early
            .challenge(ChallengeLabel::LookupBeta)
            .expect("early beta");
        let alpha = early
            .challenge(ChallengeLabel::LookupAlpha)
            .expect("early alpha");
        assert!((0..=256).all(|i| alpha != K::from_i64(i)));
        assert!(mu[0].iter().all(|v| *v == K::from_i64(0)));
        mu[0][0] = alpha * (alpha - K::from_i64(256)).inverse().expect("nonpole");
        Some(alpha)
    } else {
        None
    };
    let limbs: Vec<Vec<M31>> = mu
        .iter()
        .map(|values| {
            let mut limbs: Vec<M31> = values
                .iter()
                .flat_map(|v| {
                    v.to_le_bytes()
                        .as_ref()
                        .chunks_exact(4)
                        .map(|w| {
                            M31::from_le_bytes(w.try_into().expect("limb")).expect("canonical")
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            if attack == Attack::Tail {
                assert!(real < n);
                for (i, limb) in limbs[real * d..].iter_mut().enumerate() {
                    *limb = M31::from_i64((i + 1) as i64);
                }
            }
            limbs
        })
        .collect();
    let prepared: Vec<_> = limbs
        .iter()
        .enumerate()
        .map(|(j, message)| {
            let l = s.multiplicities[j];
            let source = descriptor
                .multiplicity_source(j, [0; 32])
                .expect("expected geometry");
            PreparedSource::<K>::new(
                l.id,
                l.ell,
                source.columns().trailing_zeros() as u8,
                l.blowup,
                message,
                &mut HashUsage::default(),
            )
            .expect("genuine mu preparation")
        })
        .collect();
    let mut bytes = vec![1, d as u8];
    let mut handles = Vec::new();
    let mut bundle = s.id.to_le_bytes().to_vec();
    bundle.push(r as u8);
    for (j, p) in prepared.iter().enumerate() {
        let certificate = p.certificate().expect("actual mu certificate").0;
        let handle = verify_certificate(*p.source(), &certificate)
            .expect("actual mu registration")
            .0;
        bundle.push(j as u8);
        bundle.extend_from_slice(&p.source().bytes());
        bundle.extend_from_slice(&handle.record().id());
        bytes.extend_from_slice(&p.source().root());
        bytes.extend_from_slice(&certificate);
        handles.push(handle);
    }
    frame(&mut t, AbsorbLabel::LookupMultiplicities, &bundle, attack);
    let pairs: Vec<[K; 2]> = (0..r)
        .map(|j| {
            t.absorb(AbsorbLabel::LookupRepetition, &phase(s.id, j, 0))
                .expect("pair frame");
            [
                t.challenge(ChallengeLabel::LookupBeta).expect("beta"),
                t.challenge(ChallengeLabel::LookupAlpha).expect("alpha"),
            ]
        })
        .collect();
    if c == 1 {
        assert!(pairs
            .iter()
            .all(|p| (0..=256).all(|i| p[1] != K::from_i64(i))));
    }
    if let Some(early) = early {
        assert_ne!(early, pairs[0][1]);
    }
    if attack == Attack::ReusePair {
        assert_ne!(pairs[0][1], pairs[1][1]);
    }
    let ids: Vec<_> = originals
        .iter()
        .map(|p| p.source().descriptor().id)
        .collect();
    let (mut trees, mut original_prefixes, mut claims_prefixes) =
        (Vec::new(), Vec::new(), Vec::new());
    let (mut value_offset, mut row_offset) = (0, 0);
    for j in 0..r {
        let [beta, alpha] = pairs[if attack == Attack::ReusePair && j == 1 {
            0
        } else {
            j
        }];
        t.absorb(AbsorbLabel::LookupRepetition, &phase(s.id, j, 1))
            .expect("tree phase");
        let tree_id = 4 * s.id + 2 * j as u64;
        let leaf_id = 8 * s.id + 4 * j as u64;
        let left = fraction::Descriptor::new(
            tree_id,
            u32::from(s.m),
            u32::from(s.b),
            [leaf_id, leaf_id + 1],
            &theta[j],
        )
        .expect("lookup tree");
        let k = n.trailing_zeros();
        let right = fraction::Descriptor::new(tree_id + 1, k, k, [leaf_id + 2, leaf_id + 3], &[])
            .expect("table tree");
        let leaves: Vec<_> = sigma
            .iter()
            .enumerate()
            .map(|(i, selected)| {
                let x = xs.iter().rev().fold(K::from_i64(0), |v, x| v * beta + x[i]);
                [
                    *selected,
                    K::from_i64(1) - *selected + *selected * (alpha - x),
                ]
            })
            .collect();
        let (proof, lookup) = left
            .prove(&leaves, &mut t)
            .expect("actual lookup tree producer");
        let left_root = proof.root;
        bytes.extend_from_slice(&proof.encode(&left).expect("lookup wire"));
        let mut leaves: Vec<_> = s
            .table
            .entries()
            .chunks_exact(c)
            .enumerate()
            .map(|(i, row)| {
                let x = row
                    .iter()
                    .rev()
                    .fold(K::from_i64(0), |v, x| v * beta + K::from_i64(i64::from(*x)));
                if i < real {
                    [mu[j][i], alpha - x]
                } else {
                    [K::from_i64(0), K::from_i64(1)]
                }
            })
            .collect();
        if attack == Attack::Pole {
            leaves[0][1] = K::from_i64(0);
        }
        let (proof, table) = right
            .prove(&leaves, &mut t)
            .expect("actual table tree producer");
        let root_check = fraction::check_roots(left_root, proof.root);
        if matches!(
            attack,
            Attack::Honest
                | Attack::Tail
                | Attack::Select
                | Attack::ReusePair
                | Attack::OmitStatement
                | Attack::OmitMultiplicities
                | Attack::OmitClaims
        ) {
            root_check.expect("actual root equation");
        }
        bytes.extend_from_slice(&proof.encode(&right).expect("table wire"));
        trees.push(t.usage());
        // Failed root/Table checks are deliberately not verifier calls here: a full
        // canonical adversarial artifact must reach the unchanged real verifier.
        let leaf = LeafDescriptor::new(&left, &ids).expect("leaf descriptor");
        let selected =
            SelectedProduct::new(leaf, &lookup, &sigma, alpha, beta).expect("selected inputs");
        let (proof, reduction) = selected
            .prove(&xs, &mut t)
            .expect("actual selected producer");
        bytes.extend_from_slice(&leaf.encode(&proof).expect("selected wire"));
        for (a, (id, value)) in reduction.claims.iter().enumerate() {
            bytes.extend_from_slice(
                &originals[a]
                    .opening_point(&mut t, s.originals[a], *id, &reduction.point, *value)
                    .expect("actual original opening")
                    .0,
            );
        }
        original_prefixes.push(t.usage());
        let ell = usize::from(s.multiplicities[j].ell);
        let width = n >> ell;
        let (q, tail) = (real / width, real % width);
        let (rw, cw) = (weights(&table.point[..ell]), weights(&table.point[ell..]));
        let basis: Vec<K> = (0..d)
            .map(|i| {
                let mut bytes = vec![0; 4 * d];
                bytes[4 * i] = 1;
                K::from_le_bytes(
                    K::Bytes::try_from(bytes.as_slice())
                        .ok()
                        .expect("basis width"),
                )
                .expect("basis")
            })
            .collect();
        let pieces: Vec<_> = (0..2u8)
            .filter(|id| if *id == 0 { q > 0 } else { tail > 0 })
            .map(|id| {
                let a: Vec<_> = rw
                    .iter()
                    .enumerate()
                    .map(|(u, w)| {
                        if (id == 0 && u < q) || (id == 1 && u == q) {
                            *w
                        } else {
                            K::from_i64(0)
                        }
                    })
                    .collect();
                let b: Vec<_> = cw
                    .iter()
                    .enumerate()
                    .flat_map(|(v, w)| {
                        basis.iter().map(move |basis| {
                            if id == 0 || v < tail {
                                *w * *basis
                            } else {
                                K::from_i64(0)
                            }
                        })
                    })
                    .collect();
                let value =
                    limbs[j]
                        .chunks_exact(b.len())
                        .zip(&a)
                        .fold(K::from_i64(0), |sum, (row, a)| {
                            sum + row.iter().zip(&b).fold(K::from_i64(0), |s, (x, b)| {
                                s + *a * *b * K::from_i64(i64::from(x.as_u32()))
                            })
                        });
                (id, a, b, value)
            })
            .collect();
        assert_eq!(
            pieces.iter().fold(K::from_i64(0), |v, p| v + p.3),
            table.claims[0].1
        );
        if j == 0 {
            value_offset = bytes.len();
        }
        let mut claims = phase(s.id, j, pieces.len() as u8);
        for v in table.point.iter().chain([&table.claims[0].1]) {
            claims.extend_from_slice(v.to_le_bytes().as_ref());
        }
        for (id, _, _, value) in &pieces {
            claims.push(*id);
            claims.extend_from_slice(value.to_le_bytes().as_ref());
            bytes.extend_from_slice(value.to_le_bytes().as_ref());
        }
        // Omit only the first Claims frame; other selected frames occur once.
        let omission = if j > 0 && attack == Attack::OmitClaims {
            Attack::Honest
        } else {
            attack
        };
        frame(
            &mut t,
            AbsorbLabel::LookupMultiplicityClaims,
            &claims,
            omission,
        );
        claims_prefixes.push(t.usage());
        for (piece_index, (id, a, b, value)) in pieces.iter().enumerate() {
            if j == 0 && piece_index == 0 {
                let column = b
                    .iter()
                    .position(|x| *x != K::from_i64(0))
                    .expect("nonzero expected b");
                row_offset = bytes.len() + 1 + 4 * d * column;
            }
            bytes.extend_from_slice(
                &prepared[j]
                    .opening(
                        &mut t,
                        &handles[j],
                        Functional {
                            id: u64::from(*id),
                            a,
                            b,
                            value: *value,
                        },
                    )
                    .expect("actual mu opening")
                    .0,
            );
        }
    }
    descriptor
        .preflight(&bytes)
        .expect("complete canonical adversarial wire");
    Packet {
        bytes,
        handles,
        transcript: t,
        trees,
        originals: original_prefixes,
        claims: claims_prefixes,
        value_offset,
        row_offset,
    }
}
