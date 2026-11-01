//! RFC-0008 A5 / native-lookup §§1,3,5,6: expected bytes and untrusted parsing only.
use stele_field::{Field, M31, OM31, QM31};
use stele_hash::{ChallengeField, HashUsage};
use stele_lookup::fraction;
use stele_pcs::{
    verify_certificate, CodeField, PreparedSource, ProofKind, Source, VerifiedCertificate,
};
use stele_reductions::lookup::{
    Descriptor, Error, Layout, Limits, Statement, Table, TableDescriptor,
};

const LIMITS: Limits = Limits {
    positions: 16,
    public_bytes: 16_000_000,
    proof_bytes: 16_000_000,
};

fn originals<K: ChallengeField + CodeField>(m: u8, count: usize) -> Vec<VerifiedCertificate<K>>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    (0..count)
        .map(|i| {
            let message = vec![M31::from_i64(0); 1 << m];
            let ell = if i == 0 { m } else { 0 };
            let p = PreparedSource::<K>::new(
                2 + i as u64,
                ell,
                m - ell,
                1,
                &message,
                &mut HashUsage::default(),
            )
            .expect("actual original preparation");
            let (bytes, _) = p.certificate().expect("actual certificate producer");
            verify_certificate(*p.source(), &bytes)
                .expect("actual registration")
                .0
        })
        .collect()
}

fn statement<'a, 'cert, K: ChallengeField>(
    table: &'a Table,
    selector: &'a [u8],
    originals: &'a [&'cert VerifiedCertificate<K>],
    layouts: &'a [Layout],
) -> Statement<'a, 'cert, K> {
    Statement {
        id: 7,
        m: selector.len().trailing_zeros() as u8,
        b: 0,
        table,
        selector,
        originals,
        multiplicities: layouts,
    }
}

#[derive(Default)]
struct WireFixture {
    bytes: Vec<u8>,
    arithmetic: Vec<usize>,
    rows: Vec<usize>,
    pieces: Vec<usize>,
    responses: Vec<usize>,
    versions: Vec<usize>,
    local_hashes: u64,
}
fn packet<K: ChallengeField>(f: &mut WireFixture, source: &Source<K>, kind: ProofKind) {
    let start = f.bytes.len();
    f.versions.push(start);
    f.rows.push(start + 1);
    f.responses
        .push(start + 1 + source.columns() * 4 * K::DEGREE);
    f.bytes
        .resize(start + source.proof_size(kind).expect("actual A9 size"), 0);
    f.bytes[start] = 1;
    if kind == ProofKind::Opening {
        // Enumerate every emitted path's hash budget; this executes no hash.
        for _ in 0..source.queries(kind) {
            f.local_hashes += 1 + source.path_height() as u64;
        }
    }
}
// Canonical shape only: these zero packets deliberately authenticate/prove nothing.
fn wire<K: ChallengeField>(s: Statement<'_, '_, K>, d: &Descriptor<'_, '_, K>) -> WireFixture {
    let mut f = WireFixture {
        bytes: vec![1, K::DEGREE as u8],
        local_hashes: 1 + s.multiplicities.len() as u64,
        ..WireFixture::default()
    };
    let k = s.table.descriptor().shape().padded().trailing_zeros();
    let t = s.table.descriptor().shape().rows() as usize;
    for j in 0..s.multiplicities.len() {
        f.bytes.extend_from_slice(&[j as u8; 32]);
        packet(
            &mut f,
            &d.multiplicity_source(j, [j as u8; 32]).expect("mu source"),
            ProofKind::Certificate,
        );
    }
    let ids: Vec<_> = s
        .originals
        .iter()
        .map(|c| c.record().source().descriptor().id)
        .collect();
    let tree = fraction::Descriptor::<K>::new(
        4 * s.id,
        u32::from(s.m),
        u32::from(s.b),
        [8 * s.id, 8 * s.id + 1],
        &vec![K::from_i64(0); usize::from(s.m - s.b)],
    )
    .expect("shape");
    let table_tree =
        fraction::Descriptor::<K>::new(4 * s.id + 1, k, k, [8 * s.id + 2, 8 * s.id + 3], &[])
            .expect("shape");
    let leaf = fraction::LeafDescriptor::new(&tree, &ids).expect("shape");
    for (j, layout) in s.multiplicities.iter().enumerate() {
        for size in [
            tree.proof_size().expect("tree"),
            table_tree.proof_size().expect("table tree"),
            leaf.proof_size().expect("leaf"),
        ] {
            f.arithmetic
                .extend([f.bytes.len(), f.bytes.len() + size - 4]);
            f.bytes.resize(f.bytes.len() + size, 0);
        }
        for c in s.originals {
            packet(&mut f, c.record().source(), ProofKind::Opening);
        }
        let columns = 1usize << (k - u32::from(layout.ell));
        let count = usize::from(t / columns > 0) + usize::from(!t.is_multiple_of(columns));
        for _ in 0..count {
            f.pieces.push(f.bytes.len());
            f.bytes.resize(f.bytes.len() + 4 * K::DEGREE, 0);
        }
        for _ in 0..count {
            packet(
                &mut f,
                &d.multiplicity_source(j, [j as u8; 32]).expect("mu source"),
                ProofKind::Opening,
            );
        }
    }
    f
}

fn encoding<K: ChallengeField + CodeField>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    for table in [
        Table::range(8).expect("range"),
        Table::generate(TableDescriptor::new("exp_q/hi", 1, &[7, 0, 0, 6]).expect("descriptor"))
            .expect("partial table"),
        Table::generate(TableDescriptor::new("exp_q/direct", 1, &[7, 0, 0]).expect("descriptor"))
            .expect("signed table"),
    ] {
        let c = usize::from(table.descriptor().shape().columns());
        for m in [0u8, 2] {
            let owned = originals::<K>(m, c);
            let handles: Vec<_> = owned.iter().collect();
            let selector = vec![1; 1 << m];
            let mut layouts = [
                Layout {
                    id: 10,
                    ell: 1,
                    blowup: 1,
                },
                Layout {
                    id: 11,
                    ell: 0,
                    blowup: 2,
                },
            ];
            for (r, b) in [(1, 0), (2, m)] {
                layouts[0].ell = if r == 1 {
                    table.descriptor().shape().padded().trailing_zeros() as u8
                } else {
                    1
                };
                let s = Statement {
                    b,
                    ..statement(&table, &selector, &handles, &layouts[..r])
                };
                let d = Descriptor::new(s, LIMITS).expect("checked expected statement");
                let mut hashes = HashUsage::default();
                let bytes = d.encode(&mut hashes).expect("statement encoding");
                assert_eq!(
                    hashes,
                    HashUsage {
                        hash_evaluations: 1,
                        ..HashUsage::default()
                    }
                );
                let metadata = table.descriptor().encode().expect("canonical descriptor");
                let data = table.encode().expect("independent expected Table bytes");
                let shape = table.descriptor().shape();
                let mut expected = vec![1, usize::from(<K as CodeField>::DEGREE) as u8];
                expected.extend_from_slice(&7u64.to_le_bytes());
                expected.extend_from_slice(&[m, b, r as u8, c as u8]);
                expected.extend_from_slice(&shape.rows().to_le_bytes());
                expected.push(shape.padded().trailing_zeros() as u8);
                for part in [metadata.as_bytes(), &data] {
                    expected.extend_from_slice(&(part.len() as u32).to_le_bytes());
                    expected.extend_from_slice(part);
                }
                expected.extend_from_slice(&(selector.len() as u64).to_le_bytes());
                expected.extend_from_slice(&selector);
                for handle in &handles {
                    expected.extend_from_slice(&handle.record().source().bytes());
                    expected.extend_from_slice(&handle.record().id());
                }
                for layout in &layouts[..r] {
                    expected.extend_from_slice(&layout.id.to_le_bytes());
                    expected.extend_from_slice(&[layout.ell, layout.blowup]);
                }
                assert_eq!(bytes, expected);
                assert_eq!(
                    d.statement_size(),
                    35 + metadata.as_bytes().len() + data.len() + selector.len() + 137 * c + 10 * r
                );
                assert_eq!(bytes.len(), d.statement_size());
                let fixture = wire(s, &d);
                assert_eq!(fixture.bytes.len(), d.proof_size());
                assert_eq!(fixture.local_hashes, d.max_local_hashes());
                d.preflight(&fixture.bytes)
                    .expect("complete canonical wire, not membership");
                hashes.hash_evaluations = u64::MAX - 1;
                assert_eq!(d.encode(&mut hashes).expect("last count"), bytes);
                assert_eq!(hashes.hash_evaluations, u64::MAX);
                assert_eq!(d.encode(&mut hashes).err(), Some(Error::Capacity));
                assert_eq!(hashes.hash_evaluations, u64::MAX);
            }
        }
    }
}

fn malformed<K: ChallengeField + CodeField>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let table =
        Table::generate(TableDescriptor::new("exp_q/hi", 1, &[7, 0, 0, 6]).expect("descriptor"))
            .expect("table");
    let owned = originals::<K>(2, 2);
    let handles: Vec<_> = owned.iter().collect();
    let layouts = [
        Layout {
            id: 10,
            ell: 1,
            blowup: 1,
        },
        Layout {
            id: 11,
            ell: 0,
            blowup: 2,
        },
    ];
    let selector = [1, 0, 1, 0];
    let s = statement(&table, &selector, &handles, &layouts);
    for (changed, error) in [
        (Statement { id: 1 << 60, ..s }, Error::Statement),
        (Statement { m: 60, ..s }, Error::Statement),
        (Statement { m: 31, b: 31, ..s }, Error::GroupBound),
        (
            Statement {
                selector: &[1, 2, 1, 0],
                ..s
            },
            Error::Selector,
        ),
        (
            Statement {
                selector: &selector[..3],
                ..s
            },
            Error::Selector,
        ),
        (
            Statement {
                originals: &handles[..1],
                ..s
            },
            Error::SourceRoster,
        ),
        (
            Statement {
                multiplicities: &[],
                ..s
            },
            Error::Statement,
        ),
    ] {
        assert_eq!(Descriptor::new(changed, LIMITS).err(), Some(error));
    }
    for invalid in [
        Layout {
            id: 2,
            ..layouts[0]
        },
        Layout {
            id: 11,
            ..layouts[0]
        },
    ] {
        let bad = [invalid, layouts[1]];
        assert_eq!(
            Descriptor::new(
                Statement {
                    multiplicities: &bad,
                    ..s
                },
                LIMITS
            )
            .err(),
            Some(Error::SourceRoster)
        );
    }
    for invalid in [
        Layout {
            ell: 3,
            ..layouts[0]
        },
        Layout {
            blowup: 0,
            ..layouts[0]
        },
    ] {
        let bad = [invalid, layouts[1]];
        assert_eq!(
            Descriptor::new(
                Statement {
                    multiplicities: &bad,
                    ..s
                },
                LIMITS
            )
            .err(),
            Some(Error::Statement)
        );
    }
    let d = Descriptor::new(s, LIMITS).expect("descriptor");
    Descriptor::new(
        s,
        Limits {
            positions: 4,
            public_bytes: d.public_bytes(),
            proof_bytes: d.proof_size(),
        },
    )
    .expect("exact caps");
    Descriptor::new(
        Statement {
            id: (1 << 60) - 1,
            ..s
        },
        LIMITS,
    )
    .expect("largest lookup id");
    for limits in [
        Limits {
            positions: 3,
            ..LIMITS
        },
        Limits {
            public_bytes: d.public_bytes() - 1,
            ..LIMITS
        },
        Limits {
            proof_bytes: d.proof_size() - 1,
            ..LIMITS
        },
    ] {
        assert_eq!(Descriptor::new(s, limits).err(), Some(Error::ResourceLimit));
    }

    let WireFixture {
        bytes,
        arithmetic,
        rows,
        pieces,
        responses,
        versions,
        local_hashes,
    } = wire(s, &d);
    assert_eq!(local_hashes, d.max_local_hashes());
    assert_eq!(bytes.len(), d.proof_size());
    d.preflight(&bytes).expect("canonical unverified shape");
    for length in [0, 1, bytes.len() - 1] {
        assert_eq!(d.preflight(&bytes[..length]), Err(Error::ProofShape));
    }
    for offset in [0, 1] {
        let mut bad = bytes.clone();
        bad[offset] = 0;
        assert_eq!(d.preflight(&bad), Err(Error::ProofShape));
    }
    for offset in versions {
        assert_eq!(d.preflight(&bytes[..offset]), Err(Error::ProofShape));
        let mut bad = bytes.clone();
        bad[offset] = 0;
        assert_eq!(
            d.preflight(&bad),
            Err(Error::Pcs(stele_pcs::Error::ProofShape))
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(d.preflight(&trailing), Err(Error::ProofShape));
    for (offsets, error) in [
        (
            arithmetic,
            Error::Fraction(fraction::Error::NoncanonicalField),
        ),
        (rows, Error::Pcs(stele_pcs::Error::NoncanonicalField)),
        (pieces, Error::ProofShape),
    ] {
        for offset in offsets {
            let mut bad = bytes.clone();
            bad[offset..offset + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
            assert_eq!(d.preflight(&bad), Err(error));
        }
    }
    for offset in responses {
        let mut unauthenticated = bytes.clone();
        unauthenticated[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        d.preflight(&unauthenticated)
            .expect("response decoding belongs after actual authentication");
    }
}

#[test]
fn matches_reference_qm31_lookup_statement() {
    encoding::<QM31>();
}
#[test]
fn matches_reference_om31_lookup_statement() {
    encoding::<OM31>();
}
#[test]
fn rejects_qm31_lookup_shape_and_limits() {
    malformed::<QM31>();
}
#[test]
fn rejects_om31_lookup_shape_and_limits() {
    malformed::<OM31>();
}
