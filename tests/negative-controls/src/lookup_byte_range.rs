//! RFC-0024 §6 NC-0315: own false-source authority, even under a zero opposite factor.
use super::*;
use stele_reductions::byte_range;

const PREFIX: &[u8] = b"stele/v0.1/integer-linear/byte-range/v1";

pub(super) fn exercise<K: ChallengeField + CodeField + TableField + Eq + core::fmt::Debug>()
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    for (role, opposite) in [(10, 11), (11, 10)] {
        let zero = [M31::from_i64(128)];
        let zp = PreparedSource::<K>::new(opposite, 0, 0, 1, &zero, &mut HashUsage::default())
            .expect("valid fixed fixture");
        let zc = verify_certificate(
            *zp.source(),
            &zp.certificate().expect("produce genuine certificate").0,
        )
        .expect("valid fixed fixture")
        .0;
        let zd =
            byte_range::Descriptor::new(&zc, 8, &[22, 23], LIMITS).expect("valid fixed fixture");
        let (zw, _) = zd
            .prove(
                &zp,
                ProducerLimits {
                    public_bytes: zd.producer_public_bytes().expect("public admission"),
                    dense_elements: zd.producer_dense_elements().expect("dense admission"),
                },
            )
            .expect("valid fixed fixture");
        let (zm, _) = zd
            .register_multiplicities(&zw, LIMITS.public_bytes)
            .expect("valid fixed fixture");
        let zr: Vec<_> = zm.iter().collect();
        let zero_range = zd.verify(&zr, &zw).expect("valid fixed fixture");
        assert_eq!(zp.message()[0] - M31::from_i64(128), M31::from_i64(0));
        assert_eq!(
            zero_range.original().record().source().descriptor().id,
            opposite
        );

        let mut false_byte = 7;
        Outside.tamper(&mut false_byte); // The only declared deviation; all work below is rebuilt.
        for byte in [7, false_byte] {
            let message = [M31::from_i64(byte)];
            let p = PreparedSource::<K>::new(role, 0, 0, 1, &message, &mut HashUsage::default())
                .expect("valid fixed fixture");
            let c = verify_certificate(
                *p.source(),
                &p.certificate().expect("produce genuine certificate").0,
            )
            .expect("valid fixed fixture")
            .0;
            let d =
                byte_range::Descriptor::new(&c, 7, &[20, 21], LIMITS).expect("valid fixed fixture");
            let table = Table::range(8).expect("valid fixed fixture");
            let originals = [&c];
            let layouts = [20, 21].map(|id| Layout {
                id,
                ell: 0,
                blowup: 1,
            });
            let s = Statement {
                id: 7,
                m: 0,
                b: 0,
                table: &table,
                selector: &[1],
                originals: &originals,
                multiplicities: &layouts,
            };
            let a5 = Descriptor::new(s, LIMITS).expect("valid fixed fixture");
            // Ordinary histogram gives zero for 256, with genuine A3/A9 dependent work.
            // Outside permits the expected failed root check in this test composer;
            // the genuine source fixed above is its only changed input.
            let packet = composer::compose_with_public_input(
                &a5,
                s,
                &[&p],
                if byte == 7 {
                    Attack::Honest
                } else {
                    Attack::Outside
                },
                PREFIX,
            );
            let (owners, imports) = d
                .register_multiplicities(&packet.bytes, LIMITS.public_bytes)
                .expect("valid fixed fixture");
            assert!(imports.iter().all(Option::is_some));
            let refs: Vec<_> = owners.iter().collect();
            if byte == 7 {
                let (wire, usage) = d
                    .prove(
                        &p,
                        ProducerLimits {
                            public_bytes: d.producer_public_bytes().expect("public admission"),
                            dense_elements: d.producer_dense_elements().expect("dense admission"),
                        },
                    )
                    .expect("valid fixed fixture");
                assert_eq!(wire, packet.bytes);
                let accepted = d.verify(&refs, &wire).expect("valid fixed fixture");
                assert_eq!(accepted.usage().transcript, usage.transcript);
                assert!(core::ptr::eq(accepted.original(), &c));
            } else {
                let failure = d
                    .verify(&refs, &packet.bytes)
                    .err()
                    .expect("actual false-byte rejection");
                assert_eq!(
                    failure.cause,
                    Error::Fraction(stele_lookup::fraction::Error::RootMismatch)
                );
                assert_eq!(failure.usage.transcript, packet.trees[0]);
                assert_eq!(
                    failure.usage.non_transcript,
                    HashUsage {
                        hash_evaluations: 3,
                        ..HashUsage::default()
                    }
                );
            }
        }
    }
}
