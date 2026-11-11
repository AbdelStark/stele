//! RFC-0010 A1 acceptance resolution: derived parameters, fail-closed resolver, exact export.
#![forbid(unsafe_code)]
use stele_code::registry::{self, check_export, parameters, resolve_pcs, Profile, CATALOG_EXPORT};
use stele_code::{Encoder, Error};

fn circle(m: u8, b: u8) -> Vec<u8> {
    [&b"stele/circle-m31/v1"[..], &[m, b]].concat()
}
fn expander(j: u8, seed: u8) -> Vec<u8> {
    [&b"stele/expander-seed/v2"[..], &[j], &[seed; 32]].concat()
}
fn supported() -> Vec<Vec<u8>> {
    let circles = (1..=2u8).flat_map(|b| (0..=30 - b).map(move |m| circle(m, b)));
    circles.chain((3..=15).map(|j| expander(j, 7))).collect()
}

#[test]
fn accepts_derived_parameters_for_every_supported_identity() {
    let ids = supported();
    assert_eq!(ids.len(), 59 + 13);
    for id in &ids {
        let p = parameters(&Encoder::from_code_id(id).expect("supported identity"));
        let (k, n) = (p.message_len, p.codeword_len);
        if id.len() == 21 {
            assert_eq!((k, n), (1 << id[19], 1 << (id[19] + id[20])));
            assert_eq!(p.distance_lower_bound, if k == 1 { n } else { n - k });
            assert_eq!(p.distance_evidence, "rfc-0010-a2/root-bound-v1");
            assert_eq!((p.setup_loss_numerator, p.setup_evidence), (0, None));
        } else {
            let j = id[22];
            assert_eq!((k, n), (1 << (2 * j), 2 << (2 * j)));
            assert_eq!(p.distance_evidence, "rfc-0010-a1/finite-v2");
            if j == 3 {
                assert_eq!((p.distance_lower_bound, p.setup_loss_numerator), (64, 0));
                assert_eq!(p.setup_evidence, None);
            } else {
                assert_eq!(p.distance_lower_bound, k / 25 + 1);
                assert_eq!(
                    (p.setup_loss_numerator, p.setup_loss_log2_denominator),
                    (200_431_782, 160)
                );
                assert_eq!(p.setup_evidence, Some("rfc-0012-a7/2^256-all-seeds-v2"));
            }
        }
    }
    // Same parameters, distinct seeds: the identity, not the parameter tuple, names the map.
    let (a, b) = (expander(5, 1), expander(5, 2));
    let (ea, eb) = (
        Encoder::from_code_id(&a).expect("seed 1"),
        Encoder::from_code_id(&b).expect("seed 2"),
    );
    assert_eq!(parameters(&ea), parameters(&eb));
    assert_ne!(
        stele_code::Code::code_id(&ea),
        stele_code::Code::code_id(&eb)
    );
}

#[test]
fn accepts_policy2_only_for_standard_extension_requests() {
    for id in supported() {
        for degree in [4, 8] {
            let j15 = id.len() != 21 && id[22] == 15;
            let resolved = resolve_pcs(&id, degree, Profile::Standard);
            if j15 {
                // A3 item 2: J = 15 exceeds the sampler domain; A14 has no entry.
                assert_eq!(resolved, Err(Error::UnsupportedParameters));
                continue;
            }
            let p = resolved.expect("A14 item 6 admits standard Policy 2");
            assert_eq!((p.policy, p.column_grind_bits, p.proven), (2, 16, true));
            assert!(p.certificate_queries >= p.opening_queries && p.opening_queries >= 1);
        }
        for degree in [1, 4, 8] {
            assert_eq!(
                resolve_pcs(&id, degree, Profile::Treaty),
                Err(Error::UnsupportedParameters)
            );
        }
        assert_eq!(
            resolve_pcs(&id, 1, Profile::Standard),
            Err(Error::UnsupportedParameters)
        );
        for degree in [0, 2, 3, 5, 16] {
            assert_eq!(
                resolve_pcs(&id, degree, Profile::Treaty),
                Err(Error::FieldMismatch)
            );
        }
    }
    // Every RFC-0010 A14 item 2 row, recomputed from the exact inequality by
    // research/merkle-oracle/check_policy2_wire.py, in both extension degrees.
    let mut rows = 0;
    for line in include_str!("policy2-tables.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let n = |i: usize| f[i].parse::<u16>().expect("fixture integer");
        let (id, counts) = match f[0] {
            "circle" => (circle(n(1) as u8, n(2) as u8), (n(3), n(4))),
            _ => (expander(n(1) as u8, 7), (n(2), n(3))),
        };
        for degree in [4, 8] {
            let p = resolve_pcs(&id, degree, Profile::Standard).expect("admitted");
            assert_eq!((p.certificate_queries, p.opening_queries), counts, "{line}");
        }
        rows += 1;
    }
    assert_eq!(rows, 59 + 12);
    for bad in [
        circle(30, 1),
        circle(5, 3),
        expander(16, 0),
        expander(2, 0),
        b"".to_vec(),
    ] {
        assert_eq!(
            resolve_pcs(&bad, 4, Profile::Standard),
            Err(Error::InvalidCodeId)
        );
    }
}

#[test]
fn matches_reference_research_registry_export() {
    let research = include_str!("../../../research/code-provenance/codes.toml");
    assert_eq!(research, CATALOG_EXPORT);
    assert_eq!(check_export(research.as_bytes()), Ok(()));
    assert!(CATALOG_EXPORT.contains("setup_loss_numerator = 200431782"));
    assert_eq!(registry::EXPANDER_SETUP_LOSS_NUMERATOR, 200_431_782);
}

#[test]
fn rejects_edited_registry_exports() {
    let exact = CATALOG_EXPORT.as_bytes();
    for edited in [
        CATALOG_EXPORT.replacen("proven = false", "proven = true", 1),
        CATALOG_EXPORT.replace("finite-v2", "finite-v3"),
        CATALOG_EXPORT.replace("200431782", "200431781"),
        CATALOG_EXPORT.replace("version = 1", "version = 2"),
        format!("{CATALOG_EXPORT}\n"),
    ] {
        assert_eq!(check_export(edited.as_bytes()), Err(Error::InvalidRegistry));
    }
    for i in 0..exact.len() {
        let mut edited = exact.to_vec();
        edited[i] ^= 1;
        assert_eq!(check_export(&edited), Err(Error::InvalidRegistry));
    }
    assert_eq!(
        check_export(&exact[..exact.len() - 1]),
        Err(Error::InvalidRegistry)
    );
}
