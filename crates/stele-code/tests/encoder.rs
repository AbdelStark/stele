//! Native identity/map checks, RFC-0010 A4; no PCS or profile admission.
use core::fmt::Debug;
use stele_code::{Circle, Code, CodeField, Encoder, Error};
use stele_field::{CM31, M31, OM31, QM31};

fn manifest(j: u8) -> [u8; 55] {
    let mut id = [0; 55];
    id[..22].copy_from_slice(b"stele/expander-seed/v2");
    id[22] = j;
    id[23] = j;
    id
}
fn limb(i: usize, k: usize) -> M31 {
    M31::from_u64((17 * i + 29 * k + 1) as u64)
}
fn qm(i: usize) -> QM31 {
    QM31(CM31(limb(i, 0), limb(i, 1)), CM31(limb(i, 2), limb(i, 3)))
}
fn om(i: usize) -> OM31 {
    OM31(
        qm(i),
        QM31(CM31(limb(i, 4), limb(i, 5)), CM31(limb(i, 6), limb(i, 7))),
    )
}

fn parity<K: CodeField + Eq + Debug>(j: u8, expected: &str, element: fn(usize) -> K) {
    let id = manifest(j);
    let code = Encoder::from_code_id(&id).expect("identity");
    assert_eq!(code.code_id(), id);
    let info = code.info();
    let n = usize::try_from(info.message_len).expect("small length");
    let row: Vec<_> = (0..n).map(element).collect();
    let original = row.clone();
    let word = code.encode(&row).expect("word");
    assert_eq!(row, original);
    let mut hash = blake3::Hasher::new();
    for value in &word {
        hash.update(value.to_le_bytes().as_ref());
    }
    assert_eq!(hash.finalize().to_hex().as_str(), expected);
    assert_eq!(word.len(), 2 * n);
    if j > 3 {
        assert_eq!(&word[..n], row);
    } else {
        assert_eq!(
            word,
            Circle::new(6, 1)
                .expect("base")
                .encode(&row)
                .expect("base word")
        );
    }
    let cols = [2 * n - 1, 0, n, 0];
    assert_eq!(
        code.eval_row(&row, &cols).expect("query"),
        cols.map(|i| word[i])
    );
    assert!(code.eval_row(&row, &[]).expect("empty").is_empty());
    assert_eq!(code.encode(&row[..n - 1]), Err(Error::RowShape));
    assert_eq!(code.eval_row(&row, &[2 * n]), Err(Error::Column));
    let scale = element(7);
    let other: Vec<_> = (n..2 * n).map(element).collect();
    let combined: Vec<_> = row
        .iter()
        .zip(&other)
        .map(|(a, b)| *a + scale * *b)
        .collect();
    let encoded_other = code.encode(&other).expect("other");
    assert_eq!(
        code.encode(&combined).expect("linear"),
        word.iter()
            .zip(encoded_other)
            .map(|(a, b)| *a + scale * b)
            .collect::<Vec<_>>()
    );
    let zeros = vec![K::from_i64(0); n];
    assert_eq!(
        code.encode(&zeros).expect("zero"),
        vec![K::from_i64(0); 2 * n]
    );
}

#[test]
fn matches_reference_materialized_codeword_digests() {
    assert_eq!(include_str!("encoder-vectors.txt").lines().count(), 10);
    for line in include_str!("encoder-vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let parts: Vec<_> = line.split_whitespace().collect();
        let j = parts[0].parse().expect("exponent");
        match parts[1] {
            "1" => parity(j, parts[2], |i| limb(i, 0)),
            "4" => parity(j, parts[2], qm),
            "8" => parity(j, parts[2], om),
            other => assert!(["1", "4", "8"].contains(&other)),
        }
    }
}

#[test]
fn accepts_exact_identities_and_derived_information() {
    for j in 3..=15 {
        let id = manifest(j);
        let code = Encoder::from_code_id(&id).expect("identity");
        let n = 1u64 << (2 * j);
        assert_eq!(code.info().message_len, n);
        assert_eq!(code.info().codeword_len, 2 * n);
        assert_eq!(code.info().row_count, 2 * n - 128);
        assert_eq!(code.code_id(), id);
    }
    for b in [1, 2] {
        for m in 0..=30 - b {
            let circle = Circle::new(m, b).expect("circle");
            let code = Encoder::from_code_id(&circle.code_id()).expect("identity");
            assert_eq!(code.info().message_len, 1 << m);
            assert_eq!(code.info().codeword_len, 1 << (m + b));
            assert_eq!(code.info().sparse_edges, 0);
            assert_eq!(code.info().row_count, 0);
        }
    }
    let circle = Circle::new(3, 2).expect("circle");
    let code = Encoder::from_code_id(&circle.code_id()).expect("id");
    let row: Vec<_> = (0..8).map(om).collect();
    assert_eq!(code.encode(&row), circle.encode(&row));
    assert_eq!(
        code.eval_row(&row, &[31, 0, 0]),
        circle.eval_row(&row, &[31, 0, 0])
    );
}

#[test]
fn rejects_malformed_code_identities() {
    let id = manifest(4);
    for end in 0..id.len() {
        assert!(matches!(
            Encoder::from_code_id(&id[..end]),
            Err(Error::InvalidCodeId)
        ));
    }
    for (at, value) in [(0, 0), (21, b'1'), (22, 2), (22, 16)] {
        let mut wrong = id;
        wrong[at] = value;
        assert!(matches!(
            Encoder::from_code_id(&wrong),
            Err(Error::InvalidCodeId)
        ));
    }
    for bytes in [
        b"stele/expander-m31/v2".as_slice(),
        b"stele/circle-m31/v1\x1e\x01",
        b"stele/circle-m31/v1\x00\x00",
    ] {
        assert!(matches!(
            Encoder::from_code_id(bytes),
            Err(Error::InvalidCodeId)
        ));
    }
    let mut extra = id.to_vec();
    extra.push(0);
    assert!(matches!(
        Encoder::from_code_id(&extra),
        Err(Error::InvalidCodeId)
    ));
}
