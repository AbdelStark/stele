//! RFC-0021 §4: expected function closure and mandatory table regeneration.
use stele_cqis::functions::{Descriptor, Error, Manifest, Representation};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../research/cqis-tables/function-identity-candidates.json"
    ))
    .expect("independent Python manifest")
}

fn selections() -> Vec<Representation> {
    let data = fixtures();
    [0, 2, 3, 4]
        .into_iter()
        .map(|i| {
            let r = &data["representations"][i];
            let f = data["functions"]
                .as_array()
                .expect("functions")
                .iter()
                .find(|f| f["name"] == r["function"])
                .expect("function");
            let f = Descriptor::decode(&hex(f["descriptor"].as_str().expect("descriptor")))
                .expect("metadata");
            Representation::new(
                f,
                r["mode"].as_u64().expect("mode") as u8,
                &hex(r["parameters"].as_str().expect("params")),
            )
            .expect("selection")
        })
        .collect()
}

fn inspect(raw: &[u8]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    fn take<'a>(raw: &mut &'a [u8], n: usize) -> &'a [u8] {
        let (part, rest) = raw.split_at(n);
        *raw = rest;
        part
    }
    fn u32le(raw: &mut &[u8]) -> u32 {
        u32::from_le_bytes(take(raw, 4).try_into().expect("u32"))
    }
    fn sized<'a>(raw: &mut &'a [u8]) -> &'a [u8] {
        let n = u16::from_le_bytes(take(raw, 2).try_into().expect("u16"));
        take(raw, usize::from(n))
    }
    let mut raw = raw
        .strip_prefix(b"stele/v0.1/cqis/functions")
        .expect("prefix");
    let mut functions = Vec::new();
    for _ in 0..u32le(&mut raw) {
        let f = Descriptor::decode(sized(&mut raw)).expect("function");
        let r = Representation::decode(f, sized(&mut raw)).expect("complete roles");
        assert_eq!(r.function(), &f);
        functions.push(f.identity().expect("id"));
    }
    let mut components = Vec::new();
    for _ in 0..u32le(&mut raw) {
        let d = stele_cqis::tables::Descriptor::decode(sized(&mut raw)).expect("component");
        components.push(d.identity().expect("id"));
        take(&mut raw, 32);
    }
    assert!(raw.is_empty());
    assert!(functions.windows(2).all(|p| p[0] < p[1]));
    assert!(components.windows(2).all(|p| p[0] < p[1]));
    (functions, components)
}

#[test]
fn matches_reference_complete_manifest_and_rejects_every_changed_byte() {
    let mut selected = selections();
    let before = selected.clone();
    let manifest = Manifest::new(&selected).expect("regenerated closure");
    assert_eq!(selected, before);
    let reference = fixtures();
    let expected = hex(reference["manifest"]["bytes"].as_str().expect("bytes"));
    assert_eq!(manifest.as_bytes(), expected);
    assert_eq!(
        blake3::hash(manifest.as_bytes()).to_hex().as_str(),
        reference["manifest"]["digest"].as_str().expect("digest")
    );
    assert_eq!(manifest.validate_encoding(&expected), Ok(()));
    let (functions, components) = inspect(manifest.as_bytes());
    assert_eq!(functions.len(), 4);
    assert_eq!(components.len(), 7);
    selected.reverse();
    assert_eq!(Manifest::new(&selected).expect("permuted input"), manifest);
    for i in 0..expected.len() {
        let mut bad = expected.clone();
        bad[i] ^= 1;
        assert_eq!(
            manifest.validate_encoding(&bad),
            Err(Error::Manifest),
            "byte {i}"
        );
    }
    for end in 0..expected.len() {
        assert_eq!(
            manifest.validate_encoding(&expected[..end]),
            Err(Error::Manifest)
        );
    }
    let mut bad = expected.clone();
    bad.push(0);
    assert_eq!(manifest.validate_encoding(&bad), Err(Error::Manifest));
    let omitted = Manifest::new(&selected[..3]).expect("different expected set");
    assert_eq!(
        manifest.validate_encoding(omitted.as_bytes()),
        Err(Error::Manifest)
    );
    let direct = Representation::new(*before[1].function(), 0, &[]).expect("same nearest function");
    let changed = Manifest::new(&[before[0], direct, before[2], before[3]])
        .expect("other selected representation");
    assert_eq!(
        manifest.validate_encoding(changed.as_bytes()),
        Err(Error::Manifest)
    );
}

#[test]
fn accepts_empty_manifest_and_exact_shared_component_union() {
    let empty = Manifest::new(&[]).expect("empty");
    let mut expected = b"stele/v0.1/cqis/functions".to_vec();
    expected.extend_from_slice(&[0; 8]);
    assert_eq!(empty.as_bytes(), expected);
    assert_eq!(inspect(empty.as_bytes()), (vec![], vec![]));
    let product = Representation::new(
        Descriptor::new("exp_q/product", 1, &[7, 10, 12, 6]).expect("product"),
        1,
        &[],
    )
    .expect("product roles");
    let nearest = Representation::new(
        Descriptor::new("exp_q/nearest", 1, &[7, 10, 12]).expect("nearest"),
        2,
        &[6],
    )
    .expect("corrected roles");
    let manifest = Manifest::new(&[product, nearest]).expect("shared high/low");
    let (functions, components) = inspect(manifest.as_bytes());
    assert_eq!((functions.len(), components.len()), (2, 3));
    let p = [8, 0, 8, 8, 8, 1, 0, 0, 0, 160, 134, 1, 0];
    let n1 = Representation::new(Descriptor::new("rmsnorm_q", 1, &p).expect("norm"), 3, &[])
        .expect("norm role");
    let mut p2 = p;
    p2[0] = 16;
    let n2 = Representation::new(
        Descriptor::new("rmsnorm_q", 1, &p2).expect("other norm"),
        3,
        &[],
    )
    .expect("shared rsqrt");
    let (functions, components) = inspect(Manifest::new(&[n1, n2]).expect("norm set").as_bytes());
    assert_eq!((functions.len(), components.len()), (2, 1));
}

#[test]
fn accepts_generation_dispatch_for_all_registered_components() {
    use stele_cqis::tables::{Descriptor as TableDescriptor, Table};
    for (name, p) in [
        ("exp_q/hi", &[7, 0, 0, 7][..]),
        ("exp_q/lo", &[7, 0, 0, 7][..]),
        ("exp_q/direct", &[7, 0, 0][..]),
        ("exp_q/correction", &[7, 0, 0, 7][..]),
        ("sigmoid_q", &[0, 0][..]),
        ("silu_q", &[0, 0][..]),
        ("gelu_q", &[0, 0][..]),
        ("gelu_tanh_q", &[0, 0][..]),
        ("softcap_q", &[0, 0, 1, 0, 0][..]),
        ("rsqrt_q", &[][..]),
        ("range_8", &[][..]),
        ("range_12", &[][..]),
        ("range_16", &[][..]),
    ] {
        let d = TableDescriptor::new(name, 1, p).expect("descriptor");
        let table = Table::generate(d).expect("complete definition");
        assert_eq!(table.descriptor(), &d);
        assert_eq!(
            table.entries().len(),
            d.shape().padded() as usize * usize::from(d.shape().columns())
        );
    }
}

#[test]
fn rejects_duplicate_function_even_with_a_different_representation() {
    let f = Descriptor::new("exp_q/nearest", 1, &[7, 10, 12]).expect("function");
    let direct = Representation::new(f, 0, &[]).expect("direct");
    let corrected = Representation::new(f, 2, &[6]).expect("corrected");
    assert_eq!(
        Manifest::new(&[direct, direct]),
        Err(Error::DuplicateFunction)
    );
    assert_eq!(
        Manifest::new(&[direct, corrected]),
        Err(Error::DuplicateFunction)
    );
}

#[test]
fn rejects_manifest_when_a_whole_component_table_overflows() {
    let f = Descriptor::new("silu_q", 1, &[0, 14]).expect("valid metadata");
    let r = Representation::new(f, 0, &[]).expect("valid representation metadata");
    assert_eq!(
        Manifest::new(&[r]),
        Err(Error::Table(stele_cqis::tables::Error::Overflow))
    );
}
