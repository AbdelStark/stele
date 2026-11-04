//! RFC-0025 encoding §§2–3: complete Map/Preparation parsing and physical joins.
use serde_json::Value;
use stele_cqis::model::{Error, Model, Preparation, SourceMap};

fn blob<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_le_bytes(input[..4].try_into().expect("length")) as usize;
    let raw = &input[4..4 + n];
    *input = &input[4 + n..];
    raw
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn matches_reference_complete_source_maps_and_preparations() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/source-preparation.json")).expect("fixture");
    let mut data = include_bytes!("fixtures/source-preparation.bin").as_slice();
    let mut counts = Vec::new();
    for (i, case) in fixture["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .enumerate()
    {
        let model = Model::decode(blob(&mut data)).expect("Model");
        let raw = blob(&mut data);
        let prep = blob(&mut data);
        let id: [u8; 32] = hex(case["map_id"].as_str().expect("MapId"))
            .try_into()
            .expect("digest");
        let map = SourceMap::decode_expected(&id, raw).expect("Map");
        assert_eq!(map.as_bytes(), raw);
        assert_eq!(map.identity(), id);
        assert_eq!(map.shape(), model.shape());
        assert_eq!(
            map.entries().len(),
            usize::from(model.shape().record_count())
        );
        for (entry, expected) in map
            .entries()
            .iter()
            .zip(case["entries"].as_array().expect("entries"))
        {
            assert_eq!(entry.name(), expected["name"].as_str().expect("name"));
            assert_eq!(
                u64::from(entry.dtype()),
                expected["dtype"].as_u64().expect("dtype")
            );
            let dims: Vec<_> = expected["dimensions"]
                .as_array()
                .expect("dimensions")
                .iter()
                .map(|v| v.as_u64().expect("dimension") as u32)
                .collect();
            assert_eq!(entry.dimensions(), dims);
            assert_eq!(
                u64::from(entry.transform()),
                expected["transform"].as_u64().expect("transform")
            );
            assert_eq!(entry.part().map(u64::from), expected["part"].as_u64());
            let width = [2u64, 2, 4, 8][usize::from(entry.dtype() - 1)];
            assert_eq!(
                entry.byte_length(),
                dims.iter().map(|d| u64::from(*d)).product::<u64>() * width
            );
        }
        let aliases = case["aliases"].as_array().expect("aliases");
        assert_eq!(
            map.alias_name(),
            aliases.first().map(|v| v[0].as_str().expect("alias"))
        );
        let ignored: Vec<_> = case["ignored"]
            .as_array()
            .expect("ignored")
            .iter()
            .map(|v| v.as_str().expect("name"))
            .collect();
        assert_eq!(map.ignored(), ignored);
        let built = Preparation::new(&model, map).expect("Preparation");
        assert_eq!(built.model_identity(), model.identity());
        assert_eq!(built.encode().expect("canonical bytes"), prep);
        assert_eq!(
            built.identity().as_slice(),
            hex(case["preparation_id"].as_str().expect("quantiser_id"))
        );
        assert_eq!(blake3::hash(prep).as_bytes(), &built.identity());
        assert_eq!(Preparation::decode(&model, prep), Ok(built));
        let expected = blake3::hash(prep);
        let checked = Preparation::decode_expected(&model, expected.as_bytes(), prep)
            .expect("expected Preparation");
        assert_eq!(checked.map().as_bytes(), raw);
        if i < 4 {
            counts.push(model.shape().record_count());
        }
        if i == 4 {
            rejects_preparation_changes(&model, raw, prep);
        }
    }
    assert_eq!(counts, [196, 291, 2052, 1155]);
    assert!(data.is_empty());
}

fn rejects_preparation_changes(model: &Model, map: &[u8], prep: &[u8]) {
    for end in 0..map.len() {
        assert!(SourceMap::decode(&map[..end]).is_err());
    }
    for end in 0..prep.len() {
        assert!(Preparation::decode(model, &prep[..end]).is_err());
    }
    let mut bad = prep.to_vec();
    bad.push(0);
    assert_eq!(Preparation::decode(model, &bad), Err(Error::Encoding));
    let start = b"stele/v0.1/cqis/quantiser".len() + 4 + map.len();
    for at in start..prep.len() {
        let mut bad = prep.to_vec();
        bad[at] ^= 1;
        assert_eq!(Preparation::decode(model, &bad), Err(Error::Physical));
    }
    let mut wrong = *blake3::hash(prep).as_bytes();
    wrong[0] ^= 1;
    assert_eq!(
        Preparation::decode_expected(model, &wrong, prep),
        Err(Error::Identity)
    );
    let mut renamed = map.to_vec();
    renamed[b"stele/v0.1/cqis/source-map".len() + 4 + 21 + 2] ^= 1;
    assert!(SourceMap::decode(&renamed).is_ok());
    assert_eq!(
        SourceMap::decode_expected(blake3::hash(map).as_bytes(), &renamed),
        Err(Error::Identity)
    );
    let mut other = include_bytes!("fixtures/source-preparation.bin").as_slice();
    blob(&mut other);
    blob(&mut other);
    blob(&mut other);
    let other = Model::decode(blob(&mut other)).expect("other shape");
    assert_eq!(Preparation::decode(&other, prep), Err(Error::Shape));
    assert_eq!(
        Preparation::new(&other, SourceMap::decode(map).expect("map")),
        Err(Error::Shape)
    );
    let mut bad = prep.to_vec();
    let at = b"stele/v0.1/cqis/quantiser".len();
    bad[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Preparation::decode(model, &bad), Err(Error::Capacity));
    assert_eq!(
        SourceMap::decode(&vec![0; (1 << 24) + 1]),
        Err(Error::Capacity)
    );
    assert_eq!(
        Preparation::decode(model, &vec![0; (17 << 20) + 1]),
        Err(Error::Capacity)
    );
}

#[test]
fn rejects_invalid_source_roles_names_partitions_and_aliases() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/source-preparation.json")).expect("fixture");
    for case in fixture["invalid"].as_array().expect("invalid") {
        let raw = hex(case["raw"].as_str().expect("raw"));
        let expected = match case["error"].as_str().expect("error") {
            "SourceName" => Error::SourceName,
            "SourceDtype" => Error::SourceDtype,
            "SourceShape" => Error::SourceShape,
            "SourceTransform" => Error::SourceTransform,
            "SourcePartition" => Error::SourcePartition,
            "SourceAlias" => Error::SourceAlias,
            "SourceIgnored" => Error::SourceIgnored,
            "Encoding" => Error::Encoding,
            "Capacity" => Error::Capacity,
            _ => unreachable!("error"),
        };
        assert_eq!(SourceMap::decode(&raw), Err(expected));
    }
}
