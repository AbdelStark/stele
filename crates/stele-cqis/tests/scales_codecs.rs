//! RFC-0025 encoding §5: complete channels, stream limits and exact Model joins.
use stele_cqis::model::{Error, Model, Scales};

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().expect("u32"))
    }
    fn blob(&mut self) -> &'a [u8] {
        let n = self.u32() as usize;
        self.take(n)
    }
}

fn models() -> Vec<Model> {
    let mut r = Reader(include_bytes!("fixtures/models.bin"));
    let count = r.u32();
    (0..count)
        .map(|_| {
            let model = Model::decode(r.blob()).expect("Model fixture");
            r.take(32);
            let records = u16::from_le_bytes(r.take(2).try_into().expect("records"));
            for _ in 0..records {
                r.blob();
                r.take(2);
                let rank = r.take(1)[0];
                r.take(4 * usize::from(rank));
            }
            model
        })
        .collect()
}

#[test]
fn matches_reference_all_scales_and_complete_named_and_maximal_shapes() {
    let models = models();
    let mut r = Reader(include_bytes!("fixtures/scales.bin"));
    assert_eq!(r.u32(), 66);
    for _ in 0..66 {
        let model = &Model::decode(r.blob()).expect("small Model");
        let raw = r.blob();
        let identity = r.take(32).try_into().expect("identity");
        let scales = Scales::decode_expected(model, &identity, raw).expect("Scales fixture");
        assert_eq!(scales.encode().expect("encoding"), raw);
        assert_eq!(scales.identity(), identity);
        assert_eq!(scales.model_identity(), model.identity());
        assert_eq!(Scales::encoded_length(model).expect("length"), raw.len());
        for entry in scales.matrices() {
            let physical = model.shape().physical(entry.ordinal()).expect("physical");
            assert_eq!(entry.mantissas().len(), physical.dimensions()[0] as usize);
            assert_eq!(scales.matrix(entry.ordinal()), Some(entry));
        }
        assert!(scales.matrix(model.shape().record_count()).is_none());
    }
    assert!(r.0.is_empty());
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/scales.json")).expect("json");
    for case in fixture["large"].as_array().expect("large cases") {
        let model = &models[case["case"].as_u64().expect("case") as usize];
        let mut raw = b"stele/v0.1/cqis/scales".to_vec();
        raw.extend_from_slice(&model.identity());
        let mut index = 0;
        for i in 0..model.shape().record_count() {
            let physical = model.shape().physical(i).expect("physical");
            if physical.dimensions().len() != 2 {
                continue;
            }
            raw.extend_from_slice(&i.to_le_bytes());
            raw.extend_from_slice(&(if index % 2 == 0 { 1024i16 } else { -1099 }).to_le_bytes());
            for channel in 0..physical.dimensions()[0] {
                raw.extend_from_slice(
                    &[1u16, 65535, 32768, 255][channel as usize % 4].to_le_bytes(),
                );
            }
            index += 1;
        }
        assert_eq!(raw.len() as u64, case["length"].as_u64().expect("length"));
        assert_eq!(
            blake3::hash(&raw).to_hex().as_str(),
            case["identity"].as_str().expect("hash")
        );
        let scales = Scales::decode(model, &raw).expect("full domain");
        assert_eq!(
            scales.matrices().len() as u64,
            case["matrices"].as_u64().expect("matrices")
        );
        let channels: usize = scales.matrices().iter().map(|m| m.mantissas().len()).sum();
        assert_eq!(
            channels as u64,
            case["channels"].as_u64().expect("channels")
        );
        assert_eq!(scales.encode().expect("full re-encoding"), raw);
    }
}

#[test]
fn rejects_scale_field_changes_and_wrong_model_identity() {
    let mut r = Reader(include_bytes!("fixtures/scales.bin"));
    r.u32();
    for _ in 0..66 {
        let model = &Model::decode(r.blob()).expect("small Model");
        let raw = r.blob();
        let identity = r.take(32).try_into().expect("identity");
        let mut changed = raw.to_vec();
        changed[54..56].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(Scales::decode(model, &changed), Err(Error::Physical));
        for exponent in [-1100i16, 1025] {
            changed.copy_from_slice(raw);
            changed[56..58].copy_from_slice(&exponent.to_le_bytes());
            assert_eq!(Scales::decode(model, &changed), Err(Error::ScaleExponent));
        }
        changed.copy_from_slice(raw);
        changed[58..60].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(Scales::decode(model, &changed), Err(Error::ScaleMantissa));
        changed[58..60].copy_from_slice(
            &(u16::from_le_bytes(raw[58..60].try_into().expect("word")) % 65535 + 1).to_le_bytes(),
        );
        assert!(Scales::decode(model, &changed).is_ok());
        assert_eq!(
            Scales::decode_expected(model, &identity, &changed),
            Err(Error::Identity)
        );
        // Shape stays fixed, while a full numerical Model field changes legally.
        let mut model_raw = model.encode().expect("model bytes");
        let decoding_len = model.decoding().encode().expect("decoding").len();
        let position = model_raw.len() - decoding_len - 5;
        model_raw[position] = (model_raw[position] + 1) % 31;
        let other = Model::decode(&model_raw).expect("changed logits fraction");
        assert_eq!(Scales::decode(&other, raw), Err(Error::Identity));
    }
}

#[test]
fn accepts_short_reads_and_rejects_incomplete_or_invalid_streams() {
    let mut r = Reader(include_bytes!("fixtures/scales.bin"));
    r.u32();
    let model = &Model::decode(r.blob()).expect("small Model");
    let raw = r.blob();
    let expected = Scales::decode(model, raw).expect("baseline");
    for chunk in [1, 3, 17, 8192] {
        let mut input = raw;
        let actual = Scales::read_from(model, |buffer| {
            assert!(buffer.len() <= 8192);
            let n = input.len().min(buffer.len()).min(chunk);
            buffer[..n].copy_from_slice(&input[..n]);
            input = &input[n..];
            Ok::<_, ()>(n)
        })
        .expect("short reads");
        assert_eq!(actual, expected);
        assert!(input.is_empty());
    }
    for end in 0..raw.len() {
        assert_eq!(Scales::decode(model, &raw[..end]), Err(Error::Encoding));
    }
    let mut suffix = raw.to_vec();
    suffix.push(0);
    assert_eq!(Scales::decode(model, &suffix), Err(Error::Encoding));
    for input in [&raw[..raw.len() - 1], suffix.as_slice()] {
        let mut input = input;
        assert_eq!(
            Scales::read_from(model, |buffer| {
                let n = input.len().min(buffer.len());
                buffer[..n].copy_from_slice(&input[..n]);
                input = &input[n..];
                Ok::<_, ()>(n)
            }),
            Err(Error::Encoding)
        );
    }
    assert_eq!(
        Scales::read_from(model, |buffer| Ok::<_, ()>(buffer.len() + 1)),
        Err(Error::Read)
    );
    assert_eq!(
        Scales::read_from(model, |_| Err::<usize, _>(())),
        Err(Error::Read)
    );
    assert_eq!(
        Scales::decode(model, &vec![0; (1 << 26) + 1]),
        Err(Error::Capacity)
    );
}
