//! RFC-0025 encoding §§1,4: complete structural metadata, without proof admission.
use stele_cqis::model::{Error, Model, Rotation, Shape};

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take(2).try_into().expect("u16"))
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().expect("u32"))
    }
    fn blob(&mut self) -> &'a [u8] {
        let n = self.u32() as usize;
        self.take(n)
    }
}

#[test]
fn matches_reference_complete_model_frames_and_physical_roles() {
    let mut corpus = Reader(include_bytes!("fixtures/models.bin"));
    let count = corpus.u32();
    assert_eq!(count, 70);
    let mut sampled = 0;
    for case in 0..count {
        let raw = corpus.blob();
        let expected: [u8; 32] = corpus.take(32).try_into().expect("identity");
        let model = Model::decode_expected(&expected, raw).expect("structurally valid model");
        assert_eq!(model.encode().expect("canonical re-encoding"), raw);
        assert_eq!(model.identity(), expected);
        let shape = model.shape();
        let records = corpus.u16();
        assert_eq!(shape.record_count(), records);
        assert_eq!(model.formats().len(), usize::from(records));
        assert_eq!(model.blocks().len(), usize::from(shape.layers()));
        assert!(shape.physical(records).is_none());
        for ordinal in 0..records {
            let expected_name = core::str::from_utf8(corpus.blob()).expect("role");
            let layer = i16::from_le_bytes(corpus.take(2).try_into().expect("layer"));
            let rank = corpus.u8();
            let dimensions: Vec<_> = (0..rank).map(|_| corpus.u32()).collect();
            let physical = shape.physical(ordinal).expect("derived physical role");
            assert_eq!(physical.ordinal(), ordinal);
            assert_eq!(physical.role().name(), expected_name);
            assert_eq!(physical.layer(), u16::try_from(layer).ok());
            assert_eq!(physical.dimensions(), dimensions);
        }
        let wanted = [196, 291, 2052, 1155];
        if let Some(n) = wanted.get(case as usize) {
            assert_eq!(records, *n);
        }
        if case == 0 {
            assert_eq!(
                (shape.width(), shape.vocabulary(), shape.context()),
                (768, 50257, 1024)
            );
        } else if case == 1 {
            assert_eq!(
                (shape.width(), shape.vocabulary(), shape.context()),
                (4096, 128256, 131072)
            );
            assert_eq!(
                (
                    shape.heads(),
                    shape.groups(),
                    shape.head_width(),
                    shape.hidden()
                ),
                (32, 8, 128, 14336)
            );
        }
        if model.decoding().sampling().is_some() {
            sampled += 1;
        }
        assert_eq!(
            model.function_roles().count(),
            4 * usize::from(shape.layers())
                + 1
                + usize::from(model.decoding().sampling().is_some())
        );
        if case == count - 1 {
            assert_eq!(model.blocks()[0].policies()[6].scale(), 8454661);
            assert_eq!(
                model.blocks()[0].rotation().expect("rotation").rationals()[0],
                (u64::MAX, 1 << 32)
            );
        }
    }
    assert!(sampled > 0 && sampled < count);
    assert!(corpus.0.is_empty());
}

#[test]
fn rejects_rehashed_but_inconsistent_model_configuration() {
    let mut corpus = Reader(include_bytes!("fixtures/models-invalid.bin"));
    let count = corpus.u32();
    assert!(count >= 25);
    for _ in 0..count {
        let reason = core::str::from_utf8(corpus.blob()).expect("reason");
        let raw = corpus.blob();
        assert!(Model::decode(raw).is_err(), "accepted {reason}");
    }
    assert!(corpus.0.is_empty());
}

fn small_models() -> Vec<&'static [u8]> {
    let mut corpus = Reader(include_bytes!("fixtures/models.bin"));
    let count = corpus.u32();
    let mut out = Vec::new();
    for i in 0..count {
        let raw = corpus.blob();
        corpus.take(32);
        let records = corpus.u16();
        for _ in 0..records {
            corpus.blob();
            corpus.take(2);
            let rank = corpus.u8();
            corpus.take(4 * usize::from(rank));
        }
        if i >= count - 2 {
            out.push(raw);
        }
    }
    out
}

#[test]
fn rejects_truncation_physical_headers_and_changed_expected_identity() {
    for raw in small_models() {
        let model = Model::decode(raw).expect("baseline");
        let digest = model.identity();
        for end in 0..raw.len() {
            assert!(Model::decode(&raw[..end]).is_err(), "accepted prefix {end}");
        }
        let mut trailing = raw.to_vec();
        trailing.push(0);
        assert_eq!(Model::decode(&trailing), Err(Error::Encoding));
        for i in 0..raw.len() {
            let mut changed = raw.to_vec();
            changed[i] ^= 1;
            assert!(
                Model::decode_expected(&digest, &changed).is_err(),
                "unbound byte {i}"
            );
        }
        let header = b"stele/v0.1/cqis/model".len();
        let mut changed = raw.to_vec();
        changed[header..header + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Model::decode(&changed), Err(Error::Capacity));
        let first = header + 4 + 21;
        for (offset, bytes) in [
            (0, &[1, 0][..]),
            (2, &[1][..]),
            (3, &u32::MAX.to_le_bytes()[..]),
            (11, &[16][..]),
            (12, &[1][..]),
        ] {
            let mut changed = raw.to_vec();
            changed[first + offset..first + offset + bytes.len()].copy_from_slice(bytes);
            assert_eq!(Model::decode(&changed), Err(Error::Physical));
        }
    }
    assert_eq!(Model::decode(&vec![0; (1 << 20) + 1]), Err(Error::Capacity));
}

#[test]
fn rejects_shape_domains_and_rotation_noncanonical_fields() {
    let small = small_models();
    let gpt = Model::decode(small[0]).expect("GPT-2");
    let llama = Model::decode(small[1]).expect("Llama");
    for model in [&gpt, &llama] {
        let shape = model.shape().encode();
        for (offset, value) in [
            (1, 0),
            (1, 129),
            (3, 0),
            (3, 16385),
            (5, 0),
            (5, 129),
            (7, 0),
            (7, 129),
            (9, 0),
            (9, 16385),
            (11, 0),
            (11, 16385),
        ] {
            let mut bad = shape;
            bad[offset..offset + 2].copy_from_slice(&u16::to_le_bytes(value));
            assert_eq!(Shape::decode(&bad), Err(Error::Shape));
        }
        for offset in [13, 17] {
            for value in [0u32, (1 << 20) + 1] {
                let mut bad = shape;
                bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                assert_eq!(Shape::decode(&bad), Err(Error::Shape));
            }
        }
        let mut bad = shape;
        bad[0] = 2;
        assert_eq!(Shape::decode(&bad), Err(Error::Shape));
        assert_eq!(Shape::decode(&shape[..20]), Err(Error::Shape));
    }
    let raw = llama.blocks()[0]
        .rotation()
        .expect("rotation")
        .encode()
        .expect("bytes");
    let header = b"stele/v0.1/cqis/rotation".len();
    for (offset, value) in [
        (0, vec![1, 0]),
        (2, vec![0; 4]),
        (6, vec![3]),
        (7, vec![2]),
        (8, vec![0; 4]),
        (20, vec![0; 8]),
        (12, vec![0; 8]),
        (44, vec![0; 8]),
    ] {
        let mut bad = raw.clone();
        bad[header + offset..header + offset + value.len()].copy_from_slice(&value);
        assert_eq!(Rotation::decode(&bad), Err(Error::Rotation));
    }
    // A maximum u64 numerator with denominator 1 exceeds the rational domain.
    let mut bad = raw.clone();
    bad[header + 20..header + 28].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(Rotation::decode(&bad), Err(Error::Rotation));
    for end in 0..raw.len() {
        assert!(Rotation::decode(&raw[..end]).is_err());
    }
}
