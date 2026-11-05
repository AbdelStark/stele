//! RFC-0025 encoding §6: complete digests, exact closure and metadata-before-data checks.
use super::{Definition, Layout, Registry};
use crate::model::{Error, Model};
use alloc::{vec, vec::Vec};

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
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
    fn slots(&mut self) -> Vec<(usize, u8)> {
        (0..self.u16())
            .map(|_| {
                let offset = self.u32() as usize;
                (offset, self.take(1)[0])
            })
            .collect()
    }
}

fn check_layout(model: &Model, raw: &[u8], slots: &[(usize, u8)]) {
    let layout = Layout::new(model).expect("derived metadata");
    let mut metadata = raw.to_vec();
    for (offset, _) in slots {
        metadata[*offset..*offset + 32].fill(0);
    }
    assert_eq!(layout.bytes, metadata);
    let actual: Vec<_> = layout
        .slots
        .iter()
        .map(|s| {
            (
                s.offset,
                match s.definition {
                    Definition::Table(_) => 0,
                    Definition::Rotation(_) => 1,
                },
            )
        })
        .collect();
    assert_eq!(actual, slots);
    assert!(layout.bytes.len() < 312000);
    assert!(layout.slots.len() <= 516 + 128);
}

#[test]
fn matches_reference_full_registry_bytes_and_regenerated_data() {
    let mut r = Reader(include_bytes!("../../../tests/fixtures/registries.bin"));
    assert_eq!(r.u32(), 6);
    for case in 0..6 {
        let model = Model::decode(r.blob()).expect("Model");
        let raw = r.blob();
        let expected: [u8; 32] = r.take(32).try_into().expect("identity");
        let slots = r.slots();
        check_layout(&model, raw, &slots);
        let registry = Registry::decode_expected(&model, &expected, raw)
            .expect("complete regenerated Registry");
        assert_eq!(registry.as_bytes(), raw);
        assert_eq!(registry.identity(), expected);
        assert_eq!(registry.model_identity(), model.identity());
        for i in 0..raw.len() {
            let mut changed = raw.to_vec();
            changed[i] ^= 1;
            assert_eq!(registry.validate_encoding(&changed), Err(Error::Registry));
        }
        if case == 0 {
            assert_eq!(
                Registry::new(&model).expect("generated construction"),
                registry
            );
            let mut wrong = expected;
            wrong[0] ^= 1;
            assert_eq!(
                Registry::decode_expected(&model, &wrong, raw),
                Err(Error::Identity)
            );
            let mut model_raw = model.encode().expect("Model bytes");
            let tail = model.decoding().encode().expect("Decoding bytes").len();
            let at = model_raw.len() - tail - 5;
            model_raw[at] = (model_raw[at] + 1) % 31;
            let changed = Model::decode(&model_raw).expect("legal different logits fraction");
            assert_eq!(Registry::decode(&changed, raw), Err(Error::Registry));
        }
        if case == 5 {
            // Exercise each component/rotation digest as a supplied claim, using
            // the actual native definition generator, without a truth callback.
            for (offset, kind) in slots {
                let mut changed = raw.to_vec();
                changed[offset] ^= 1;
                assert_eq!(
                    Registry::decode(&model, &changed),
                    Err(if kind == 0 {
                        Error::TableData
                    } else {
                        Error::RotationData
                    })
                );
            }
        }
    }
    assert!(r.0.is_empty());
}

#[test]
fn matches_reference_complete_named_and_maximal_registry_metadata() {
    let mut r = Reader(include_bytes!(
        "../../../tests/fixtures/registry-layouts.bin"
    ));
    assert_eq!(r.u32(), 4);
    for _ in 0..4 {
        let model = Model::decode(r.blob()).expect("Model");
        let metadata = r.blob();
        let slots = r.slots();
        check_layout(&model, metadata, &slots);
    }
    assert!(r.0.is_empty());
}

#[test]
fn rejects_all_metadata_mutations_before_digest_generation_and_whole_table_overflow() {
    let mut r = Reader(include_bytes!(
        "../../../tests/fixtures/registry-overflow.bin"
    ));
    let model = Model::decode(r.blob()).expect("structural Model can precede a table overflow");
    let metadata = r.blob();
    let slots = r.slots();
    assert!(r.0.is_empty());
    check_layout(&model, metadata, &slots);
    for end in 0..metadata.len() {
        assert_eq!(
            Registry::decode(&model, &metadata[..end]),
            Err(Error::Registry)
        );
    }
    let mut suffix = metadata.to_vec();
    suffix.push(0);
    assert_eq!(Registry::decode(&model, &suffix), Err(Error::Registry));
    assert_eq!(
        Registry::decode(&model, &vec![0; (1 << 20) + 1]),
        Err(Error::Capacity)
    );
    for i in 0..metadata.len() {
        if slots
            .iter()
            .any(|(offset, _)| (*offset..*offset + 32).contains(&i))
        {
            continue;
        }
        let mut changed = metadata.to_vec();
        changed[i] ^= 1;
        assert_eq!(
            Registry::decode(&model, &changed),
            Err(Error::Registry),
            "metadata byte {i}"
        );
    }
    assert_eq!(
        Registry::new(&model),
        Err(Error::Generation(crate::tables::Error::Overflow))
    );
}
