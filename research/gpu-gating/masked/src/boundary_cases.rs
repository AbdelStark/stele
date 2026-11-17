//! RFC-0014 §5/§7: field boundaries are canonical; hash words keep all 32 bits.
use crate::{source, Field, Rng, M31};
use stele_reductions::stele_hash::{
    blake3_digest,
    mask::{MaskStream, SOURCE_SALT},
    merkle::{Descriptor, Kind},
};

pub(crate) const CASES: usize = 1000;
pub(crate) const SEED: u64 = 0x40_4000_0001;

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub(crate) enum Op {
    Mask,
    Tile,
    Duplicate,
    Transpose,
    BitReverse,
    Forward,
    Inverse,
    Scale,
    Leaf,
    Node,
}
pub(crate) const OPS: [Op; 10] = [
    Op::Mask,
    Op::Tile,
    Op::Duplicate,
    Op::Transpose,
    Op::BitReverse,
    Op::Forward,
    Op::Inverse,
    Op::Scale,
    Op::Leaf,
    Op::Node,
];

pub(crate) struct Case {
    pub op: Op,
    pub args: [u32; 3],
    pub input: Vec<u32>,
    pub expected: Vec<u32>,
}

fn words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect()
}
fn hash(bytes: &[u8]) -> Vec<u32> {
    words(&blake3_digest(bytes))
}
fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub(crate) fn fixture(op: Op, case: usize, raw: bool) -> Case {
    let mut rng = Rng::new(SEED + 2 * case as u64);
    let mut field = |count: usize| -> Vec<u32> {
        (0..count)
            .map(|i| {
                let value = match (case + i) % 7 {
                    0 => 0,
                    1 => 1,
                    2 => M31::MODULUS - 1,
                    _ => rng.m31().as_u32(),
                };
                value + if raw { M31::MODULUS } else { 0 }
            })
            .collect()
    };
    let log = case % 10;
    let len = 1usize << log;
    let rows = [1, 3, 17, 31, 32, 33, 65][case % 7];
    let (args, input, expected) = match op {
        Op::Mask => {
            let u: Vec<_> = (0..log)
                .rev()
                .filter(|v| (case + v) % 3 != 0)
                .map(|v| v as u32)
                .collect();
            let block = field(1 << u.len());
            let canonical: Vec<_> = block.iter().map(|w| M31::from_lazy(*w).unwrap()).collect();
            let expected = stele_reductions::zk::claims::bench::mask_table::<crate::K>(
                &canonical,
                &u.iter().map(|v| *v as usize).collect::<Vec<_>>(),
                log,
            )
            .iter()
            .map(|v| v.0 .0.as_u32())
            .collect();
            (
                [log as u32, u.len() as u32, 0],
                [u, block].concat(),
                expected,
            )
        }
        Op::Tile | Op::Duplicate => {
            let half = field(4 * len);
            let expected = half.iter().chain(&half).map(|w| w % M31::MODULUS).collect();
            ([len as u32, 0, 0], half, expected)
        }
        Op::Transpose => {
            let len = 1 << (case % 7);
            let input = field(rows * len);
            let expected = (0..len)
                .flat_map(|c| (0..rows).map(move |r| r * len + c))
                .map(|i| input[i] % M31::MODULUS)
                .collect();
            ([rows as u32, len as u32, 0], input, expected)
        }
        Op::BitReverse => {
            let rows = [1, 3, 17][case % 3];
            let input = field(rows * len);
            let mut expected: Vec<_> = input.iter().map(|w| w % M31::MODULUS).collect();
            if log != 0 {
                source::bit_reverse(&mut expected, rows, log as u32);
            }
            ([rows as u32, log as u32, 0], input, expected)
        }
        Op::Forward | Op::Inverse => {
            let log = 1 + case % 7;
            let n = 1 << log;
            let inverse = matches!(op, Op::Inverse);
            let tw = source::twiddles(log as u32, inverse).remove(case % log);
            let mut input = field(rows * n);
            let mut expected = input.clone();
            source::level(&mut expected, rows, n, &tw, inverse);
            input.extend(tw.iter().map(|w| w + if raw { M31::MODULUS } else { 0 }));
            ([rows as u32, n as u32, tw.len() as u32], input, expected)
        }
        Op::Scale => {
            let input = field(1 + (case * 73) % 1025);
            let scale = field(1)[0];
            let expected = input
                .iter()
                .map(|w| (M31::from_lazy(*w).unwrap() * M31::from_lazy(scale).unwrap()).as_u32())
                .collect();
            ([input.len() as u32, scale, 0], input, expected)
        }
        Op::Leaf => {
            let rows = [1, 4, 16, 234, 235, 236, 491, 492, 512][case % 9];
            let leaves = 1 << (case % 3);
            let encoded = field(rows * leaves);
            let descriptor = Descriptor {
                kind: Kind::Columns,
                id: SEED + case as u64,
                count: leaves as u64,
                width: (32 + 4 * rows) as u64,
            };
            let prefix = source::prefix(&descriptor, 0);
            let key: Vec<_> = (0..8)
                .map(|i| if i == 0 { u32::MAX } else { rng.next() as u32 })
                .collect();
            let seed: [u8; 32] = bytes(&key).try_into().unwrap();
            let (block, length) = source::salt_block(descriptor.id);
            let stream = MaskStream::new(&seed, SOURCE_SALT, descriptor.id);
            let expected = (0..leaves)
                .flat_map(|i| {
                    let mut payload = prefix.clone();
                    payload.extend_from_slice(&(i as u64).to_le_bytes());
                    payload.push(1);
                    let mut salt = [0; 32];
                    stream.fill_at((32 * i) as u64, &mut salt);
                    payload.extend_from_slice(&salt);
                    payload.extend(bytes(
                        &encoded[i * rows..(i + 1) * rows]
                            .iter()
                            .map(|w| w % M31::MODULUS)
                            .collect::<Vec<_>>(),
                    ));
                    hash(&payload)
                })
                .collect();
            let mut input: Vec<_> = prefix.into_iter().map(u32::from).collect();
            input.extend(key);
            input.extend(block);
            input.push(length);
            input.extend(encoded);
            ([rows as u32, leaves as u32, 0], input, expected)
        }
        Op::Node => {
            let parents = 1 + case % 4;
            let level = 1 + case % 8;
            let descriptor = Descriptor {
                kind: Kind::Columns,
                id: SEED + case as u64,
                count: (2 * parents) as u64,
                width: 32,
            };
            let prefix = source::prefix(&descriptor, 1);
            let children: Vec<_> = (0..16 * parents)
                .map(|i| match i % 4 {
                    0 => u32::MAX,
                    1 => M31::MODULUS,
                    _ => rng.next() as u32,
                })
                .collect();
            let expected = (0..parents)
                .flat_map(|i| {
                    let mut payload = prefix.clone();
                    payload.extend_from_slice(&(level as u32).to_le_bytes());
                    payload.extend_from_slice(&(i as u64).to_le_bytes());
                    payload.extend(bytes(&children[16 * i..16 * (i + 1)]));
                    hash(&payload)
                })
                .collect();
            let mut input: Vec<_> = prefix.into_iter().map(u32::from).collect();
            input.extend(children);
            ([parents as u32, level as u32, 0], input, expected)
        }
    };
    Case {
        op,
        args,
        input,
        expected,
    }
}

#[test]
fn matches_reference_copy_and_source_kernels_on_host() {
    let mut input = Vec::new();
    let mut cases = Vec::new();
    for case in 0..CASES {
        for op in OPS {
            for raw in [false, true] {
                let c = fixture(op, case, raw);
                input.extend([
                    op as u32,
                    c.args[0],
                    c.args[1],
                    c.args[2],
                    c.input.len() as u32,
                    c.expected.len() as u32,
                ]);
                input.extend(&c.input);
                cases.push((case, raw, c));
            }
        }
    }
    let kernels = include_str!("kernels.cu")
        .split_once("// x[i] = x[i] + c")
        .unwrap()
        .0;
    let source = format!(
        "{}\n{}\n#undef GRID_STRIDE\n#define GRID_STRIDE(i,n) for(u64 i=0;i<(n);++i)\n{}\n{}",
        include_str!("boundary_host.cuh"),
        kernels,
        include_str!("source.cu"),
        include_str!("boundary_main.cuh")
    );
    let output = crate::host_probe::run(&source, &input);
    let mut at = 0;
    let mut failed = Vec::new();
    for (case, raw, c) in cases {
        let end = at + c.expected.len();
        if output.get(at..end) != Some(c.expected.as_slice()) {
            failed.push((case, raw, c.op));
        }
        at = end;
    }
    assert_eq!(at, output.len());
    assert!(
        failed.is_empty(),
        "boundary mismatches: {} cases, first {:?}",
        failed.len(),
        &failed[..failed.len().min(20)]
    );
    eprintln!("boundary_host_cases={CASES} operations=10 representations=2 seed={SEED}");
}
