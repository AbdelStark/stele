//! RFC-0008 A7 items 2/3: checked geometry and canonical tree material for CUDA.
use crate::{Serialize, K};
use stele_reductions::zk::claims::bench::{LookupInputs, LookupTree};

/// Invalid geometry, noncanonical output, or the production top abort.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Value,
    DenominatorZero,
}

pub(crate) fn words(value: K) -> [u32; 4] {
    let bytes = value.to_le_bytes();
    core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

fn element(words: &[u32]) -> Result<K, Error> {
    let mut bytes = [0; 16];
    for (w, b) in words.iter().zip(bytes.chunks_exact_mut(4)) {
        b.copy_from_slice(&w.to_le_bytes());
    }
    K::from_le_bytes(bytes).ok_or(Error::Value)
}

pub(crate) struct Prepared {
    pub values: Vec<u32>,
    pub selector: Vec<u32>,
    pub n: usize,
    pub width: usize,
    pub mults: usize,
    pub leaves: usize,
    pub tree_words: usize,
    pub top: usize,
}

impl Prepared {
    pub fn new(input: &LookupInputs<K>) -> Result<Self, Error> {
        let n = input.table.len();
        let width = input.tuples.len();
        let mults = input.multiplicity.len();
        let leaves = n.checked_mul(2).ok_or(Error::Shape)?;
        let tree_words = leaves
            .checked_mul(2)
            .and_then(|x| x.checked_sub(1))
            .and_then(|x| x.checked_mul(8))
            .ok_or(Error::Shape)?;
        let top = u32::try_from(input.top_variables)
            .ok()
            .and_then(|x| 1usize.checked_shl(x))
            .ok_or(Error::Shape)?;
        let value_count = n
            .checked_mul(width)
            .and_then(|x| x.checked_add(n))
            .and_then(|x| x.checked_add(mults))
            .and_then(|x| x.checked_add(width))
            .and_then(|x| x.checked_add(1))
            .ok_or(Error::Shape)?;
        let total_words = value_count
            .checked_mul(4)
            .and_then(|x| x.checked_add(n))
            .and_then(|x| x.checked_add(tree_words))
            .and_then(|x| top.checked_mul(5).and_then(|t| x.checked_add(t)))
            .ok_or(Error::Shape)?;
        if !n.is_power_of_two()
            || width == 0
            || input.powers.len() != width
            || input.selector.len() != n
            || input.selector.iter().any(|s| !matches!(s, 0 | 1))
            || input.tuples.iter().any(|t| t.len() != n)
            || !mults.is_power_of_two()
            || mults > n
            || top > leaves
            || total_words > isize::MAX as usize / 4
        {
            return Err(Error::Shape);
        }
        let values = input
            .tuples
            .iter()
            .flatten()
            .chain(&input.table)
            .chain(&input.multiplicity)
            .chain(&input.powers)
            .chain([&input.alpha])
            .flat_map(|v| words(*v))
            .collect();
        Ok(Self {
            values,
            selector: input.selector.iter().map(|x| *x as u32).collect(),
            n,
            width,
            mults,
            leaves,
            tree_words,
            top,
        })
    }

    pub fn finish(&self, tree: &[u32], h: &[u32], flags: &[u32]) -> Result<LookupTree<K>, Error> {
        if tree.len() != self.tree_words || h.len() != 4 * self.top || flags.len() != self.top {
            return Err(Error::Shape);
        }
        if flags.iter().any(|x| *x > 1) {
            return Err(Error::Value);
        }
        if flags.contains(&1) {
            return Err(Error::DenominatorZero);
        }
        let mut layers = Vec::new();
        let mut width = 1;
        while width <= self.leaves {
            layers.push(
                tree[8 * (width - 1)..8 * (2 * width - 1)]
                    .chunks_exact(8)
                    .map(|pair| Ok([element(&pair[..4])?, element(&pair[4..])?]))
                    .collect::<Result<Vec<_>, Error>>()?,
            );
            width *= 2;
        }
        let layer = &layers[self.top.trailing_zeros() as usize];
        let top = [
            layer.iter().map(|x| x[0]).collect(),
            layer.iter().map(|x| x[1]).collect(),
            h.chunks_exact(4).map(element).collect::<Result<_, _>>()?,
        ];
        Ok(LookupTree { layers, top })
    }
}
