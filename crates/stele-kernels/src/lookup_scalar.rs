//! RFC-0014 A6. Compute the genuine A7 lookup parents from proof-local immutable originals.
use super::{Original, Scalar};
use crate::gkr::{plan::Plan, scalar::State, GkrConstruction};
use crate::lookup::{Column, Input, Key, LookupBackend, Visit};
use crate::{Error, Field, QM31 as K};
use alloc::{vec, vec::Vec};

pub struct Tree<'s> {
    session: &'s Scalar<K>,
    key: Key,
    // Level k occupies pair slots [2^k-1,2^(k+1)-1).
    pairs: Vec<[K; 2]>,
}

fn index(axes: &[usize], x: usize, n: usize) -> usize {
    axes.iter()
        .fold(0, |i, &q| 2 * i + ((x >> (n - 1 - q)) & 1))
}

impl Scalar<K> {
    fn lookup_pairs(
        &self,
        input: &Input<'_>,
        owners: &[&Original<'_, K>],
    ) -> Result<Vec<[K; 2]>, Error> {
        input.check()?;
        let fetch = |c: Column, x: usize| {
            let o = *owners.get(c.owner).ok_or(Error::Source)?;
            if !core::ptr::eq(self, o.session) || o.geometry != c.geometry {
                return Err(Error::Source);
            }
            Ok(K::from_i64(i64::from(o.words[c.physical(x)?].as_u32())))
        };
        // Validate even an unselected leg before producing the first field value.
        for c in core::iter::once(input.multiplicity).chain(
            input
                .members
                .iter()
                .flat_map(|m| m.tuple.iter().map(|l| l.column)),
        ) {
            fetch(c, 0)?;
        }
        let key = input.key;
        let n = 1 << key.variables;
        let mut tree = vec![[K::ZERO; 2]; 2 * n - 1];
        let mut member = 0usize;
        for (x, out) in tree[n - 1..].iter_mut().enumerate() {
            while input.members.get(member).is_some_and(|m| x >= m.range.end) {
                member += 1
            }
            let mut selected = K::ZERO;
            let mut tuple = K::ZERO;
            if let Some(m) = input.members.get(member) {
                selected =
                    K::from_i64(m.selector.map_or(1, |(v, c)| v[index(c, x, key.variables)]));
                let mut power = K::ONE;
                for leg in &m.tuple {
                    let at = index(leg.coordinates, x, key.variables);
                    tuple = tuple + power * (fetch(leg.column, at)? + K::from_i64(leg.shift));
                    power = power * key.beta;
                }
            }
            let mut table = K::ONE;
            if x < input.valid {
                table = key.alpha;
                let mut power = K::ONE;
                for &value in &input.table[x] {
                    table = table - power * K::from_i64(value);
                    power = power * key.beta;
                }
            }
            let count = if x < input.multiplicity.len {
                fetch(input.multiplicity, x)?
            } else {
                K::ZERO
            };
            let denominator = key.alpha - selected * tuple;
            *out = [selected * table - count * denominator, denominator * table];
        }
        for i in (0..n - 1).rev() {
            let [a, b] = tree[2 * i + 1];
            let [c, d] = tree[2 * i + 2];
            tree[i] = [a * d + c * b, b * d]
        }
        Ok(tree)
    }
}

impl LookupBackend for Scalar<K> {
    type Tree<'s> = Tree<'s>;
    fn lookup_top(
        &self,
        input: &Input<'_>,
        owners: &[&Self::Original<'_>],
    ) -> Result<Vec<[K; 2]>, Error> {
        let tree = self.lookup_pairs(input, owners)?;
        let width = 1usize << input.key.top_variables;
        Ok(tree[width - 1..2 * width - 1].to_vec())
    }
    fn lookup_tree<'s>(
        &'s self,
        input: &Input<'_>,
        owners: &[&Self::Original<'_>],
    ) -> Result<Tree<'s>, Error> {
        Ok(Tree {
            session: self,
            key: input.key,
            pairs: self.lookup_pairs(input, owners)?,
        })
    }
    fn lookup_gkr(
        &self,
        key: Key,
        visit: Visit<'_, Tree<'_>>,
        input: &GkrConstruction<'_, K>,
    ) -> Result<State, Error> {
        let tree = visit.tree();
        let level = input.layer_variables.checked_add(1).ok_or(Error::Shape)?;
        if !core::ptr::eq(self, tree.session)
            || tree.key != key
            || level > key.variables
            || level <= key.top_variables
            || matches!(visit, Visit::Last(_)) != (level == key.variables)
        {
            return Err(Error::Source);
        }
        let width = 1usize << level;
        let slice = tree
            .pairs
            .get(width - 1..2 * width - 1)
            .ok_or(Error::Shape)?;
        State::from_plan(Plan::retained(input, level, Some(slice)).map_err(|_| Error::Shape)?)
    }
}
