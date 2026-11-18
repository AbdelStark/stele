//! RFC-0014 A6. The source-message layout supplies every original column interval.
use super::{Error, LookupPlan, Plan};
use alloc::{vec, vec::Vec};
use stele_field::M31;
use stele_hash::ChallengeField;
use stele_kernels::{
    lookup::{Column, Input, Key, Leg, Member},
    SourceGeometry,
};
use stele_pcs::CodeField;

pub(in crate::zk::claims) struct Descriptor<'a> {
    members: Vec<Member<'a>>,
    multiplicity: Column,
    lookup: &'a LookupPlan,
    id: u64,
}
impl Descriptor<'_> {
    pub(in crate::zk::claims) fn input<K>(&self, beta: K, alpha: K) -> Input<'_, K> {
        Input {
            key: Key {
                id: self.id,
                variables: self.lookup.n,
                top_variables: self.lookup.k0,
                beta,
                alpha,
            },
            multiplicity: self.multiplicity,
            members: &self.members,
            table: &self.lookup.table,
            valid: self.lookup.valid,
        }
    }
}

pub(in crate::zk::claims) fn descriptors<'a, K: ChallengeField + CodeField>(
    plan: &'a Plan<K>,
    original: &[Vec<M31>],
) -> Result<Vec<Descriptor<'a>>, Error> {
    let mut slots = vec![0; plan.early()];
    let mut columns = Vec::with_capacity(original.len());
    for (index, values) in original.iter().enumerate() {
        let c = plan.columns.get(index).ok_or(Error::Statement)?;
        let layout = plan.layouts.get(c.source).ok_or(Error::Statement)?;
        let slot = slots.get_mut(c.source).ok_or(Error::Statement)?;
        let &(at, blocks) = layout.offsets.get(*slot).ok_or(Error::Statement)?;
        *slot += 1;
        let len = 1usize.checked_shl(c.log_len).ok_or(Error::Statement)?;
        if len != values.len() || c.limbs != 1 || at.checked_add(len) != Some(blocks) {
            return Err(Error::Statement);
        }
        let geometry = SourceGeometry {
            id: plan.source_id(c.source),
            rows: 2usize << layout.ell,
            columns: 2usize << layout.m,
        };
        let column = Column {
            owner: c.source,
            geometry,
            offset: at,
            len,
        };
        column.check().map_err(|_| Error::Statement)?;
        columns.push(column);
    }
    plan.lookups
        .iter()
        .enumerate()
        .map(|(id, lp)| {
            let mut members = Vec::with_capacity(lp.members.len());
            for m in &lp.members {
                if m.tuple.len() != m.shifts.len() {
                    return Err(Error::Statement);
                }
                let tuple = m
                    .tuple
                    .iter()
                    .zip(&m.shifts)
                    .map(|((i, coords), shift)| {
                        Ok(Leg {
                            column: *columns.get(*i).ok_or(Error::Statement)?,
                            coordinates: coords,
                            shift: *shift,
                        })
                    })
                    .collect::<Result<_, Error>>()?;
                members.push(Member {
                    range: m.offset..m.offset + (1usize << m.m),
                    selector: m
                        .selector
                        .as_ref()
                        .map(|(v, c)| (v.as_slice(), c.as_slice())),
                    tuple,
                });
            }
            Ok(Descriptor {
                members,
                multiplicity: *columns.get(lp.multiplicity).ok_or(Error::Statement)?,
                lookup: lp,
                id: id as u64,
            })
        })
        .collect()
}
