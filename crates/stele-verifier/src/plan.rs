//! The byte-5 plan of a development proof: source geometry and checks, derived from
//! the relation alone (RFC-0026 A15 §§6.1–6.3, A3, A4, A5, A11, A12, A14), task E8-02f1.
//!
//! Written from the RFC-0026 text and `formal/native-lookup.md` only (ADR-128). Nothing
//! here reads a proof byte.

use crate::development::{reserve, Error};
use crate::logup;
use crate::pcs::Source;
use crate::relation::{pow2, Kind, Ref, Relation};
use alloc::vec::Vec;

/// A15 §6.1 ids.
pub const STACKED_ID: u64 = 2;
pub const MODEL_ID: u64 = 1 << 32;
pub const ZEROCHECK_ID: u64 = 1 << 62;
pub const MATMUL_ID: u64 = (1 << 62) + (1 << 48);
pub const BATCH_ID: u64 = (1 << 62) + (1 << 49);
pub const TUPLE_ID: u64 = (1 << 62) + 3 * (1 << 48);
/// Byte-5 Circle blow-up exponent (A11 item 2, A12 item 2).
pub const BLOWUP: u8 = 2;

/// `ceil_log2(n)`: the least `b` with `2^b ≥ n` (A15 §6).
pub fn ceil_log2(n: u64) -> u32 {
    if n <= 1 {
        0
    } else {
        64 - (n - 1).leading_zeros()
    }
}

/// A committed source with its derived geometry and wire sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub id: u64,
    pub ell: u8,
    /// `log2` of the columns `C`.
    pub m: u8,
    pub certificate: usize,
    pub opening: usize,
}

impl Geometry {
    /// The PCS context under `root` (A15 §6.2: layout 0, policy 2, QM31).
    pub fn source(&self, root: [u8; 32]) -> Source {
        Source {
            degree: 4,
            id: self.id,
            ell: self.ell,
            m: self.m,
            blowup: BLOWUP,
            policy: 2,
            root,
        }
    }
}

/// formal/native-field-pcs.md §§3–4 with RFC-0010 A14: certificate
/// `u8 1 ‖ [tensor nonce] ‖ row ‖ column nonce ‖ q_c responses` and opening
/// `u8 1 ‖ row ‖ column nonce ‖ q_o responses`, each response `R` limbs and `m + b`
/// siblings. `None` for a geometry that is not a valid source.
fn sized(id: u64, ell: u8, m: u8) -> Option<Geometry> {
    let mut g = Geometry {
        id,
        ell,
        m,
        certificate: 0,
        opening: 0,
    };
    let p = g.source([0; 32]).parameters().ok()?;
    let response = pow2(ell)?
        .checked_mul(4)?
        .checked_add(32 * (usize::from(m) + usize::from(BLOWUP)))?;
    let row = pow2(m)?.checked_mul(16)?;
    let column_nonce = 8 * usize::from(p.column_bits > 0);
    let head = (1 + column_nonce).checked_add(row)?;
    g.certificate = usize::from(p.certificate_queries)
        .checked_mul(response)?
        .checked_add(head + 8 * usize::from(p.tensor_bits > 0))?;
    g.opening = usize::from(p.opening_queries)
        .checked_mul(response)?
        .checked_add(head)?;
    Some(g)
}

/// A15 §6.2 geometry rule: over the candidate `ell`, the valid geometry of least
/// certificate plus opening size, ties to the smallest `ell`.
fn best(
    id: u64,
    ells: core::ops::RangeInclusive<u8>,
    m: impl Fn(u8) -> u8,
) -> Result<Geometry, Error> {
    let mut out: Option<Geometry> = None;
    for ell in ells {
        if let Some(g) = sized(id, ell, m(ell)) {
            if out.is_none_or(|b| g.certificate + g.opening < b.certificate + b.opening) {
                out = Some(g);
            }
        }
    }
    out.ok_or(Error::Unsupported)
}

/// A stacked or model source of `2^bits` entries (A15 §6.2).
fn message_source(id: u64, bits: u8) -> Result<Geometry, Error> {
    best(id, bits.saturating_sub(28)..=bits.min(30), |ell| bits - ell)
}

/// A committed source: its geometry, batch id and `bits`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Committed {
    pub geometry: Geometry,
    pub batch: u64,
    pub bits: u8,
}

/// A column's place in a committed source: the source's position in
/// [`Plan::sources`] and the Boolean block index `o/2^n (+ j)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Home {
    pub source: usize,
    pub index: u64,
}

/// One member of a check (A3): a lookup, or a range read through its identity ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    pub vars: u8,
    pub tuple: Vec<Ref>,
    pub selector: Option<Ref>,
    /// `−width.min()` for a range, else 0.
    pub shift: i64,
    pub offset: u64,
}

/// One A3 check with its multiplicity source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Check {
    pub members: Vec<Member>,
    pub m: u8,
    pub c: usize,
    pub t: usize,
    pub k: u8,
    /// The `c·t` table entries, row-major.
    pub rows: Vec<i64>,
    pub k_lu: u8,
    pub multiplicity: Geometry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    /// The stacked source first, when there is a group, then model sources in split order.
    pub sources: Vec<Committed>,
    pub stacked: bool,
    /// One per column: its source block, or `None` for a public column.
    pub homes: Vec<Option<Home>>,
    pub checks: Vec<Check>,
    /// The identity domain sizes, increasing.
    pub sizes: Vec<u8>,
}

/// Blocks of `2^size` placed largest first, ties in the given order, at cumulative
/// offsets (A4, A5). Returns each block's offset and the total.
fn place(sizes: &[u8]) -> Result<(Vec<u64>, u64), Error> {
    let mut order = reserve(sizes.len())?;
    order.extend(0..sizes.len());
    order.sort_by_key(|i| core::cmp::Reverse(sizes[*i]));
    let mut offsets = reserve(sizes.len())?;
    offsets.resize(sizes.len(), 0);
    let mut at = 0u64;
    for i in order {
        offsets[i] = at;
        at = at.checked_add(1u64 << sizes[i]).ok_or(Error::Unsupported)?;
    }
    Ok((offsets, at))
}

impl Plan {
    pub fn derive(rel: &Relation) -> Result<Self, Error> {
        let mut homes = reserve(rel.columns.len())?;
        homes.resize(rel.columns.len(), None);
        let mut sources = Vec::new();
        // A15 §6.2 groups: c = ceil_log2(max(1, count)), blocks of 2^(n + c).
        let mut members: Vec<Vec<usize>> = reserve(rel.groups.len())?;
        members.resize_with(rel.groups.len(), Vec::new);
        for (id, c) in rel.columns.iter().enumerate() {
            if let Kind::Witness(g) = c.kind {
                members[g as usize]
                    .try_reserve(1)
                    .map_err(|_| Error::Capacity)?;
                members[g as usize].push(id);
            }
        }
        let mut blocks = reserve(rel.groups.len())?;
        for (n, cols) in rel.groups.iter().zip(&members) {
            let size = u32::from(*n) + ceil_log2(cols.len().max(1) as u64);
            // A15 §6.2: any n + c > 30 is Unsupported.
            if size > 30 {
                return Err(Error::Unsupported);
            }
            blocks.push(size as u8);
        }
        let stacked = !rel.groups.is_empty();
        if stacked {
            let (offsets, total) = place(&blocks)?;
            let s = ceil_log2(total);
            // A15 §6.2: S > 30 is Unsupported; bits = max(S, 6).
            if s > 30 {
                return Err(Error::Unsupported);
            }
            let bits = s.max(6) as u8;
            for ((n, cols), o) in rel.groups.iter().zip(&members).zip(&offsets) {
                for (j, id) in cols.iter().enumerate() {
                    homes[*id] = Some(Home {
                        source: 0,
                        index: (o >> n) + j as u64,
                    });
                }
            }
            sources.push(Committed {
                geometry: message_source(STACKED_ID, bits)?,
                batch: BATCH_ID,
                bits,
            });
        }
        // A5: weights in ColumnId order, split greedily at 2^30 entries per source.
        let mut split: Vec<Vec<usize>> = Vec::new();
        let mut total = 0u64;
        for (id, c) in rel.columns.iter().enumerate() {
            if c.kind != Kind::Weight {
                continue;
            }
            // A15 §6.2: a weight with n > 30 is Unsupported.
            if c.log_len > 30 {
                return Err(Error::Unsupported);
            }
            let size = 1u64 << c.log_len;
            if split.is_empty() || total + size > 1 << 30 {
                split.try_reserve(1).map_err(|_| Error::Capacity)?;
                split.push(Vec::new());
                total = 0;
            }
            total += size;
            let last = split.len() - 1;
            split[last].try_reserve(1).map_err(|_| Error::Capacity)?;
            split[last].push(id);
        }
        for (k, ids) in split.iter().enumerate() {
            let mut sizes = reserve(ids.len())?;
            sizes.extend(ids.iter().map(|id| rel.columns[*id].log_len));
            let (offsets, total) = place(&sizes)?;
            let bits = ceil_log2(total).max(6) as u8;
            for (id, o) in ids.iter().zip(offsets) {
                homes[*id] = Some(Home {
                    source: sources.len(),
                    index: o >> rel.columns[*id].log_len,
                });
            }
            sources.try_reserve(1).map_err(|_| Error::Capacity)?;
            sources.push(Committed {
                geometry: message_source(MODEL_ID + k as u64, bits)?,
                batch: BATCH_ID + 1 + k as u64,
                bits,
            });
        }
        let mut sizes: Vec<u8> = reserve(rel.identities.len() + rel.composes.len())?;
        sizes.extend(rel.identities.iter().map(|i| i.vars));
        for c in &rel.composes {
            sizes.push(rel.column(c.column)?.log_len);
        }
        sizes.sort_unstable();
        sizes.dedup();
        Ok(Plan {
            sources,
            stacked,
            homes,
            checks: checks(rel)?,
            sizes,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Key {
    Table(u32),
    Range(u8),
}

/// A15 §6.3: checks keyed by table or range width, in order of first use.
fn checks(rel: &Relation) -> Result<Vec<Check>, Error> {
    let mut keyed: Vec<(Key, Vec<Member>)> = Vec::new();
    let mut add = |key: Key, member: Member| -> Result<(), Error> {
        let at = match keyed.iter().position(|(k, _)| *k == key) {
            Some(at) => at,
            None => {
                keyed.try_reserve(1).map_err(|_| Error::Capacity)?;
                keyed.push((key, Vec::new()));
                keyed.len() - 1
            }
        };
        keyed[at].1.try_reserve(1).map_err(|_| Error::Capacity)?;
        keyed[at].1.push(member);
        Ok(())
    };
    for l in &rel.lookups {
        let mut tuple = reserve(l.tuple.len())?;
        tuple.extend(l.tuple.iter().cloned());
        add(
            Key::Table(l.table),
            Member {
                vars: l.vars,
                tuple,
                selector: l.selector.clone(),
                shift: 0,
                offset: 0,
            },
        )?;
    }
    for r in &rel.ranges {
        let n = rel.column(r.column)?.log_len;
        let mut vars = reserve(usize::from(n))?;
        vars.extend(0..n);
        let mut tuple = reserve(1)?;
        tuple.push(Ref {
            column: r.column,
            vars,
        });
        // A15 §6.3: a range member reads its column shifted by −width.min().
        add(
            Key::Range(r.width.bits),
            Member {
                vars: n,
                tuple,
                selector: None,
                shift: -r.width.min(),
                offset: 0,
            },
        )?;
    }
    let mut out = reserve(keyed.len())?;
    for (i, (key, mut members)) in keyed.into_iter().enumerate() {
        // A3: relation order, then stably sorted by m_i descending; cumulative offsets.
        members.sort_by_key(|m| core::cmp::Reverse(m.vars));
        let mut at = 0u64;
        for m in &mut members {
            m.offset = at;
            at += 1u64 << m.vars;
        }
        let m = ceil_log2(at);
        let c = members[0].tuple.len();
        let rows = match key {
            Key::Table(id) => {
                let table = rel
                    .tables
                    .get(id as usize)
                    .ok_or(Error::StatementMismatch)?;
                let mut rows = reserve(table.rows.iter().map(Vec::len).sum())?;
                for r in &table.rows {
                    rows.extend_from_slice(r);
                }
                rows
            }
            Key::Range(bits) => {
                // A15 §6.3: a range's table is the rows 0..2^bits in one column.
                let mut rows = reserve(1 << bits)?;
                rows.extend(0..1i64 << bits);
                rows
            }
        };
        let t = match key {
            Key::Table(id) => rel.tables[id as usize].rows.len(),
            Key::Range(bits) => 1 << bits,
        };
        // A15 §6.3: m ≤ 30, c ∈ {1, 2}, t ∈ [1, 2^16], and exactly c·t entries.
        if m > 30 || !(1..=2).contains(&c) || !(1..=1 << 16).contains(&t) || rows.len() != c * t {
            return Err(Error::Unsupported);
        }
        let k = ceil_log2(t as u64) as u8;
        // A14 item 3: the least k_LU for (c, 2^m, t); none up to 32 is Unsupported.
        let k_lu = logup::bits(c as u64, 1 << m, t as u64, 4).ok_or(Error::Unsupported)?;
        // A12 item 2: ell ∈ [0, k] of least certificate plus opening, C = 2^(k − ell)·4.
        let multiplicity = best(3 + i as u64, 0..=k, |ell| k - ell + 2)?;
        out.push(Check {
            members,
            m: m as u8,
            c,
            t,
            k,
            rows,
            k_lu,
            multiplicity,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceil_log2_matches_its_definition() {
        for (n, b) in [
            (0, 0),
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 3),
            (1 << 30, 30),
        ] {
            assert_eq!(ceil_log2(n), b);
        }
    }

    #[test]
    fn places_blocks_largest_first_with_ties_in_order() {
        let (offsets, total) = place(&[2, 4, 2]).expect("test vector");
        assert_eq!(offsets, [16, 0, 20]);
        assert_eq!(total, 24);
    }
}
