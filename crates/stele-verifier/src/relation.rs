//! The relation of a development proof: its canonical decoding (RFC-0026 A15 §5) and
//! `Relation::validate` (RFC-0026 §3.6 with A6), task E8-02f1.
//!
//! Written from the RFC-0026 text only (ADR-128): no production crate was opened.
//! Every failure here is `StatementMismatch`, raised before any proof byte is read
//! (A15 §6.0). Names are parsed and dropped: they do not enter the replay, only the
//! digest of the whole encoding does.

use crate::development::{reserve, Error, Reader};
use alloc::vec::Vec;
use stele_field::{Field, M31};

/// `MAX_VARS` (RFC-0026 §3.1).
pub const MAX_VARS: u8 = 30;
/// A matmul ref's fixed bits (RFC-0026 A6).
pub const FIXED_0: u8 = 0xFE;
pub const FIXED_1: u8 = 0xFF;
const MAGIC: &[u8; 31] = b"stele/v0.1/relation/encoding/v1";

/// A declared width (RFC-0026 §2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Width {
    pub signed: bool,
    pub bits: u8,
}

impl Width {
    /// A15 §1: `−2^(bits−1)` signed, `0` unsigned (bits ≤ 30 after validation).
    pub fn min(&self) -> i64 {
        if self.signed {
            -(1i64 << (self.bits - 1))
        } else {
            0
        }
    }
    pub fn max(&self) -> i64 {
        if self.signed {
            (1i64 << (self.bits - 1)) - 1
        } else {
            (1i64 << self.bits) - 1
        }
    }
    /// §3.6 item 2: `mag(w) = max(|w.min|, |w.max|)`.
    pub fn mag(&self) -> u128 {
        self.min()
            .unsigned_abs()
            .max(self.max().unsigned_abs())
            .into()
    }
    fn within(&self, outer: &Width) -> bool {
        self.min() >= outer.min() && self.max() <= outer.max()
    }
}

/// `Ref { column, vars }` (§3.1); `vars[j]` is the domain bit read as column bit `j`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ref {
    pub column: u32,
    pub vars: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    Witness(u32),
    Weight,
    Public(Vec<i64>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    pub kind: Kind,
    pub width: Width,
    pub log_len: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    pub widths: Vec<Width>,
    pub rows: Vec<Vec<i64>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Term {
    pub coeff: i64,
    pub factors: Vec<Ref>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub vars: u8,
    pub terms: Vec<Term>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lookup {
    pub vars: u8,
    pub selector: Option<Ref>,
    pub tuple: Vec<Ref>,
    pub table: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Range {
    pub column: u32,
    pub width: Width,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Matmul {
    pub free: u8,
    pub summed: u8,
    pub out: Ref,
    pub lhs: Ref,
    pub rhs: Ref,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Compose {
    pub column: u32,
    pub limbs: Vec<(u32, u8)>,
}

/// A decoded relation; ids are positions (A15 §5).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Relation {
    /// Each group's `log_len`.
    pub groups: Vec<u8>,
    pub columns: Vec<Column>,
    pub tables: Vec<Table>,
    pub identities: Vec<Identity>,
    pub lookups: Vec<Lookup>,
    pub ranges: Vec<Range>,
    pub matmuls: Vec<Matmul>,
    pub composes: Vec<Compose>,
}

fn width(r: &mut Reader) -> Result<Width, Error> {
    let signed = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(r.fail()),
    };
    Ok(Width {
        signed,
        bits: r.u8()?,
    })
}

fn reference(r: &mut Reader) -> Result<Ref, Error> {
    let column = r.u32()?;
    let n = usize::from(r.u8()?);
    let mut vars = reserve(n)?;
    vars.extend_from_slice(r.take(n)?);
    Ok(Ref { column, vars })
}

/// `list X`, with each element at least `min` bytes so a count cannot outrun the input.
fn list<T>(
    r: &mut Reader,
    min: usize,
    mut item: impl FnMut(&mut Reader) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let n = r.count(min)?;
    let mut out = reserve(n)?;
    for _ in 0..n {
        out.push(item(r)?);
    }
    Ok(out)
}

impl Relation {
    /// A15 §5: the canonical encoding, exactly, with nothing after it.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let r = &mut Reader::new(bytes, Error::StatementMismatch);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(Error::StatementMismatch);
        }
        let groups = list(r, 5, |r| {
            r.blob()?;
            r.u8()
        })?;
        let columns = list(r, 8, |r| {
            r.blob()?;
            let kind = match r.u8()? {
                0 => Kind::Witness(r.u32()?),
                1 => Kind::Weight,
                2 => Kind::Public(list(r, 8, |r| r.i64())?),
                _ => return Err(Error::StatementMismatch),
            };
            Ok(Column {
                kind,
                width: width(r)?,
                log_len: r.u8()?,
            })
        })?;
        let tables = list(r, 12, |r| {
            r.blob()?;
            Ok(Table {
                widths: list(r, 2, width)?,
                rows: list(r, 4, |r| list(r, 8, |r| r.i64()))?,
            })
        })?;
        let identities = list(r, 9, |r| {
            r.blob()?;
            Ok(Identity {
                vars: r.u8()?,
                terms: list(r, 9, |r| {
                    let coeff = r.i64()?;
                    let n = usize::from(r.u8()?);
                    let mut factors = reserve(n)?;
                    for _ in 0..n {
                        factors.push(reference(r)?);
                    }
                    Ok(Term { coeff, factors })
                })?,
            })
        })?;
        let lookups = list(r, 14, |r| {
            r.blob()?;
            let vars = r.u8()?;
            let selector = match r.u8()? {
                0 => None,
                1 => Some(reference(r)?),
                _ => return Err(Error::StatementMismatch),
            };
            Ok(Lookup {
                vars,
                selector,
                tuple: list(r, 5, reference)?,
                table: r.u32()?,
            })
        })?;
        let ranges = list(r, 10, |r| {
            r.blob()?;
            Ok(Range {
                column: r.u32()?,
                width: width(r)?,
            })
        })?;
        let matmuls = list(r, 21, |r| {
            r.blob()?;
            Ok(Matmul {
                free: r.u8()?,
                summed: r.u8()?,
                out: reference(r)?,
                lhs: reference(r)?,
                rhs: reference(r)?,
            })
        })?;
        let composes = list(r, 12, |r| {
            r.blob()?;
            Ok(Compose {
                column: r.u32()?,
                limbs: list(r, 5, |r| Ok((r.u32()?, r.u8()?)))?,
            })
        })?;
        r.end()?;
        Ok(Relation {
            groups,
            columns,
            tables,
            identities,
            lookups,
            ranges,
            matmuls,
            composes,
        })
    }

    pub fn column(&self, id: u32) -> Result<&Column, Error> {
        self.columns
            .get(id as usize)
            .ok_or(Error::StatementMismatch)
    }

    /// RFC-0026 §3.6 (with A6): shapes, the bound rule and range discipline. Any
    /// failure is `StatementMismatch` (A15 §6.0).
    pub fn validate(&self) -> Result<(), Error> {
        let bad = Error::StatementMismatch;
        let p = u128::from(M31::MODULUS);
        let ok_width = |w: &Width| (1..=30).contains(&w.bits);
        for c in &self.columns {
            // §3.6 item 1: a width outside 1..=30.
            if !ok_width(&c.width) {
                return Err(bad);
            }
            match &c.kind {
                // §3.6 item 1: a public column's length and values fit its declaration.
                Kind::Public(values) => {
                    let fits = values
                        .iter()
                        .all(|v| *v >= c.width.min() && *v <= c.width.max());
                    if pow2(c.log_len) != Some(values.len()) || !fits {
                        return Err(bad);
                    }
                }
                // §3.6 item 1: a witness column's group exists with its log_len.
                Kind::Witness(g) => {
                    if self.groups.get(*g as usize) != Some(&c.log_len) {
                        return Err(bad);
                    }
                }
                Kind::Weight => {}
            }
        }
        for t in &self.tables {
            // §3.6 item 1: at most 2^16 rows; widths valid; every row of the table's
            // arity and inside its widths (E8-02f1 reading, spec gap 3).
            if t.rows.len() > 1 << 16 || !t.widths.iter().all(ok_width) {
                return Err(bad);
            }
            for row in &t.rows {
                if row.len() != t.widths.len()
                    || row
                        .iter()
                        .zip(&t.widths)
                        .any(|(v, w)| *v < w.min() || *v > w.max())
                {
                    return Err(bad);
                }
            }
        }
        for i in &self.identities {
            if i.vars > MAX_VARS {
                return Err(bad);
            }
            let mut bound = 0u128;
            for t in &i.terms {
                // §3.6 item 1: at most 3 factors and a nonzero coefficient.
                if t.factors.len() > 3 || t.coeff == 0 {
                    return Err(bad);
                }
                let mut b = u128::from(t.coeff.unsigned_abs());
                for f in &t.factors {
                    self.check_ref(f, i.vars, false)?;
                    b = b
                        .checked_mul(self.column(f.column)?.width.mag())
                        .ok_or(bad)?;
                }
                bound = bound.checked_add(b).ok_or(bad)?;
            }
            // §3.6 item 2: B = Σ|c_t|·Π mag(width_f) < p.
            if bound >= p {
                return Err(bad);
            }
        }
        for l in &self.lookups {
            let table = self.tables.get(l.table as usize).ok_or(bad)?;
            // §3.6 item 1: arity equal to the table's and in {1, 2}.
            if l.vars > MAX_VARS
                || l.tuple.len() != table.widths.len()
                || !(1..=2).contains(&l.tuple.len())
            {
                return Err(bad);
            }
            for r in &l.tuple {
                self.check_ref(r, l.vars, false)?;
            }
            // §3.6 item 1: a selector is a public 0/1 column.
            if let Some(s) = &l.selector {
                self.check_ref(s, l.vars, false)?;
                match &self.column(s.column)?.kind {
                    Kind::Public(v) if v.iter().all(|x| *x == 0 || *x == 1) => {}
                    _ => return Err(bad),
                }
            }
        }
        for r in &self.ranges {
            // §3.6 item 1: a range at most 16 bits wide, never on a public column.
            if !ok_width(&r.width)
                || r.width.bits > 16
                || matches!(self.column(r.column)?.kind, Kind::Public(_))
            {
                return Err(bad);
            }
        }
        for m in &self.matmuls {
            let domain = m.free.checked_add(m.summed).ok_or(bad)?;
            // §3.1 / A6: 1 ≤ free and free + summed ≤ MAX_VARS.
            if m.free == 0 || domain > MAX_VARS {
                return Err(bad);
            }
            self.check_ref(&m.out, m.free, true)?;
            self.check_ref(&m.lhs, domain, true)?;
            self.check_ref(&m.rhs, domain, true)?;
            // §3.6 item 2: B = mag(out) + 2^s·mag(lhs)·mag(rhs) < p.
            let b = self.product_bound(m)? + self.column(m.out.column)?.width.mag();
            if b >= p {
                return Err(bad);
            }
        }
        for c in &self.composes {
            let column = self.column(c.column)?;
            // §3.6 item 1: limbs, each of the column's length, shifts at most 30.
            if c.limbs.is_empty() {
                return Err(bad);
            }
            let mut bound = column.width.mag();
            for (limb, shift) in &c.limbs {
                let l = self.column(*limb)?;
                if l.log_len != column.log_len || *shift > 30 {
                    return Err(bad);
                }
                bound += l.width.mag() << shift;
            }
            // §3.5a: mag(column) + Σ 2^shift·mag(limb) < p.
            if bound >= p {
                return Err(bad);
            }
        }
        self.discipline()
    }

    /// `2^s·mag(lhs)·mag(rhs)` (below 2^90 for validated widths).
    fn product_bound(&self, m: &Matmul) -> Result<u128, Error> {
        let l = self.column(m.lhs.column)?.width.mag();
        let r = self.column(m.rhs.column)?.width.mag();
        (l * r)
            .checked_shl(u32::from(m.summed))
            .ok_or(Error::StatementMismatch)
    }

    /// §3.1 / §3.6 item 1 (A6): arity equal to `log_len`, non-fixed entries injective
    /// and inside the domain, fixed entries only in a matmul ref.
    fn check_ref(&self, r: &Ref, domain: u8, fixed: bool) -> Result<(), Error> {
        let c = self.column(r.column)?;
        let mut seen = 0u64;
        for v in &r.vars {
            if *v == FIXED_0 || *v == FIXED_1 {
                if !fixed {
                    return Err(Error::StatementMismatch);
                }
                continue;
            }
            if *v >= domain || seen & (1 << v) != 0 {
                return Err(Error::StatementMismatch);
            }
            seen |= 1 << v;
        }
        if r.vars.len() != usize::from(c.log_len) {
            return Err(Error::StatementMismatch);
        }
        Ok(())
    }

    /// §3.6 item 3 (A6): the least fixed point of the enforcement rules; then every
    /// witness and weight column is enforced.
    fn discipline(&self) -> Result<(), Error> {
        let n = self.columns.len();
        let mut enforced = reserve::<bool>(n)?;
        enforced.extend(
            self.columns
                .iter()
                .map(|c| matches!(c.kind, Kind::Public(_))),
        );
        loop {
            let mut changed = false;
            let mut mark = |id: u32, e: &mut Vec<bool>| {
                if !e[id as usize] {
                    e[id as usize] = true;
                    changed = true;
                }
            };
            for r in &self.ranges {
                if r.width.within(&self.columns[r.column as usize].width) {
                    mark(r.column, &mut enforced);
                }
            }
            for l in self.lookups.iter().filter(|l| l.selector.is_none()) {
                let table = &self.tables[l.table as usize];
                for (r, w) in l.tuple.iter().zip(&table.widths) {
                    if w.within(&self.columns[r.column as usize].width) {
                        mark(r.column, &mut enforced);
                    }
                }
            }
            for c in &self.composes {
                let (mut lo, mut hi) = (0i64, 0i64);
                let mut all = true;
                for (limb, shift) in &c.limbs {
                    let w = &self.columns[*limb as usize].width;
                    all &= enforced[*limb as usize];
                    lo += w.min() << shift;
                    hi += w.max() << shift;
                }
                let w = &self.columns[c.column as usize].width;
                if all && lo >= w.min() && hi <= w.max() {
                    mark(c.column, &mut enforced);
                }
            }
            for (id, column) in self.columns.iter().enumerate() {
                if enforced[id] {
                    continue;
                }
                let mut patterns = Vec::new();
                for m in self.matmuls.iter().filter(|m| m.out.column as usize == id) {
                    let bp = self.product_bound(m)?;
                    let w = column.width;
                    if enforced[m.lhs.column as usize]
                        && enforced[m.rhs.column as usize]
                        && bp <= w.max() as u128
                        && bp <= w.min().unsigned_abs() as u128
                    {
                        patterns.try_reserve(1).map_err(|_| Error::Capacity)?;
                        patterns.push(slice(&m.out)?);
                    }
                }
                if covers(&patterns)? {
                    mark(id as u32, &mut enforced);
                }
            }
            if !changed {
                break;
            }
        }
        // §3.6 item 3: every witness and weight column is enforced.
        if enforced.iter().all(|e| *e) {
            Ok(())
        } else {
            Err(Error::StatementMismatch)
        }
    }
}

/// A ref's slice: the fixed column bits and their constants (A6).
fn slice(r: &Ref) -> Result<Vec<(usize, bool)>, Error> {
    let mut out = reserve(r.vars.len())?;
    for (j, v) in r.vars.iter().enumerate() {
        if *v == FIXED_0 || *v == FIXED_1 {
            out.push((j, *v == FIXED_1));
        }
    }
    Ok(out)
}

/// Whether the slices cover every index: split on a fixed bit until some slice has
/// no constraint left (covered) or none remains (a gap).
fn covers(patterns: &[Vec<(usize, bool)>]) -> Result<bool, Error> {
    let Some(first) = patterns.first() else {
        return Ok(false);
    };
    if patterns.iter().any(|p| p.is_empty()) {
        return Ok(true);
    }
    let bit = first[0].0;
    for value in [false, true] {
        let mut branch = reserve(patterns.len())?;
        for p in patterns {
            if p.iter().all(|(j, v)| *j != bit || *v == value) {
                let mut rest = reserve(p.len())?;
                rest.extend(p.iter().filter(|(j, _)| *j != bit).copied());
                branch.push(rest);
            }
        }
        if !covers(&branch)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `2^k` as a usize, `None` past the word.
pub fn pow2(k: u8) -> Option<usize> {
    1usize.checked_shl(u32::from(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(bits: &[(usize, bool)]) -> Vec<(usize, bool)> {
        bits.to_vec()
    }

    #[test]
    fn covers_split_blocks_and_rejects_one_block() {
        let both = [pat(&[(3, false)]), pat(&[(3, true)])];
        assert_eq!(covers(&both), Ok(true));
        assert_eq!(covers(&both[..1]), Ok(false));
        let four = [
            pat(&[(3, false), (2, false)]),
            pat(&[(3, false), (2, true)]),
            pat(&[(3, true)]),
        ];
        assert_eq!(covers(&four), Ok(true));
        assert_eq!(covers(&four[1..]), Ok(false));
        assert_eq!(covers(&[pat(&[])]), Ok(true));
    }
}
