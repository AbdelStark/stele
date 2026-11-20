//! The relation of a development proof: its canonical decoding (RFC-0026 A15 §5, A27 §2,
//! RFC-0028 §2.5) and `Relation::validate` (RFC-0026 §3.6 with A6, A15 E1, A27, RFC-0028
//! §§2.1–2.3 and A1), tasks E8-02f1/E8-02f0b/E18-05a.
//!
//! Written from the RFC-0026 and RFC-0028 texts only (ADR-128): no production crate was
//! opened. Every failure here is `StatementMismatch`, raised before any proof byte is read
//! (A15 §6.0). Names are parsed and dropped: they do not enter the replay, only the digest
//! of the whole encoding does.

use crate::development::{reserve, Error, Reader};
use alloc::vec::Vec;
use stele_field::{Field, M31};

/// `MAX_VARS` (RFC-0026 §3.1).
pub const MAX_VARS: u8 = 30;
/// `(p - 1) / 2` (RFC-0028 §2.2: strict `< p / 2` bound for virtual derived magnitudes).
pub const HALF_MODULUS: u128 = ((M31::MODULUS as u128) - 1) / 2;
/// A matmul ref's fixed bits (RFC-0026 A6).
pub const FIXED_0: u8 = 0xFE;
pub const FIXED_1: u8 = 0xFF;
const MAGIC: &[u8; 31] = b"stele/v0.1/relation/encoding/v1";
const MAGIC_V2: &[u8; 31] = b"stele/v0.1/relation/encoding/v2";

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

/// Virtual column definition (RFC-0028 §2.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Def {
    Linear {
        constant: i64,
        terms: Vec<(i64, Ref)>,
    },
    Pointwise {
        terms: Vec<Term>,
    },
    Contraction {
        free: u8,
        summed: u8,
        lhs: Ref,
        rhs: Ref,
    },
}

impl Def {
    /// Invoke `f` on every operand column id referenced by this definition.
    pub fn for_each_operand(&self, mut f: impl FnMut(u32)) {
        match self {
            Def::Linear { terms, .. } => {
                for (_, r) in terms {
                    f(r.column);
                }
            }
            Def::Pointwise { terms } => {
                for t in terms {
                    for fac in &t.factors {
                        f(fac.column);
                    }
                }
            }
            Def::Contraction { lhs, rhs, .. } => {
                f(lhs.column);
                f(rhs.column);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    Witness(u32),
    Weight,
    Public(Vec<i64>),
    Virtual(Def),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    pub kind: Kind,
    pub width: Width,
    pub log_len: u8,
    /// Optional explicit segment for a weight/public-only virtual column (RFC-0028 §2.3).
    pub segment: Option<u32>,
    /// Carried witness column readable by segment `s + 1` (RFC-0026 A27, RFC-0028 §2.3).
    pub carried: bool,
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

/// A decoded relation; ids are positions (A15 §5, A27 §2, RFC-0028 §2.5).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Relation {
    /// Each group's `log_len`.
    pub groups: Vec<u8>,
    /// Each group's name (§2.3: names are distinct).
    pub group_names: Vec<Vec<u8>>,
    /// Each group's segment number (0 in v1; RFC-0026 A27 in v2).
    pub group_segments: Vec<u32>,
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
    let bytes = r.take(n)?;
    let mut vars = reserve(n)?;
    vars.extend_from_slice(bytes);
    Ok(Ref { column, vars })
}

/// RFC-0026 A15 §§1,5: names are UTF-8 even when only their encoded digest is used.
fn name<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let bytes = r.blob()?;
    core::str::from_utf8(bytes).map_err(|_| Error::StatementMismatch)?;
    Ok(bytes)
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

fn term_decode(r: &mut Reader) -> Result<Term, Error> {
    let coeff = r.i64()?;
    let n = usize::from(r.u8()?);
    r.check_count(n, 5)?;
    let mut factors = reserve(n)?;
    for _ in 0..n {
        factors.push(reference(r)?);
    }
    Ok(Term { coeff, factors })
}

impl Relation {
    /// A15 §5 / A27 §2 / RFC-0028 §2.5: the canonical v1 or v2 encoding, exactly, with
    /// nothing after it.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let r = &mut Reader::new(bytes, Error::StatementMismatch);
        let magic = r.take(MAGIC.len())?;
        let v2 = if magic == MAGIC {
            false
        } else if magic == MAGIC_V2 {
            true
        } else {
            return Err(Error::StatementMismatch);
        };
        let named = list(r, if v2 { 9 } else { 5 }, |r| {
            let name = name(r)?;
            let mut owned = reserve(name.len())?;
            owned.extend_from_slice(name);
            let log_len = r.u8()?;
            let seg = if v2 { r.u32()? } else { 0 };
            Ok((owned, log_len, seg))
        })?;
        let mut groups = reserve(named.len())?;
        groups.extend(named.iter().map(|(_, n, _)| *n));
        let mut group_segments = reserve(named.len())?;
        group_segments.extend(named.iter().map(|(_, _, s)| *s));
        let mut group_names = reserve(named.len())?;
        group_names.extend(named.into_iter().map(|(name, _, _)| name));
        let columns = list(r, if v2 { 9 } else { 8 }, |r| {
            name(r)?;
            let mut segment = None;
            let kind = match r.u8()? {
                0 => Kind::Witness(r.u32()?),
                1 => Kind::Weight,
                2 => Kind::Public(list(r, 8, |r| r.i64())?),
                3 if v2 => {
                    let def = match r.u8()? {
                        0 => Def::Linear {
                            constant: r.i64()?,
                            terms: list(r, 13, |r| Ok((r.i64()?, reference(r)?)))?,
                        },
                        1 => Def::Pointwise {
                            terms: list(r, 9, term_decode)?,
                        },
                        2 => Def::Contraction {
                            free: r.u8()?,
                            summed: r.u8()?,
                            lhs: reference(r)?,
                            rhs: reference(r)?,
                        },
                        _ => return Err(Error::StatementMismatch),
                    };
                    segment = match r.u8()? {
                        0 => None,
                        1 => Some(r.u32()?),
                        _ => return Err(Error::StatementMismatch),
                    };
                    Kind::Virtual(def)
                }
                _ => return Err(Error::StatementMismatch),
            };
            let w = width(r)?;
            let log_len = r.u8()?;
            let carried = if v2 {
                match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::StatementMismatch),
                }
            } else {
                false
            };
            Ok(Column {
                kind,
                width: w,
                log_len,
                segment,
                carried,
            })
        })?;
        let tables = list(r, 12, |r| {
            name(r)?;
            Ok(Table {
                widths: list(r, 2, width)?,
                rows: list(r, 4, |r| list(r, 8, |r| r.i64()))?,
            })
        })?;
        let identities = list(r, 9, |r| {
            name(r)?;
            Ok(Identity {
                vars: r.u8()?,
                terms: list(r, 9, term_decode)?,
            })
        })?;
        let lookups = list(r, 14, |r| {
            name(r)?;
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
            name(r)?;
            Ok(Range {
                column: r.u32()?,
                width: width(r)?,
            })
        })?;
        let matmuls = list(r, 21, |r| {
            name(r)?;
            Ok(Matmul {
                free: r.u8()?,
                summed: r.u8()?,
                out: reference(r)?,
                lhs: reference(r)?,
                rhs: reference(r)?,
            })
        })?;
        let composes = list(r, 12, |r| {
            name(r)?;
            Ok(Compose {
                column: r.u32()?,
                limbs: list(r, 5, |r| Ok((r.u32()?, r.u8()?)))?,
            })
        })?;
        r.end()?;
        Ok(Relation {
            groups,
            group_names,
            group_segments,
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

    pub fn group_segment(&self, g: usize) -> u32 {
        self.group_segments.get(g).copied().unwrap_or(0)
    }

    /// True if any column is `Kind::Virtual` (RFC-0028 §2.1).
    pub fn has_virtual(&self) -> bool {
        self.columns
            .iter()
            .any(|c| matches!(c.kind, Kind::Virtual(_)))
    }

    /// True if any group sits in a non-zero segment, any column is carried, or any
    /// virtual column specifies an explicit segment (RFC-0026 A27, RFC-0028 §2.3).
    pub fn is_segmented(&self) -> bool {
        self.group_segments.iter().any(|&s| s != 0)
            || self
                .columns
                .iter()
                .any(|c| c.carried || c.segment.is_some())
    }

    /// Number of segments (`>= 1`).
    pub fn segments(&self) -> u32 {
        self.group_segments
            .iter()
            .copied()
            .max()
            .map_or(1, |m| m.saturating_add(1))
    }

    /// Owning segment of every column in one forward pass (RFC-0026 A27, RFC-0028 §2.3).
    pub fn column_segments(&self) -> Result<Vec<Option<u32>>, Error> {
        let mut segs = reserve(self.columns.len())?;
        for (i, col) in self.columns.iter().enumerate() {
            let seg = match &col.kind {
                Kind::Witness(g) => {
                    if (*g as usize) < self.groups.len() {
                        Some(self.group_segment(*g as usize))
                    } else {
                        None
                    }
                }
                Kind::Weight | Kind::Public(_) => None,
                Kind::Virtual(def) => {
                    let mut max_seg: Option<u32> = None;
                    def.for_each_operand(|op| {
                        if (op as usize) < i {
                            if let Some(s) = segs[op as usize] {
                                max_seg = Some(max_seg.map_or(s, |cur| cur.max(s)));
                            }
                        }
                    });
                    Some(max_seg.unwrap_or_else(|| col.segment.unwrap_or(0)))
                }
            };
            segs.push(seg);
        }
        Ok(segs)
    }

    /// Earliest witness/virtual-bearing segment reading each weight column (RFC-0026 A27 §1).
    pub fn weight_segments(&self, col_segs: &[Option<u32>]) -> Result<Vec<u32>, Error> {
        let mut out = reserve(self.columns.len())?;
        out.resize(self.columns.len(), u32::MAX);
        let mut note = |id: u32, seg: u32| {
            if let Some(c) = self.columns.get(id as usize) {
                if matches!(c.kind, Kind::Weight) && seg < out[id as usize] {
                    out[id as usize] = seg;
                }
            }
        };
        for (i, col) in self.columns.iter().enumerate() {
            if let Kind::Virtual(def) = &col.kind {
                if let Some(seg) = col_segs[i] {
                    def.for_each_operand(|op| note(op, seg));
                }
            }
        }
        for id in &self.identities {
            let mut max_seg: Option<u32> = None;
            for t in &id.terms {
                for f in &t.factors {
                    if let Some(s) = col_segs.get(f.column as usize).copied().flatten() {
                        max_seg = Some(max_seg.map_or(s, |cur| cur.max(s)));
                    }
                }
            }
            if let Some(seg) = max_seg {
                for t in &id.terms {
                    for f in &t.factors {
                        note(f.column, seg);
                    }
                }
            }
        }
        for c in &self.composes {
            let mut max_seg = col_segs.get(c.column as usize).copied().flatten();
            for &(l, _) in &c.limbs {
                if let Some(s) = col_segs.get(l as usize).copied().flatten() {
                    max_seg = Some(max_seg.map_or(s, |cur| cur.max(s)));
                }
            }
            if let Some(seg) = max_seg {
                note(c.column, seg);
                for &(l, _) in &c.limbs {
                    note(l, seg);
                }
            }
        }
        for l in &self.lookups {
            let mut max_seg: Option<u32> = None;
            for r in l.tuple.iter().chain(l.selector.iter()) {
                if let Some(s) = col_segs.get(r.column as usize).copied().flatten() {
                    max_seg = Some(max_seg.map_or(s, |cur| cur.max(s)));
                }
            }
            if let Some(seg) = max_seg {
                for r in l.tuple.iter().chain(l.selector.iter()) {
                    note(r.column, seg);
                }
            }
        }
        for m in &self.matmuls {
            let mut max_seg: Option<u32> = None;
            for id in [m.out.column, m.lhs.column, m.rhs.column] {
                if let Some(s) = col_segs.get(id as usize).copied().flatten() {
                    max_seg = Some(max_seg.map_or(s, |cur| cur.max(s)));
                }
            }
            if let Some(seg) = max_seg {
                for id in [m.out.column, m.lhs.column, m.rhs.column] {
                    note(id, seg);
                }
            }
        }
        for slot in &mut out {
            if *slot == u32::MAX {
                *slot = 0;
            }
        }
        Ok(out)
    }

    pub fn identity_segment_with(&self, id: &Identity, col_segs: &[Option<u32>]) -> u32 {
        id.terms
            .iter()
            .flat_map(|t| t.factors.iter())
            .filter_map(|f| col_segs.get(f.column as usize).copied().flatten())
            .max()
            .unwrap_or(0)
    }

    pub fn compose_segment_with(&self, c: &Compose, col_segs: &[Option<u32>]) -> u32 {
        core::iter::once(c.column)
            .chain(c.limbs.iter().map(|(l, _)| *l))
            .filter_map(|id| col_segs.get(id as usize).copied().flatten())
            .max()
            .unwrap_or(0)
    }

    pub fn lookup_segment_with(&self, l: &Lookup, col_segs: &[Option<u32>]) -> u32 {
        l.tuple
            .iter()
            .chain(l.selector.iter())
            .filter_map(|r| col_segs.get(r.column as usize).copied().flatten())
            .max()
            .unwrap_or(0)
    }

    pub fn range_segment_with(
        &self,
        r: &Range,
        col_segs: &[Option<u32>],
        weight_segs: &[u32],
    ) -> u32 {
        col_segs
            .get(r.column as usize)
            .copied()
            .flatten()
            .unwrap_or_else(|| weight_segs.get(r.column as usize).copied().unwrap_or(0))
    }

    pub fn matmul_segment_with(&self, m: &Matmul, col_segs: &[Option<u32>]) -> u32 {
        [m.out.column, m.lhs.column, m.rhs.column]
            .into_iter()
            .filter_map(|id| col_segs.get(id as usize).copied().flatten())
            .max()
            .unwrap_or(0)
    }

    fn check_item_segment(
        &self,
        cols: impl Iterator<Item = u32> + Clone,
        col_segs: &[Option<u32>],
    ) -> Result<(), Error> {
        let Some(max_seg) = cols
            .clone()
            .filter_map(|id| col_segs.get(id as usize).copied().flatten())
            .max()
        else {
            return Ok(());
        };
        for id in cols {
            if let Some(seg) = col_segs.get(id as usize).copied().flatten() {
                let col = self.column(id)?;
                if !(seg == max_seg || (seg.checked_add(1) == Some(max_seg) && col.carried)) {
                    return Err(Error::StatementMismatch);
                }
            }
        }
        Ok(())
    }

    /// RFC-0026 §3.6 (with A6, A15 E1, A27) and RFC-0028 §§2.1–2.3 + A1: shapes,
    /// derived virtual magnitudes, bound rule, segment boundaries and range discipline.
    /// Any failure is `StatementMismatch` (A15 §6.0).
    pub fn validate(&self) -> Result<(), Error> {
        let bad = Error::StatementMismatch;
        let p = u128::from(M31::MODULUS);
        let ok_width = |w: &Width| (1..=30).contains(&w.bits);
        // RFC-0028 A1: precompute valid whole-column range tightenings per column.
        let mut range_tight = reserve(self.columns.len())?;
        range_tight.resize(self.columns.len(), u128::MAX);
        for r in &self.ranges {
            if let Some(slot) = range_tight.get_mut(r.column as usize) {
                if (1..=16).contains(&r.width.bits) {
                    *slot = (*slot).min(r.width.mag());
                }
            }
        }
        let mut mags = reserve(self.columns.len())?;
        for (i, c) in self.columns.iter().enumerate() {
            if c.log_len > MAX_VARS {
                return Err(bad);
            }
            if c.carried && !matches!(c.kind, Kind::Witness(_)) {
                return Err(bad);
            }
            if c.segment.is_some() && !matches!(c.kind, Kind::Virtual(_)) {
                return Err(bad);
            }
            let mag = match &c.kind {
                // §3.6 item 1: a public column's length and values fit its declaration.
                Kind::Public(values) => {
                    if !ok_width(&c.width) {
                        return Err(bad);
                    }
                    let fits = values
                        .iter()
                        .all(|v| *v >= c.width.min() && *v <= c.width.max());
                    if pow2(c.log_len) != Some(values.len()) || !fits {
                        return Err(bad);
                    }
                    c.width.mag()
                }
                // §3.6 item 1: a witness column's group exists with its log_len.
                Kind::Witness(g) => {
                    if !ok_width(&c.width) || self.groups.get(*g as usize) != Some(&c.log_len) {
                        return Err(bad);
                    }
                    c.width.mag()
                }
                Kind::Weight => {
                    if !ok_width(&c.width) {
                        return Err(bad);
                    }
                    c.width.mag()
                }
                // RFC-0028 §§2.1–2.2 + A1: virtual column definition & derived magnitude.
                Kind::Virtual(def) => {
                    if c.width
                        != (Width {
                            signed: false,
                            bits: 0,
                        })
                    {
                        return Err(bad);
                    }
                    let id = i as u32;
                    let raw = match def {
                        Def::Linear { constant, terms } => {
                            let mut acc = u128::from(constant.unsigned_abs());
                            for (coeff, r) in terms {
                                if *coeff == 0 || r.column >= id {
                                    return Err(bad);
                                }
                                self.check_ref(r, c.log_len, false)?;
                                acc = acc.saturating_add(
                                    u128::from(coeff.unsigned_abs())
                                        .saturating_mul(mags[r.column as usize]),
                                );
                            }
                            acc
                        }
                        Def::Pointwise { terms } => {
                            if terms.is_empty() {
                                return Err(bad);
                            }
                            let mut acc = 0u128;
                            for t in terms {
                                if t.factors.len() > 3 || t.coeff == 0 {
                                    return Err(bad);
                                }
                                let mut prod = u128::from(t.coeff.unsigned_abs());
                                for f in &t.factors {
                                    if f.column >= id {
                                        return Err(bad);
                                    }
                                    self.check_ref(f, c.log_len, false)?;
                                    prod = prod.saturating_mul(mags[f.column as usize]);
                                }
                                acc = acc.saturating_add(prod);
                            }
                            acc
                        }
                        Def::Contraction {
                            free,
                            summed,
                            lhs,
                            rhs,
                        } => {
                            if *free != c.log_len || *summed > MAX_VARS {
                                return Err(bad);
                            }
                            let domain = *free + *summed;
                            if lhs.column >= id || rhs.column >= id {
                                return Err(bad);
                            }
                            self.check_ref(lhs, domain, true)?;
                            self.check_ref(rhs, domain, true)?;
                            (1u128 << *summed)
                                .saturating_mul(mags[lhs.column as usize])
                                .saturating_mul(mags[rhs.column as usize])
                        }
                    };
                    if raw > HALF_MODULUS {
                        return Err(bad);
                    }
                    raw.min(range_tight[i])
                }
            };
            mags.push(mag);
        }
        // §2.3 group naming & A27 contiguous non-decreasing segments.
        let mut prev_seg: Option<u32> = None;
        for (n, name) in self.group_names.iter().enumerate() {
            if self.group_names[n + 1..].contains(name) {
                return Err(bad);
            }
            let seg = self.group_segment(n);
            let seg_ok = match prev_seg {
                None => seg == 0,
                Some(prev) => seg == prev || prev.checked_add(1) == Some(seg),
            };
            if !seg_ok {
                return Err(bad);
            }
            prev_seg = Some(seg);
        }
        let total_segments = self.segments();
        let col_segs = self.column_segments()?;
        for c in &self.columns {
            if let Kind::Virtual(def) = &c.kind {
                let mut ops = Vec::new();
                def.for_each_operand(|op| ops.push(op));
                let op_max = ops
                    .iter()
                    .filter_map(|&id| col_segs.get(id as usize).copied().flatten())
                    .max();
                match op_max {
                    Some(_) => {
                        if c.segment.is_some() {
                            return Err(bad);
                        }
                        self.check_item_segment(ops.into_iter(), &col_segs)?;
                    }
                    None => {
                        if let Some(explicit) = c.segment {
                            if explicit >= total_segments {
                                return Err(bad);
                            }
                        }
                    }
                }
            }
        }
        for t in &self.tables {
            // §3.6 item 1 / A15 E1 item 3: nonempty widths and rows, with at most
            // 2^16 rows, each of the table's arity and inside its valid widths.
            if t.widths.is_empty()
                || t.rows.is_empty()
                || t.rows.len() > 1 << 16
                || !t.widths.iter().all(ok_width)
            {
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
            // An identity with no term (review of #381).
            if i.vars > MAX_VARS || i.terms.is_empty() {
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
                    b = b.checked_mul(mags[f.column as usize]).ok_or(bad)?;
                }
                bound = bound.checked_add(b).ok_or(bad)?;
            }
            // §3.6 item 2: B = Σ|c_t|·Π mag(width_f) < p.
            if bound >= p {
                return Err(bad);
            }
            self.check_item_segment(
                i.terms
                    .iter()
                    .flat_map(|t| t.factors.iter().map(|f| f.column)),
                &col_segs,
            )?;
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
            self.check_item_segment(
                l.tuple.iter().chain(l.selector.iter()).map(|r| r.column),
                &col_segs,
            )?;
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
            // §3.1: free + summed ≤ MAX_VARS.
            if domain > MAX_VARS {
                return Err(bad);
            }
            self.check_ref(&m.out, m.free, true)?;
            self.check_ref(&m.lhs, domain, true)?;
            self.check_ref(&m.rhs, domain, true)?;
            // §3.6 item 2: B = mag(out) + 2^s·mag(lhs)·mag(rhs) < p.
            let b = self
                .product_bound(m, &mags)?
                .checked_add(mags[m.out.column as usize])
                .ok_or(bad)?;
            if b >= p {
                return Err(bad);
            }
            self.check_item_segment(
                [m.out.column, m.lhs.column, m.rhs.column].into_iter(),
                &col_segs,
            )?;
        }
        for c in &self.composes {
            let column = self.column(c.column)?;
            // §3.6 item 1: limbs, each of the column's length, shifts at most 30.
            if c.limbs.is_empty() {
                return Err(bad);
            }
            let mut bound = mags[c.column as usize];
            for (limb, shift) in &c.limbs {
                let l = self.column(*limb)?;
                if l.log_len != column.log_len || *shift > 30 {
                    return Err(bad);
                }
                bound = bound
                    .checked_add(mags[*limb as usize] << shift)
                    .ok_or(bad)?;
            }
            // §3.5a: mag(column) + Σ 2^shift·mag(limb) < p.
            if bound >= p {
                return Err(bad);
            }
            self.check_item_segment(
                core::iter::once(c.column).chain(c.limbs.iter().map(|(l, _)| *l)),
                &col_segs,
            )?;
        }
        self.discipline(&mags)
    }

    /// `2^s·mag(lhs)·mag(rhs)` (below 2^90 for validated widths).
    fn product_bound(&self, m: &Matmul, mags: &[u128]) -> Result<u128, Error> {
        let l = mags[m.lhs.column as usize];
        let r = mags[m.rhs.column as usize];
        l.checked_mul(r)
            .and_then(|p| p.checked_shl(u32::from(m.summed)))
            .ok_or(Error::StatementMismatch)
    }

    /// §3.1 / §3.6 item 1 (A6): arity equal to `log_len`, non-fixed entries injective
    /// and inside the domain, fixed entries only in a matmul/contraction ref.
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
            if *v >= domain || seen & (1u64 << v) != 0 {
                return Err(Error::StatementMismatch);
            }
            seen |= 1u64 << v;
        }
        if r.vars.len() != usize::from(c.log_len) {
            return Err(Error::StatementMismatch);
        }
        Ok(())
    }

    /// §3.6 item 3 (A6, A15 E1) & RFC-0028 §2.2: seed, virtual, compose, snapshot and
    /// matmul passes until unchanged; then every witness and weight column is enforced.
    fn discipline(&self, mags: &[u128]) -> Result<(), Error> {
        let n = self.columns.len();
        let mut enforced = reserve::<bool>(n)?;
        enforced.extend(
            self.columns
                .iter()
                .map(|c| matches!(c.kind, Kind::Public(_))),
        );
        for r in &self.ranges {
            let col = &self.columns[r.column as usize];
            if !matches!(col.kind, Kind::Virtual(_)) && r.width.within(&col.width) {
                enforced[r.column as usize] = true;
            }
        }
        for l in self.lookups.iter().filter(|l| l.selector.is_none()) {
            let table = &self.tables[l.table as usize];
            for (r, w) in l.tuple.iter().zip(&table.widths) {
                let col = &self.columns[r.column as usize];
                if !matches!(col.kind, Kind::Virtual(_)) && w.within(&col.width) {
                    enforced[r.column as usize] = true;
                }
            }
        }
        let mut snapshot = reserve(n)?;
        snapshot.resize(n, false);
        loop {
            let mut changed = false;
            let mut mark = |id: u32, e: &mut Vec<bool>| {
                if !e[id as usize] {
                    e[id as usize] = true;
                    changed = true;
                }
            };
            for (id, col) in self.columns.iter().enumerate() {
                if enforced[id] {
                    continue;
                }
                if let Kind::Virtual(def) = &col.kind {
                    let mut all = true;
                    def.for_each_operand(|op| all &= enforced[op as usize]);
                    if all {
                        mark(id as u32, &mut enforced);
                    }
                }
            }
            for c in &self.composes {
                let target = &self.columns[c.column as usize];
                if matches!(target.kind, Kind::Virtual(_)) || enforced[c.column as usize] {
                    continue;
                }
                let (mut lo, mut hi) = (0i128, 0i128);
                let mut all = true;
                for (limb, shift) in &c.limbs {
                    let lc = &self.columns[*limb as usize];
                    all &= enforced[*limb as usize];
                    let (min_v, max_v) = match lc.kind {
                        Kind::Virtual(_) => {
                            let m = mags[*limb as usize] as i128;
                            (-m, m)
                        }
                        _ => (i128::from(lc.width.min()), i128::from(lc.width.max())),
                    };
                    lo += min_v << shift;
                    hi += max_v << shift;
                }
                let w = &target.width;
                if all && lo >= i128::from(w.min()) && hi <= i128::from(w.max()) {
                    mark(c.column, &mut enforced);
                }
            }
            // A15 E1 item 3: new matmul outputs cannot change this pass's eligible sets.
            snapshot.copy_from_slice(&enforced);
            for (id, column) in self.columns.iter().enumerate() {
                if snapshot[id] || matches!(column.kind, Kind::Virtual(_)) {
                    continue;
                }
                let mut patterns = Vec::new();
                for m in self.matmuls.iter().filter(|m| m.out.column as usize == id) {
                    let bp = self.product_bound(m, mags)?;
                    let w = column.width;
                    if snapshot[m.lhs.column as usize]
                        && snapshot[m.rhs.column as usize]
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
        // §3.6 item 3 & RFC-0028 §2.2: every witness and weight column is enforced.
        if self
            .columns
            .iter()
            .enumerate()
            .all(|(i, c)| !matches!(c.kind, Kind::Witness(_) | Kind::Weight) || enforced[i])
        {
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

/// Most distinct fixed positions [`covers`] searches; past it the column is not
/// disciplined (RFC-0026 A15 E1 item 3: bounds the search at 2^16 leaves).
const MAX_COVER_BITS: usize = 16;

/// Whether the slices cover every index. Past [`MAX_COVER_BITS`] distinct fixed
/// positions the answer is "no", so the column stays undisciplined.
fn covers(patterns: &[Vec<(usize, bool)>]) -> Result<bool, Error> {
    let mut positions = 0u64;
    for p in patterns {
        for (j, _) in p {
            positions |= 1u64.checked_shl(*j as u32).unwrap_or(0);
        }
    }
    if positions.count_ones() as usize > MAX_COVER_BITS {
        return Ok(false);
    }
    split(patterns)
}

/// Split on a fixed bit until some slice has no constraint left (covered) or none
/// remains (a gap).
fn split(patterns: &[Vec<(usize, bool)>]) -> Result<bool, Error> {
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
        if !split(&branch)? {
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

    fn unsigned(bits: u8) -> Width {
        Width {
            signed: false,
            bits,
        }
    }

    fn whole(column: u32) -> Ref {
        Ref {
            column,
            vars: alloc::vec![0],
        }
    }

    fn col(kind: Kind, width: Width, log_len: u8) -> Column {
        Column {
            kind,
            width,
            log_len,
            segment: None,
            carried: false,
        }
    }

    /// A witness `w` (unsigned 8, ranged) equal to a public `c`: `w − c = 0`.
    fn small() -> Relation {
        Relation {
            groups: alloc::vec![1],
            group_names: alloc::vec![b"g".to_vec()],
            columns: alloc::vec![
                col(Kind::Witness(0), unsigned(8), 1),
                col(Kind::Public(alloc::vec![3, 200]), unsigned(8), 1),
            ],
            identities: alloc::vec![Identity {
                vars: 1,
                terms: alloc::vec![
                    Term {
                        coeff: 1,
                        factors: alloc::vec![whole(0)],
                    },
                    Term {
                        coeff: -1,
                        factors: alloc::vec![whole(1)],
                    },
                ],
            }],
            ranges: alloc::vec![Range {
                column: 0,
                width: unsigned(8),
            }],
            ..Relation::default()
        }
    }

    /// §3.6: each rule, one change at a time, on a relation that validates.
    #[test]
    fn rejects_each_section_3_6_rule() {
        assert_eq!(small().validate(), Ok(()));
        let bad: [fn(&mut Relation); 11] = [
            // An empty identity, and two groups of one name.
            |r| r.identities[0].terms.clear(),
            |r| {
                r.groups.push(1);
                r.group_names = alloc::vec![b"g".to_vec(), b"g".to_vec()];
            },
            // item 3: the witness is no longer enforced.
            |r| r.ranges.clear(),
            // item 3: a range wider than the column does not enforce it.
            |r| r.ranges[0].width = unsigned(9),
            // item 1: a zero coefficient.
            |r| r.identities[0].terms[0].coeff = 0,
            // item 2: B = Σ|c|·Π mag ≥ p.
            |r| r.identities[0].terms[0].coeff = 1 << 24,
            // item 1: a ref of the wrong arity, and a fixed bit outside a matmul.
            |r| r.identities[0].terms[0].factors[0].vars.push(0),
            |r| r.identities[0].terms[0].factors[0].vars[0] = FIXED_0,
            // item 1: a public value outside its width, and a range on a public column.
            |r| r.columns[1].kind = Kind::Public(alloc::vec![3, 256]),
            |r| r.ranges[0].column = 1,
            // item 1: a witness whose group has another length.
            |r| r.groups[0] = 2,
        ];
        for (i, f) in bad.iter().enumerate() {
            let mut r = small();
            f(&mut r);
            assert_eq!(r.validate(), Err(Error::StatementMismatch), "rule {i}");
        }
    }

    #[test]
    fn rejects_a15_empty_table_widths() {
        let mut r = small();
        // A15 E1 item 3 applies even when no lookup reads the table.
        r.tables.push(Table {
            widths: alloc::vec![unsigned(2)],
            rows: alloc::vec![alloc::vec![0]],
        });
        assert_eq!(r.validate(), Ok(()));
        r.tables[0].widths.clear();
        r.tables[0].rows[0].clear();
        assert_eq!(r.validate(), Err(Error::StatementMismatch));
    }

    #[test]
    fn rejects_a15_empty_table_rows() {
        for used in [false, true] {
            let mut r = small();
            r.tables.push(Table {
                widths: alloc::vec![unsigned(8)],
                rows: alloc::vec![alloc::vec![3], alloc::vec![200]],
            });
            if used {
                r.lookups.push(Lookup {
                    vars: 1,
                    selector: None,
                    tuple: alloc::vec![whole(0)],
                    table: 0,
                });
            }
            assert_eq!(r.validate(), Ok(()));
            r.tables[0].rows.clear();
            assert_eq!(r.validate(), Err(Error::StatementMismatch), "used={used}");
        }
    }

    #[test]
    fn rejects_a15_column_domains_above_thirty_before_planning() {
        for kind in [Kind::Weight, Kind::Witness(0)] {
            let witness = matches!(kind, Kind::Witness(_));
            let mut r = Relation {
                groups: if witness { alloc::vec![30] } else { Vec::new() },
                group_names: if witness {
                    alloc::vec![b"g".to_vec()]
                } else {
                    Vec::new()
                },
                columns: alloc::vec![col(kind, unsigned(8), 30)],
                ranges: alloc::vec![Range {
                    column: 0,
                    width: unsigned(8),
                }],
                ..Relation::default()
            };
            assert_eq!(r.validate(), Ok(()));
            r.columns[0].log_len = 31;
            if witness {
                r.groups[0] = 31;
            }
            // A15 E1 item 3: Column/StatementMismatch precedes source Unsupported.
            assert_eq!(
                (r.validate(), crate::plan::Plan::derive(&r).map(|_| ())),
                (Err(Error::StatementMismatch), Err(Error::StatementMismatch)),
                "kind={:?}",
                r.columns[0].kind
            );
        }
        let mut public = Relation {
            columns: alloc::vec![col(Kind::Public(alloc::vec![0]), unsigned(1), 0)],
            ..Relation::default()
        };
        assert_eq!(public.validate(), Ok(()));
        public.columns[0].log_len = 31;
        assert_eq!(public.validate(), Err(Error::StatementMismatch));
        assert_eq!(
            crate::plan::Plan::derive(&public),
            Err(Error::StatementMismatch)
        );
    }

    #[test]
    fn accepts_a15_matmul_enforcement_snapshot() {
        // A15 E1's golden relation: d is unavailable to o's slices in this pass.
        let mut r = Relation {
            groups: alloc::vec![0, 17],
            group_names: alloc::vec![b"d".to_vec(), b"o".to_vec()],
            columns: alloc::vec![
                col(
                    Kind::Witness(0),
                    Width {
                        signed: true,
                        bits: 8
                    },
                    0,
                ),
                col(
                    Kind::Witness(1),
                    Width {
                        signed: true,
                        bits: 10
                    },
                    17,
                ),
                col(
                    Kind::Public(alloc::vec![1]),
                    Width {
                        signed: true,
                        bits: 2
                    },
                    0,
                ),
            ],
            ..Relation::default()
        };
        let one = Ref {
            column: 2,
            vars: Vec::new(),
        };
        for (column, free) in [(0, 0), (1, 17)] {
            r.matmuls.push(Matmul {
                free,
                summed: 0,
                out: Ref {
                    column,
                    vars: (0..free).collect(),
                },
                lhs: one.clone(),
                rhs: one.clone(),
            });
        }
        for j in 0..17 {
            let mut vars: Vec<u8> = (0..16).collect();
            vars.insert(j, FIXED_0);
            r.matmuls.push(Matmul {
                free: 16,
                summed: 0,
                out: Ref { column: 1, vars },
                lhs: Ref {
                    column: 0,
                    vars: Vec::new(),
                },
                rhs: one.clone(),
            });
        }
        assert_eq!(r.validate(), Ok(()));
    }

    #[test]
    fn rejects_a15_matmul_cover_past_sixteen_fixed_positions() {
        // A15 E1's covers-cap golden relation covers o, but fixes 17 positions.
        let mut r = Relation {
            groups: alloc::vec![17],
            group_names: alloc::vec![b"G/o/17".to_vec()],
            columns: alloc::vec![
                col(
                    Kind::Witness(0),
                    Width {
                        signed: true,
                        bits: 8
                    },
                    17,
                ),
                col(
                    Kind::Public(alloc::vec![1]),
                    Width {
                        signed: true,
                        bits: 2
                    },
                    0,
                ),
            ],
            ..Relation::default()
        };
        let one = Ref {
            column: 1,
            vars: Vec::new(),
        };
        for j in 0..17 {
            for fixed in [FIXED_0, FIXED_1] {
                let mut vars: Vec<u8> = (0..16).collect();
                vars.insert(j, fixed);
                r.matmuls.push(Matmul {
                    free: 16,
                    summed: 0,
                    out: Ref { column: 0, vars },
                    lhs: one.clone(),
                    rhs: one.clone(),
                });
            }
        }
        assert_eq!(r.validate(), Err(Error::StatementMismatch));
        r.matmuls.truncate(2);
        assert_eq!(r.validate(), Ok(()));
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
        // 17 distinct fixed positions are past the cap, even when they cover.
        let mut wide = alloc::vec![pat(&[(0, false)]), pat(&[(0, true)])];
        wide.extend((1..17).map(|j| pat(&[(j, false), (0, false)])));
        assert_eq!(covers(&wide[..2]), Ok(true));
        assert_eq!(covers(&wide), Ok(false));
    }

    #[test]
    fn validates_rfc0028_virtual_columns_a1_tightening_and_segments() {
        let mut r = Relation {
            groups: alloc::vec![1, 1],
            group_names: alloc::vec![b"s0".to_vec(), b"s1".to_vec()],
            group_segments: alloc::vec![0, 1],
            columns: alloc::vec![
                Column {
                    kind: Kind::Witness(0),
                    width: unsigned(16),
                    log_len: 1,
                    segment: None,
                    carried: true,
                },
                Column {
                    kind: Kind::Witness(0),
                    width: unsigned(16),
                    log_len: 1,
                    segment: None,
                    carried: false,
                },
                // Virtual Linear in segment 0 whose raw mag = 2^16 * 65535 + 65535 > 2^30 (too wide),
                // first test a wrap-free Linear with raw mag = 1000 * 65535 <= HALF_MODULUS,
                // tightened by a u8 Range so downstream 2^16 * v stays < p/2 (RFC-0028 A1).
                Column {
                    kind: Kind::Virtual(Def::Linear {
                        constant: 0,
                        terms: alloc::vec![(1000, whole(0))],
                    }),
                    width: Width {
                        signed: false,
                        bits: 0,
                    },
                    log_len: 1,
                    segment: None,
                    carried: false,
                },
                Column {
                    kind: Kind::Virtual(Def::Linear {
                        constant: 0,
                        terms: alloc::vec![(1 << 16, whole(2))],
                    }),
                    width: Width {
                        signed: false,
                        bits: 0,
                    },
                    log_len: 1,
                    segment: None,
                    carried: false,
                },
                // Segment 1 witness reading carried column 0 via virtual Linear.
                Column {
                    kind: Kind::Witness(1),
                    width: unsigned(8),
                    log_len: 1,
                    segment: None,
                    carried: false,
                },
                Column {
                    kind: Kind::Virtual(Def::Linear {
                        constant: 0,
                        terms: alloc::vec![(1, whole(0)), (-1, whole(4))],
                    }),
                    width: Width {
                        signed: false,
                        bits: 0,
                    },
                    log_len: 1,
                    segment: None,
                    carried: false,
                },
            ],
            ranges: alloc::vec![
                Range {
                    column: 0,
                    width: unsigned(16),
                },
                Range {
                    column: 1,
                    width: unsigned(16),
                },
                Range {
                    column: 2,
                    width: unsigned(8),
                },
                Range {
                    column: 4,
                    width: unsigned(8),
                },
            ],
            ..Relation::default()
        };
        assert_eq!(r.validate(), Ok(()));

        // Removing the A1 range on column 2 leaves raw mag = 65_535_000, so 2^16 * mag > HALF_MODULUS.
        let mut without_a1 = r.clone();
        without_a1.ranges.remove(2);
        assert_eq!(without_a1.validate(), Err(Error::StatementMismatch));

        // NC-1340: over-wide virtual definition (raw > HALF_MODULUS) is rejected even WITH a Range.
        let mut overwide = r.clone();
        overwide.columns[2].kind = Kind::Virtual(Def::Linear {
            constant: 0,
            terms: alloc::vec![(1 << 16, whole(0))],
        });
        assert_eq!(overwide.validate(), Err(Error::StatementMismatch));

        // Forward reference in virtual definition is rejected (RFC-0028 §2.1).
        let mut cyclic = r.clone();
        cyclic.columns[2].kind = Kind::Virtual(Def::Linear {
            constant: 0,
            terms: alloc::vec![(1, whole(3))],
        });
        assert_eq!(cyclic.validate(), Err(Error::StatementMismatch));

        // NC-1335: reading a non-carried segment-0 column from segment 1 is rejected.
        let mut bad_seg = r.clone();
        bad_seg.columns[5].kind = Kind::Virtual(Def::Linear {
            constant: 0,
            terms: alloc::vec![(1, whole(1)), (-1, whole(4))],
        });
        assert_eq!(bad_seg.validate(), Err(Error::StatementMismatch));

        // Carried flag on a virtual column is rejected.
        r.columns[2].carried = true;
        assert_eq!(r.validate(), Err(Error::StatementMismatch));
    }
}
