//! Development-profile relations over committed integer columns (RFC-0026 §3).
//!
//! A [`Relation`] declares columns and four relation kinds: identities, lookups,
//! ranges and matmuls. [`Relation::validate`] is the static check of RFC-0026 §3.6
//! (shapes, the wrap-free bound rule and range discipline); [`check`] evaluates
//! every relation over the integers with no proof (RFC-0026 §3.7).
//!
//! Indexing convention (RFC-0026 §3.2): a column of length `2^n` is indexed by `n`
//! bits; a [`Ref`] binds column bit `j` to domain bit `vars[j]`. Broadcast,
//! tiling, transposition and head splitting are all variable maps, so no column
//! is ever copied to change its layout.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

mod check;
pub use check::{check, check_except};

/// M31 modulus `p = 2^31 - 1` (RFC-0003 §1). Every identity is wrap-free below it.
pub const MODULUS: u128 = (1 << 31) - 1;
/// Widest declared column, in bits; every value then lies in `(-p/2, p/2)`.
pub const MAX_WIDTH_BITS: u8 = 30;
/// Widest single [`Range`]; wider values are split into limbs (RFC-0026 §3.5).
pub const MAX_RANGE_BITS: u8 = 16;
/// Most factors in one identity term; with `eq` the zerocheck degree is at most 4.
pub const MAX_FACTORS: usize = 3;
/// Most boolean variables of one column or relation domain.
pub const MAX_VARS: u8 = 30;
/// Lookup tuple arity admitted by RFC-0008 A2 item 5.
pub const MAX_TUPLE: usize = 2;
/// Real table rows admitted by RFC-0008 A2 item 5.
pub const MAX_TABLE_ROWS: usize = 1 << 16;

/// Index of a column in its [`Relation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ColumnId(pub u32);

/// Index of a public table in its [`Relation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableId(pub u32);

/// A commitment group: all its witness columns form one PCS source (RFC-0026 §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub u32);

/// Declared integer width: `signed` is `[-2^(bits-1), 2^(bits-1))`, unsigned is `[0, 2^bits)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Width {
    pub signed: bool,
    pub bits: u8,
}

impl Width {
    pub const fn signed(bits: u8) -> Self {
        Self { signed: true, bits }
    }

    pub const fn unsigned(bits: u8) -> Self {
        Self {
            signed: false,
            bits,
        }
    }

    pub const fn min(self) -> i64 {
        if self.signed && self.bits > 0 {
            -(1 << (self.bits - 1))
        } else {
            0
        }
    }

    pub const fn max(self) -> i64 {
        match (self.signed, self.bits) {
            (_, 0) => 0,
            (true, bits) => (1 << (bits - 1)) - 1,
            (false, bits) => (1 << bits) - 1,
        }
    }

    /// Largest absolute value of a member.
    pub const fn magnitude(self) -> u128 {
        let (min, max) = (self.min().unsigned_abs(), self.max().unsigned_abs());
        (if min > max { min } else { max }) as u128
    }

    pub const fn contains(self, value: i64) -> bool {
        self.min() <= value && value <= self.max()
    }

    /// Every member of `self` is a member of `outer`.
    pub const fn within(self, outer: Width) -> bool {
        outer.min() <= self.min() && self.max() <= outer.max()
    }
}

/// Who supplies a column's values and how it is committed (RFC-0026 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Per-proof witness column committed in the given group.
    Witness(GroupId),
    /// Model weight, committed once in the model commitment (RFC-0026 §2.2).
    Weight,
    /// Verifier-known values (statement data, masks, selectors, coefficient vectors).
    Public(Vec<i64>),
}

/// Column metadata. Its length is `2^log_len`; padding is explicit data, never implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub kind: Kind,
    pub width: Width,
    pub log_len: u8,
}

/// A column read inside a relation domain: column index bit `j` is domain bit `vars[j]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ref {
    pub column: ColumnId,
    pub vars: Vec<u8>,
}

impl Ref {
    /// Column read in its natural order on the low domain bits.
    pub fn identity(column: ColumnId, log_len: u8) -> Self {
        Self {
            column,
            vars: (0..log_len).collect(),
        }
    }

    /// Column index selected by domain point `x`.
    pub fn index(&self, x: u64) -> usize {
        self.vars.iter().enumerate().fold(0, |index, (bit, &var)| {
            index | ((((x >> var) & 1) as usize) << bit)
        })
    }
}

/// One identity term: `coeff * product(factors)`; no factors is the constant `coeff`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    pub coeff: i64,
    pub factors: Vec<Ref>,
}

/// For every `x` in `{0,1}^vars`: `sum(terms at x) = 0` over the integers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub vars: u8,
    pub terms: Vec<Term>,
}

/// For every `x` with `selector(x) = 1` (all `x` when `None`): `tuple(x)` is a table row.
/// The selector must be a public 0/1 column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub name: String,
    pub vars: u8,
    pub selector: Option<Ref>,
    pub tuple: Vec<Ref>,
    pub table: TableId,
}

/// Every entry of `column` lies in `width`; `width.bits <= MAX_RANGE_BITS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    pub name: String,
    pub column: ColumnId,
    pub width: Width,
}

/// Two-factor contraction: for every free `x` in `{0,1}^free`,
/// `out(x) = sum over y in {0,1}^summed of lhs(x, y) * rhs(x, y)`, with `y` on domain
/// bits `free..free+summed`. `out` reads free bits only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matmul {
    pub name: String,
    pub free: u8,
    pub summed: u8,
    pub out: Ref,
    pub lhs: Ref,
    pub rhs: Ref,
}

/// A commitment group: witness columns of one `log_len`, committed as one PCS source
/// in `ColumnId` order (RFC-0026 §2.3). Names follow `L{layer}/{module}/{log_len}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub log_len: u8,
}

/// Limb composition (RFC-0026 §3.5): for every index `i`,
/// `column[i] = sum over (limb, shift) of 2^shift * limb[i]`. Every limb has the
/// column's length. It is an identity under the bound rule, and it disciplines
/// `column` when the composed range of the disciplined limbs lies within its width.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compose {
    pub name: String,
    pub column: ColumnId,
    pub limbs: Vec<(ColumnId, u8)>,
}

/// Public table: rows of `widths.len()` integers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    pub widths: Vec<Width>,
    pub rows: Vec<Vec<i64>>,
}

/// A complete relation set; prover and verifier both build it from plan data (RFC-0026 §3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Relation {
    pub groups: Vec<Group>,
    pub columns: Vec<Column>,
    pub tables: Vec<Table>,
    pub identities: Vec<Identity>,
    pub lookups: Vec<Lookup>,
    pub ranges: Vec<Range>,
    pub matmuls: Vec<Matmul>,
    pub composes: Vec<Compose>,
}

/// A static defect of a relation (RFC-0026 §3.6); no values are involved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// Column width, length or public length/value is malformed.
    Column(ColumnId),
    /// A reference names a missing column, has the wrong arity or a repeated/out-of-domain bit.
    Ref { relation: String },
    /// A relation's own shape is malformed (domain, arity, factor count, table id or row).
    Shape { relation: String },
    /// A relation can wrap modulo p: its worst-case integer magnitude is not below p.
    Bound { relation: String, bound: u128 },
    /// A witness or weight column has no full-column range or unselected lookup enforcing its width.
    Undisciplined(ColumnId),
}

/// The first failure found by [`check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    Invalid(Invalid),
    /// A non-public column has no assigned values.
    Missing(ColumnId),
    Range {
        relation: String,
        index: usize,
    },
    Lookup {
        relation: String,
        point: u64,
    },
    Identity {
        relation: String,
        point: u64,
    },
    Matmul {
        relation: String,
        point: u64,
    },
    Compose {
        relation: String,
        index: usize,
    },
}

impl From<Invalid> for Violation {
    fn from(invalid: Invalid) -> Self {
        Violation::Invalid(invalid)
    }
}

/// Values of every witness and weight column, indexed by [`ColumnId`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Values(Vec<Option<Vec<i64>>>);

impl Values {
    pub fn new(relation: &Relation) -> Self {
        Self(vec![None; relation.columns.len()])
    }

    /// Assign a witness or weight column; the length must be exactly `2^log_len`.
    pub fn set(
        &mut self,
        relation: &Relation,
        id: ColumnId,
        values: Vec<i64>,
    ) -> Result<(), Invalid> {
        let column = relation.column(id).ok_or(Invalid::Column(id))?;
        if matches!(column.kind, Kind::Public(_)) || values.len() != 1usize << column.log_len {
            return Err(Invalid::Column(id));
        }
        self.0.resize(relation.columns.len(), None);
        self.0[id.0 as usize] = Some(values);
        Ok(())
    }

    /// Values of any column: public values come from the relation.
    pub fn get<'a>(&'a self, relation: &'a Relation, id: ColumnId) -> Option<&'a [i64]> {
        match &relation.column(id)?.kind {
            Kind::Public(values) => Some(values),
            _ => self.0.get(id.0 as usize)?.as_deref(),
        }
    }
}

/// A unit of the claim graph that declares its columns and relations, and fills its
/// witness columns from witness capture (RFC-0026 §5). `declare` depends on plan data
/// only, so prover and verifier derive the identical relation.
pub trait Module {
    /// What witness capture (task E16-03) hands this module.
    type Capture: ?Sized;

    /// Allocate this module's columns, tables and relations; keep the ids it needs.
    fn declare(&mut self, relation: &mut Relation);

    /// Fill this module's witness columns; weights and public columns are not set here.
    fn assign(
        &self,
        relation: &Relation,
        capture: &Self::Capture,
        values: &mut Values,
    ) -> Result<(), Violation>;
}

impl Relation {
    pub fn column(&self, id: ColumnId) -> Option<&Column> {
        self.columns.get(id.0 as usize)
    }

    /// Register a commitment group; names must be unique.
    pub fn add_group(&mut self, name: &str, log_len: u8) -> GroupId {
        self.groups.push(Group {
            name: name.into(),
            log_len,
        });
        GroupId((self.groups.len() - 1) as u32)
    }

    pub fn add_column(&mut self, name: &str, kind: Kind, width: Width, log_len: u8) -> ColumnId {
        self.columns.push(Column {
            name: name.into(),
            kind,
            width,
            log_len,
        });
        ColumnId((self.columns.len() - 1) as u32)
    }

    /// Register a public table; an identical table already present is reused.
    pub fn add_table(&mut self, table: Table) -> TableId {
        let index = self
            .tables
            .iter()
            .position(|t| *t == table)
            .unwrap_or_else(|| {
                self.tables.push(table);
                self.tables.len() - 1
            });
        TableId(index as u32)
    }

    fn width(&self, r: &Ref) -> Width {
        self.columns[r.column.0 as usize].width
    }

    /// Static check of RFC-0026 §3.6: shapes, wrap-free bounds and range discipline.
    pub fn validate(&self) -> Result<(), Invalid> {
        for (i, column) in self.columns.iter().enumerate() {
            let id = ColumnId(i as u32);
            let width_ok = column.width.bits >= 1 && column.width.bits <= MAX_WIDTH_BITS;
            let public_ok = match &column.kind {
                Kind::Public(values) => {
                    values.len() == 1usize << column.log_len
                        && values.iter().all(|&v| column.width.contains(v))
                }
                Kind::Witness(group) => self
                    .groups
                    .get(group.0 as usize)
                    .is_some_and(|g| g.log_len == column.log_len),
                Kind::Weight => true,
            };
            if !width_ok || column.log_len > MAX_VARS || !public_ok {
                return Err(Invalid::Column(id));
            }
        }
        for (i, group) in self.groups.iter().enumerate() {
            if self.groups[..i].iter().any(|g| g.name == group.name) {
                return Err(Invalid::Shape {
                    relation: group.name.clone(),
                });
            }
        }
        for table in &self.tables {
            let ok = !table.widths.is_empty()
                && !table.rows.is_empty()
                && table
                    .widths
                    .iter()
                    .all(|w| w.bits >= 1 && w.bits <= MAX_WIDTH_BITS)
                && table.rows.iter().all(|row| {
                    row.len() == table.widths.len()
                        && row.iter().zip(&table.widths).all(|(&v, w)| w.contains(v))
                });
            if !ok {
                return Err(Invalid::Shape {
                    relation: table.name.clone(),
                });
            }
        }
        for identity in &self.identities {
            self.validate_identity(identity)?;
        }
        for lookup in &self.lookups {
            self.validate_lookup(lookup)?;
        }
        for range in &self.ranges {
            let column = self.column(range.column).ok_or_else(|| Invalid::Ref {
                relation: range.name.clone(),
            })?;
            if range.width.bits == 0
                || range.width.bits > MAX_RANGE_BITS
                || matches!(column.kind, Kind::Public(_))
            {
                return Err(Invalid::Shape {
                    relation: range.name.clone(),
                });
            }
        }
        for matmul in &self.matmuls {
            self.validate_matmul(matmul)?;
        }
        for compose in &self.composes {
            self.validate_compose(compose)?;
        }
        self.validate_discipline()
    }

    fn validate_ref(&self, r: &Ref, domain: u8, relation: &str) -> Result<(), Invalid> {
        let column = self.column(r.column).ok_or_else(|| Invalid::Ref {
            relation: relation.into(),
        })?;
        let distinct = r.vars.iter().collect::<BTreeSet<_>>().len() == r.vars.len();
        if r.vars.len() != column.log_len as usize
            || !distinct
            || r.vars.iter().any(|&v| v >= domain)
        {
            return Err(Invalid::Ref {
                relation: relation.into(),
            });
        }
        Ok(())
    }

    fn validate_identity(&self, identity: &Identity) -> Result<(), Invalid> {
        let name = &identity.name;
        if identity.vars > MAX_VARS || identity.terms.is_empty() {
            return Err(Invalid::Shape {
                relation: name.clone(),
            });
        }
        let mut bound = 0u128;
        for term in &identity.terms {
            if term.factors.len() > MAX_FACTORS || term.coeff == 0 {
                return Err(Invalid::Shape {
                    relation: name.clone(),
                });
            }
            let mut magnitude = term.coeff.unsigned_abs() as u128;
            for factor in &term.factors {
                self.validate_ref(factor, identity.vars, name)?;
                magnitude = magnitude.saturating_mul(self.width(factor).magnitude());
            }
            bound = bound.saturating_add(magnitude);
        }
        if bound >= MODULUS {
            return Err(Invalid::Bound {
                relation: name.clone(),
                bound,
            });
        }
        Ok(())
    }

    fn validate_lookup(&self, lookup: &Lookup) -> Result<(), Invalid> {
        let name = &lookup.name;
        let table = self
            .tables
            .get(lookup.table.0 as usize)
            .ok_or_else(|| Invalid::Shape {
                relation: name.clone(),
            })?;
        if lookup.vars > MAX_VARS
            || lookup.tuple.len() != table.widths.len()
            || lookup.tuple.len() > MAX_TUPLE
            || table.rows.len() > MAX_TABLE_ROWS
        {
            return Err(Invalid::Shape {
                relation: name.clone(),
            });
        }
        for r in &lookup.tuple {
            self.validate_ref(r, lookup.vars, name)?;
        }
        if let Some(selector) = &lookup.selector {
            self.validate_ref(selector, lookup.vars, name)?;
            match &self.columns[selector.column.0 as usize].kind {
                Kind::Public(values) if values.iter().all(|&v| v == 0 || v == 1) => {}
                _ => {
                    return Err(Invalid::Shape {
                        relation: name.clone(),
                    })
                }
            }
        }
        Ok(())
    }

    fn validate_matmul(&self, matmul: &Matmul) -> Result<(), Invalid> {
        let name = &matmul.name;
        let domain = matmul
            .free
            .checked_add(matmul.summed)
            .filter(|&d| d <= MAX_VARS);
        let domain = domain.ok_or_else(|| Invalid::Shape {
            relation: name.clone(),
        })?;
        self.validate_ref(&matmul.out, matmul.free, name)?;
        self.validate_ref(&matmul.lhs, domain, name)?;
        self.validate_ref(&matmul.rhs, domain, name)?;
        let products = (1u128 << matmul.summed)
            .saturating_mul(self.width(&matmul.lhs).magnitude())
            .saturating_mul(self.width(&matmul.rhs).magnitude());
        let bound = products.saturating_add(self.width(&matmul.out).magnitude());
        if bound >= MODULUS {
            return Err(Invalid::Bound {
                relation: name.clone(),
                bound,
            });
        }
        Ok(())
    }

    fn validate_compose(&self, compose: &Compose) -> Result<(), Invalid> {
        let shape = || Invalid::Shape {
            relation: compose.name.clone(),
        };
        let column = self.column(compose.column).ok_or_else(shape)?;
        if compose.limbs.is_empty() {
            return Err(shape());
        }
        let mut bound = column.width.magnitude();
        for &(limb, shift) in &compose.limbs {
            let limb = self.column(limb).ok_or_else(shape)?;
            if limb.log_len != column.log_len || shift > MAX_WIDTH_BITS {
                return Err(shape());
            }
            bound = bound.saturating_add(limb.width.magnitude() << shift);
        }
        if bound >= MODULUS {
            return Err(Invalid::Bound {
                relation: compose.name.clone(),
                bound,
            });
        }
        Ok(())
    }

    /// RFC-0026 §3.6 range discipline: every witness and weight column's declared
    /// width is enforced on all of its entries by a range, an unselected lookup, or
    /// a composition of enforced limbs whose composed range lies within it.
    fn validate_discipline(&self) -> Result<(), Invalid> {
        let mut enforced = BTreeSet::new();
        for range in &self.ranges {
            if range.width.within(self.width(&Ref {
                column: range.column,
                vars: Vec::new(),
            })) {
                enforced.insert(range.column);
            }
        }
        for lookup in self.lookups.iter().filter(|l| l.selector.is_none()) {
            let table = &self.tables[lookup.table.0 as usize];
            for (r, width) in lookup.tuple.iter().zip(&table.widths) {
                if width.within(self.width(r)) {
                    enforced.insert(r.column);
                }
            }
        }
        for (i, column) in self.columns.iter().enumerate() {
            if matches!(column.kind, Kind::Public(_)) {
                enforced.insert(ColumnId(i as u32));
            }
        }
        // Compositions may chain, so iterate to a fixed point.
        loop {
            let before = enforced.len();
            for compose in &self.composes {
                if enforced.contains(&compose.column)
                    || !compose.limbs.iter().all(|(l, _)| enforced.contains(l))
                {
                    continue;
                }
                let (mut low, mut high) = (0i128, 0i128);
                for &(limb, shift) in &compose.limbs {
                    let width = self.columns[limb.0 as usize].width;
                    low += (width.min() as i128) << shift;
                    high += (width.max() as i128) << shift;
                }
                let width = self.columns[compose.column.0 as usize].width;
                if width.min() as i128 <= low && high <= width.max() as i128 {
                    enforced.insert(compose.column);
                }
            }
            // A matmul out is exact when its worst case 2^s*mag(lhs)*mag(rhs) lies in
            // width(out): out = V (mod p) and both lie in (-p/2, p/2) (RFC-0026 §3.6).
            for matmul in &self.matmuls {
                if enforced.contains(&matmul.out.column)
                    || !enforced.contains(&matmul.lhs.column)
                    || !enforced.contains(&matmul.rhs.column)
                {
                    continue;
                }
                let worst = (1u128 << matmul.summed)
                    .saturating_mul(self.width(&matmul.lhs).magnitude())
                    .saturating_mul(self.width(&matmul.rhs).magnitude());
                let out = self.width(&matmul.out);
                if worst <= out.max() as u128 && worst <= out.min().unsigned_abs() as u128 {
                    enforced.insert(matmul.out.column);
                }
            }
            if enforced.len() == before {
                break;
            }
        }
        for (i, column) in self.columns.iter().enumerate() {
            let id = ColumnId(i as u32);
            if !matches!(column.kind, Kind::Public(_)) && !enforced.contains(&id) {
                return Err(Invalid::Undisciplined(id));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
