//! RFC-0010 A4 — closed code identities and typed encoder metadata.
use crate::{expander::Expander, memory, reserved, Circle, Encoding, Error};
use alloc::vec::Vec;
use stele_field::{Field, M31, OM31, QM31};
mod sealed {
    pub trait Element {}
    impl Element for stele_field::M31 {}
    impl Element for stele_field::QM31 {}
    impl Element for stele_field::OM31 {}
    pub trait Code {}
    impl Code for super::PreparedCode {}
}
/// Actual native field representations supported by the closed encoder API.
pub trait Element: sealed::Element + Field {}
impl Element for M31 {}
impl Element for QM31 {}
impl Element for OM31 {}
/// Requested profile; neither has an admitted PCS parameter set through A4.
#[derive(Clone, Copy, Debug)]
pub enum Profile {
    Standard,
    Treaty,
}
/// Derived encoder evidence only; returned snapshots are never accepted as authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    /// Exact message length; no implicit padding.
    pub message_len: usize,
    /// Exact codeword length.
    pub codeword_len: usize,
    /// Symbol distance bound, conditional on the stated setup event for v2.
    pub distance_lower_bound: u64,
    /// All-seed setup-loss numerator, not a complete PCS error.
    pub setup_loss_numerator: u64,
    /// Denominator is two to this power; zero numerator means exact zero loss.
    pub setup_loss_denominator_bits: u16,
    /// Total retained sparse records across recursive levels.
    pub edge_count: u64,
    /// Canonical raw setup bytes (not actual heap footprint).
    pub raw_setup_bytes: u64,
    /// Complete PCS parameter evidence; always false until separately admitted.
    pub proven: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Config {
    Circle(Circle),
    Expander { exponent: u8, seed: [u8; 32] },
}
/// Validated identity; resolving it performs no setup or FFT allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeId(Config);
impl CodeId {
    /// Select only an exact A2 circle identity or A4 v2 seeded identity.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() == 21 && &raw[..19] == b"stele/circle-m31/v1" {
            return Circle::new(u32::from(raw[19]), u32::from(raw[20]))
                .map(|c| Self(Config::Circle(c)))
                .map_err(|e| {
                    if e == Error::Capacity {
                        e
                    } else {
                        Error::InvalidCodeId
                    }
                });
        }
        if raw.len() != 55
            || &raw[..22] != b"stele/expander-seed/v2"
            || !(3..=15).contains(&raw[22])
        {
            return Err(Error::InvalidCodeId);
        }
        let exponent = raw[22];
        1usize
            .checked_shl(2 * u32::from(exponent) + 1)
            .ok_or(Error::Capacity)?;
        let mut seed = [0; 32];
        seed.copy_from_slice(&raw[23..]);
        Ok(Self(Config::Expander { exponent, seed }))
    }
    /// Serialize the complete map identity; consumers separately bind the field.
    pub fn to_bytes(self) -> Result<Vec<u8>, Error> {
        let mut out = reserved(55)?;
        match self.0 {
            Config::Circle(c) => out.extend(c.code_id()),
            Config::Expander { exponent, seed } => {
                out.extend(b"stele/expander-seed/v2");
                out.push(exponent);
                out.extend(seed);
            }
        }
        Ok(out)
    }
    /// Derive every metadata value from the validated identity without allocation.
    pub fn parameters(self) -> Parameters {
        let (n, total, distance, edges, raw, loss) = match self.0 {
            Config::Circle(c) => {
                let n = c.message_len();
                let total = c.codeword_len();
                (
                    n,
                    total,
                    if n == 1 {
                        total as u64
                    } else {
                        (total - n) as u64
                    },
                    0,
                    0,
                    0,
                )
            }
            Config::Expander { exponent, .. } => {
                let n = 1usize << (2 * exponent);
                let edges = crate::expander::edge_count(exponent);
                (
                    n,
                    2 * n,
                    if exponent == 3 { 64 } else { n as u64 / 25 + 1 },
                    edges,
                    43 + 8 * edges,
                    if exponent == 3 { 0 } else { 200431782 },
                )
            }
        };
        Parameters {
            message_len: n,
            codeword_len: total,
            distance_lower_bound: distance,
            edge_count: edges,
            raw_setup_bytes: raw,
            setup_loss_numerator: loss,
            setup_loss_denominator_bits: if loss == 0 { 0 } else { 160 },
            proven: false,
        }
    }
    /// Fail closed: distance evidence does not supply PCS/profile parameters.
    pub fn pcs_parameters(self, _profile: Profile) -> Result<(), Error> {
        Err(Error::UnsupportedParameters)
    }
    /// Prepare an exact map with an explicit retained-graph byte limit.
    /// Caller row and encoding workspace are separate from this limit.
    pub fn prepare(self, max_setup_bytes: usize) -> Result<PreparedCode, Error> {
        let inner = match self.0 {
            Config::Circle(c) => Prepared::Circle(c),
            Config::Expander { exponent, seed } => {
                Prepared::Expander(Expander::new(exponent, &seed, max_setup_bytes)?)
            }
        };
        Ok(PreparedCode { id: self, inner })
    }
}
enum Prepared {
    Circle(Circle),
    Expander(Expander),
}
/// Prepared exact map. No public raw graph or unchecked implementation constructor.
pub struct PreparedCode {
    id: CodeId,
    inner: Prepared,
}
impl PreparedCode {
    /// Encode through the same arithmetic path, recording every owned heap capacity.
    /// Includes the retained graph; excludes caller input and stack/process overhead.
    pub fn encode_with_memory<K: Element>(&self, row: &[K]) -> Result<Encoding<K>, Error> {
        if row.len() != self.parameters().message_len {
            return Err(Error::RowShape);
        }
        let mut memory = memory::Memory::default();
        memory.add(self.graph_capacity_bytes())?;
        let word = match &self.inner {
            Prepared::Circle(c) => c.encode_counted(row, &mut memory)?,
            Prepared::Expander(e) => e.encode(row, &mut memory)?,
        };
        Ok(Encoding {
            word,
            peak_owned_heap_bytes: memory.peak(),
        })
    }
    /// Select columns while accounting for selected-buffer/full-word overlap.
    pub fn eval_row_with_memory<K: Element>(
        &self,
        row: &[K],
        columns: &[usize],
    ) -> Result<Encoding<K>, Error> {
        let p = self.parameters();
        if row.len() != p.message_len {
            return Err(Error::RowShape);
        }
        if columns.iter().any(|c| *c >= p.codeword_len) {
            return Err(Error::Column);
        }
        let mut memory = memory::Memory::default();
        memory.add(self.graph_capacity_bytes())?;
        let mut selected = memory.reserve(columns.len())?;
        if !columns.is_empty() {
            let word = match &self.inner {
                Prepared::Circle(c) => c.encode_counted(row, &mut memory)?,
                Prepared::Expander(e) => e.encode(row, &mut memory)?,
            };
            selected.extend(columns.iter().map(|c| word[*c]));
            memory.remove(memory::bytes(&word));
        }
        Ok(Encoding {
            word: selected,
            peak_owned_heap_bytes: memory.peak(),
        })
    }
    /// Actual retained sparse-buffer capacity; excludes encoding and caller memory.
    pub fn graph_capacity_bytes(&self) -> usize {
        match &self.inner {
            Prepared::Circle(_) => 0,
            Prepared::Expander(e) => e.capacity_bytes(),
        }
    }
    /// Number of fixed-domain hash blocks actually used by setup preparation.
    pub fn setup_hash_blocks(&self) -> u64 {
        match &self.inner {
            Prepared::Circle(_) => 0,
            Prepared::Expander(e) => e.hash_blocks(),
        }
    }
}
/// Sealed native encoder, not a commitment verifier or a profile-admission interface.
pub trait Code: sealed::Code {
    /// Complete identity used to prepare this actual map.
    fn code_id(&self) -> CodeId;
    /// Derived descriptive parameters; never a proximity certificate.
    fn parameters(&self) -> Parameters;
    /// Encode exactly one admitted-field row, returning no partial result on error.
    fn encode<K: Element>(&self, row: &[K]) -> Result<Vec<K>, Error>;
    /// Validate and select encoded columns, retaining order and duplicates.
    fn eval_row<K: Element>(&self, row: &[K], columns: &[usize]) -> Result<Vec<K>, Error>;
}
impl Code for PreparedCode {
    fn code_id(&self) -> CodeId {
        self.id
    }
    fn parameters(&self) -> Parameters {
        self.id.parameters()
    }
    fn encode<K: Element>(&self, row: &[K]) -> Result<Vec<K>, Error> {
        Ok(self.encode_with_memory(row)?.word)
    }

    fn eval_row<K: Element>(&self, row: &[K], columns: &[usize]) -> Result<Vec<K>, Error> {
        Ok(self.eval_row_with_memory(row, columns)?.word)
    }
}
