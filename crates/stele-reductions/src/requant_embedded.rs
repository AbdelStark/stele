//! RFC-0024 §2.1: static embedded advice and captured integer witnesses.
//! O(J+E) term construction and O((R+E)N) witness work; no proof authority.
use super::{bounds, buffer, constraints, witness, Block, Constraints, Error, Format, Schema};
use alloc::vec::Vec;
use stele_field::{Field, M31};
use stele_hash::ChallengeField;

/// Checked full-int8 dot bound and embedded layout; no sources are authenticated.
#[derive(Debug)]
pub struct EmbeddedSchema {
    semantic: Schema,
    cap: Block,
    rows: usize,
}
impl EmbeddedSchema {
    /// Derive B=2^inner_bits*128² and the unchanged scalar CQIS schema.
    pub fn new(inner_bits: u8, mantissa: u32, shift: u32, format: Format) -> Result<Self, Error> {
        let bound = 1u64
            .checked_shl(u32::from(inner_bits))
            .and_then(|n| n.checked_mul(128 * 128))
            .filter(|b| {
                b.checked_mul(2)
                    .is_some_and(|twice| twice < u64::from(M31::MODULUS))
            })
            .ok_or(Error::Bounds(bounds::Error::FieldBound))?;
        let semantic = Schema::new(mantissa, shift, format)?;
        let start = semantic.allocated_rows();
        let end = start.checked_add(7).ok_or(Error::Capacity)?;
        let rows = end
            .checked_add(4)
            .and_then(usize::checked_next_power_of_two)
            .filter(|r| *r <= 4096)
            .ok_or(Error::Capacity)?;
        // Semantic indices +5 already equal embedded physical indices +1.
        let cap = Block {
            cap: bound,
            value: semantic.values()[0].value(),
            slack: start..start + 4,
            carry: start + 4..end,
        };
        Ok(Self {
            semantic,
            cap,
            rows,
        })
    }
    /// Original schema and generated bound record; its reserved rows are not embedded.
    pub fn semantic(&self) -> &Schema {
        &self.semantic
    }
    /// Static signed accumulator magnitude bound, with 2B<p.
    pub fn bound(&self) -> u64 {
        self.cap.cap()
    }
    /// Four input planes, all semantic planes, and seven cap planes.
    pub fn allocated_rows(&self) -> usize {
        self.cap.carry.end + 4
    }
    /// Power-of-two physical row count, including reserved zero rows.
    pub fn rows(&self) -> usize {
        self.rows
    }
    /// Exact semantic prefix, full-width cap and regenerated physical tail.
    pub fn constraints<K: ChallengeField>(&self) -> Result<Constraints<K>, Error> {
        let mut equations = self.semantic.semantic_constraints(self.rows() + 7)?;
        constraints::cap(&mut equations, &self.cap)?;
        constraints::finish(equations, self.allocated_rows() + 1, self.rows() + 1)
    }
    /// Fill one untrusted cut from captured C, with no original X/W access.
    /// `positions` bounds R*N cells; N must be a nonzero power of two.
    pub fn witness(&self, captured: &[i32], positions: usize) -> Result<EmbeddedWitness, Error> {
        let n = captured.len();
        if !n.is_power_of_two() {
            return Err(Error::Statement);
        }
        let count = self.rows().checked_mul(n).ok_or(Error::Capacity)?;
        if count > positions {
            return Err(Error::ResourceLimit);
        }
        for (elements, width) in [
            (count, core::mem::size_of::<M31>()),
            (n, core::mem::size_of::<i16>()),
        ] {
            elements
                .checked_mul(width)
                .filter(|bytes| *bytes <= isize::MAX as usize)
                .ok_or(Error::Capacity)?;
        }
        if captured
            .iter()
            .any(|v| i64::from(*v).unsigned_abs() > self.bound())
        {
            return Err(Error::Witness);
        }
        let output = self.semantic.witness_outputs(captured)?;
        let mut advice = buffer(count)?;
        advice.resize(count, M31::from_i64(0));
        for (at, acc) in captured.iter().enumerate() {
            witness::put(
                &mut advice,
                n,
                at,
                0..4,
                (i64::from(*acc) + (1 << 31)) as u64,
            )?;
            let semantic = &mut advice[4 * n..];
            self.semantic.fill_witness(semantic, n, at, *acc)?;
            witness::cap(semantic, n, at, &self.cap, i64::from(*acc).unsigned_abs())?;
        }
        Ok(EmbeddedWitness { advice, output })
    }
}

/// Untrusted physical advice and exact signed outputs, before any registration.
#[derive(Debug)]
pub struct EmbeddedWitness {
    advice: Vec<M31>,
    output: Vec<i16>,
}
impl EmbeddedWitness {
    /// One whole embedded source; U is its first four rows.
    pub fn advice(&self) -> &[M31] {
        &self.advice
    }
    /// Exact full-domain outputs; overflow returns no witness.
    pub fn output(&self) -> &[i16] {
        &self.output
    }
    /// Actual owned buffer capacities, excluding allocator, caller and stack storage.
    pub fn owned_bytes(&self) -> Result<usize, Error> {
        self.advice
            .capacity()
            .checked_mul(core::mem::size_of::<M31>())
            .and_then(|n| {
                self.output
                    .capacity()
                    .checked_mul(core::mem::size_of::<i16>())
                    .and_then(|out| n.checked_add(out))
            })
            .ok_or(Error::Capacity)
    }
}

#[cfg(test)]
#[path = "requant_embedded_tests.rs"]
mod tests;
