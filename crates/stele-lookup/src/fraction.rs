//! Conditional fraction tree, original public consumer and codecs, RFC-0008 A3.
//! No private source authentication or lookup membership follows.
#[path = "tree.rs"]
mod tree;
use alloc::vec::Vec;
use stele_hash::ChallengeField;
use stele_sumcheck::Proof as SumcheckProof;
pub use tree::{check_roots, Accounting, Reduction};

/// Invalid metadata, payload or resource request; no partially decoded proof escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Depth, group boundary, leaf ids or unit-vector length is invalid.
    InvalidDescriptor,
    /// Exact verifier-owned payload dimensions were not supplied.
    ProofShape,
    /// A field limb is not canonical; it must not be reduced during decoding.
    NoncanonicalField,
    /// Checked size or allocation exceeds available capacity.
    Capacity,
    /// Original source dimensions disagree with the descriptor.
    SourceShape,
    /// Exact equality coefficient consumption failed.
    CoefficientMismatch,
    /// At least one original public leaf evaluation disagrees.
    LeafMismatch,
    /// A rational root equation contains a zero denominator.
    Pole,
    /// The nonzero-denominator root equation failed.
    RootMismatch,
    /// The underlying A1 reduction rejected; abort the entire attempt.
    Sumcheck(stele_sumcheck::Error),
    /// The production transcript aborted; never resample.
    Transcript(stele_hash::Error),
}
impl From<stele_sumcheck::Error> for Error {
    fn from(e: stele_sumcheck::Error) -> Self {
        Self::Sumcheck(e)
    }
}
impl From<stele_hash::Error> for Error {
    fn from(e: stele_hash::Error) -> Self {
        Self::Transcript(e)
    }
}
fn reserve<T>(out: &mut Vec<T>, count: usize) -> Result<(), Error> {
    out.try_reserve_exact(count).map_err(|_| Error::Capacity)
}

/// Immutable, consumer-owned metadata; never adopted from a proof.
///
/// The base field is not a challenge target:
/// ```compile_fail
/// use stele_field::M31;
/// use stele_lookup::fraction::Descriptor;
/// let descriptor = Descriptor::<M31>::new(0, 0, 0, [0, 1], &[]);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor<K: ChallengeField> {
    id: u64,
    m: u32,
    b: u32,
    leaves: [u64; 2],
    theta: Vec<K>,
}
impl<K: ChallengeField> Descriptor<K> {
    /// Validate before copying the at-most-63 unit coordinates.
    pub fn new(id: u64, m: u32, b: u32, leaves: [u64; 2], theta: &[K]) -> Result<Self, Error> {
        if m > 63 || b > m || leaves[0] == leaves[1] || theta.len() != (m - b) as usize {
            return Err(Error::InvalidDescriptor);
        }
        let mut owned = Vec::new();
        reserve(&mut owned, theta.len())?;
        owned.extend_from_slice(theta);
        Ok(Self {
            id,
            m,
            b,
            leaves,
            theta: owned,
        })
    }
    /// Tree identity, scoped independently of local A1 instance ids.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Canonical original-domain depth.
    pub fn num_vars(&self) -> u32 {
        self.m
    }
    /// Ordinary bottom-layer count; lookup count admission is a separate obligation.
    pub fn group_bits(&self) -> u32 {
        self.b
    }
    /// Ordered original numerator/denominator tensor ids.
    pub fn leaf_ids(&self) -> [u64; 2] {
        self.leaves
    }
    /// Owned, immutable upper-layer unit coordinates in MSB-first order.
    pub fn theta(&self) -> &[K] {
        &self.theta
    }

    /// Exact descriptor bytes, including the sealed challenge-field degree.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let size = self
            .theta
            .len()
            .checked_mul(4 * K::DEGREE)
            .and_then(|n| n.checked_add(34))
            .ok_or(Error::Capacity)?;
        let mut out = Vec::new();
        reserve(&mut out, size)?;
        out.extend_from_slice(&[1, K::DEGREE as u8]);
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.m.to_le_bytes());
        out.extend_from_slice(&self.b.to_le_bytes());
        for id in self.leaves {
            out.extend_from_slice(&id.to_le_bytes());
        }
        for value in &self.theta {
            out.extend_from_slice(value.to_le_bytes().as_ref());
        }
        Ok(out)
    }
    /// Exact proof length, independent of the exponentially larger source domain.
    pub fn proof_size(&self) -> Result<usize, Error> {
        let m = self.m as usize;
        m.checked_mul(m)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(3 * m + 2))
            .and_then(|n| n.checked_mul(4 * K::DEGREE))
            .ok_or(Error::Capacity)
    }
}

/// Unverified roots and A1 layer messages. Decoding is not a reduction verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof<K: ChallengeField> {
    /// Supplied numerator and denominator roots, in that order.
    pub root: [K; 2],
    /// One degree-three A1 payload per root-to-leaf level.
    pub steps: Vec<SumcheckProof<K>>,
}
impl<K: ChallengeField> Proof<K> {
    fn validate(&self, descriptor: &Descriptor<K>) -> Result<(), Error> {
        if self.steps.len() != descriptor.m as usize
            || self.steps.iter().enumerate().any(|(k, step)| {
                step.rounds.len() != k
                    || step.final_values.len() != 5
                    || step.rounds.iter().any(|row| row.len() != 4)
            })
        {
            return Err(Error::ProofShape);
        }
        Ok(())
    }
    /// Serialize exact dimensions with no prover-supplied counts or points.
    pub fn encode(&self, descriptor: &Descriptor<K>) -> Result<Vec<u8>, Error> {
        self.validate(descriptor)?;
        let mut out = Vec::new();
        reserve(&mut out, descriptor.proof_size()?)?;
        for value in self.root {
            out.extend_from_slice(value.to_le_bytes().as_ref());
        }
        for step in &self.steps {
            for value in step.rounds.iter().flatten().chain(&step.final_values) {
                out.extend_from_slice(value.to_le_bytes().as_ref());
            }
        }
        Ok(out)
    }
    /// Reject incorrect total length before allocation, then reject every noncanonical limb.
    pub fn decode(descriptor: &Descriptor<K>, bytes: &[u8]) -> Result<Self, Error>
    where
        for<'a> K::Bytes: TryFrom<&'a [u8]>,
    {
        if bytes.len() != descriptor.proof_size()? {
            return Err(Error::ProofShape);
        }
        let mut cursor = 0;
        let root = [
            read::<K>(bytes, &mut cursor)?,
            read::<K>(bytes, &mut cursor)?,
        ];
        let mut steps = Vec::new();
        reserve(&mut steps, descriptor.m as usize)?;
        for k in 0..descriptor.m {
            let mut rounds = Vec::new();
            reserve(&mut rounds, k as usize)?;
            for _ in 0..k {
                rounds.push(read_values::<K>(bytes, &mut cursor, 4)?);
            }
            steps.push(SumcheckProof {
                rounds,
                final_values: read_values::<K>(bytes, &mut cursor, 5)?,
            });
        }
        Ok(Self { root, steps })
    }
}
fn read<K: ChallengeField>(bytes: &[u8], cursor: &mut usize) -> Result<K, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let end = cursor.checked_add(4 * K::DEGREE).ok_or(Error::Capacity)?;
    let slice = bytes.get(*cursor..end).ok_or(Error::ProofShape)?;
    let encoded = K::Bytes::try_from(slice).map_err(|_| Error::NoncanonicalField)?;
    let value = K::from_le_bytes(encoded).ok_or(Error::NoncanonicalField)?;
    *cursor = end;
    Ok(value)
}
fn read_values<K: ChallengeField>(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<K>, Error>
where
    for<'a> K::Bytes: TryFrom<&'a [u8]>,
{
    let mut values = Vec::new();
    reserve(&mut values, count)?;
    for _ in 0..count {
        values.push(read::<K>(bytes, cursor)?);
    }
    Ok(values)
}
