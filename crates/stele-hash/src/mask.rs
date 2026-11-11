//! Secret mask streams, RFC-0013 A2 items 1–2. Prover-only: a stream is never
//! transcript data, never a challenge and never verifier input.
use crate::ChallengeField;
use stele_field::M31;

/// Context of a hiding source's mask elements (RFC-0013 A2 item 1).
pub const SOURCE_MASK: &[u8] = b"stele/v0.1/zk/source-mask";
/// Context of a hiding source's leaf salts (RFC-0013 A2 item 1).
pub const SOURCE_SALT: &[u8] = b"stele/v0.1/zk/source-salt";
/// Context of a masked sumcheck's mask polynomial (RFC-0013 A2 item 2).
pub const SUMCHECK_MASK: &[u8] = b"stele/v0.1/zk/sumcheck-mask";

/// `BLAKE3-keyed(key = seed).update(context || u64le(id)).finalize_xof()`.
/// The seed must be fresh and secret; equal seeds give equal streams (INV-8).
pub struct MaskStream {
    reader: blake3::OutputReader,
}
impl MaskStream {
    /// Start the stream for one context and object id.
    pub fn new(seed: &[u8; 32], context: &[u8], id: u64) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(seed);
        hasher.update(context);
        hasher.update(&id.to_le_bytes());
        Self {
            reader: hasher.finalize_xof(),
        }
    }
    /// Next raw bytes, in stream order.
    pub fn fill(&mut self, out: &mut [u8]) {
        self.reader.fill(out);
    }
    /// The raw bytes at absolute stream offset `position`, without advancing this
    /// stream: the bytes [`Self::fill`] yields after `position` bytes from the start.
    /// Disjoint ranges can be read concurrently (a prover's split; E16-24).
    pub fn fill_at(&self, position: u64, out: &mut [u8]) {
        let mut reader = self.reader.clone();
        reader.set_position(position);
        reader.fill(out);
    }
    /// Next uniform M31: the low 31 bits of a u32le word, rejecting `p`.
    pub fn m31(&mut self) -> M31 {
        loop {
            let mut word = [0; 4];
            self.reader.fill(&mut word);
            let value = u32::from_le_bytes(word) & 0x7fff_ffff;
            if value != 0x7fff_ffff {
                return M31::from_u64(u64::from(value));
            }
        }
    }
    /// Next uniform `K`: `D` consecutive M31 elements in limb order.
    pub fn element<K: ChallengeField>(&mut self) -> K {
        let mut limbs = [M31::ZERO; 8];
        for limb in &mut limbs[..K::DEGREE] {
            *limb = self.m31();
        }
        K::from_limbs(limbs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_reference_keyed_stream() {
        let seed = [7; 32];
        let mut hasher = blake3::Hasher::new_keyed(&seed);
        hasher.update(SOURCE_MASK);
        hasher.update(&5u64.to_le_bytes());
        let mut expected = [0; 8];
        hasher.finalize_xof().fill(&mut expected);
        let mut stream = MaskStream::new(&seed, SOURCE_MASK, 5);
        let first = stream.m31();
        let word = u32::from_le_bytes([expected[0], expected[1], expected[2], expected[3]]);
        if word & 0x7fff_ffff != 0x7fff_ffff {
            assert_eq!(first, M31::from_u64(u64::from(word & 0x7fff_ffff)));
        }
        assert_ne!(
            MaskStream::new(&seed, SOURCE_MASK, 6).m31(),
            MaskStream::new(&seed, SOURCE_MASK, 5).m31()
        );
    }
}
