//! RFC-0012 A10: certificate column draws and completed-proof identity.
use crate::{ChallengeField, ChallengeLabel, Error, HashUsage, Transcript, M31};
use stele_field::Field;

struct ColumnDecoder {
    length: u32,
    threshold: u32,
    attempts: u8,
}
impl ColumnDecoder {
    fn new(length: u64) -> Result<Self, Error> {
        if !(2..=1 << 30).contains(&length) || !length.is_power_of_two() {
            return Err(Error::InvalidColumnDomain);
        }
        Ok(Self {
            length: length as u32,
            threshold: M31::MODULUS - (length as u32 - 1),
            attempts: 0,
        })
    }
    // A10: pure candidate decoder; there is no production randomness injection API.
    fn push(&mut self, first: u32) -> Result<Option<u64>, Error> {
        if self.attempts == 64 {
            return Err(Error::ColumnSamplingExhausted);
        }
        self.attempts += 1;
        if first < self.threshold {
            return Ok(Some(u64::from(first % self.length)));
        }
        if self.attempts == 64 {
            return Err(Error::ColumnSamplingExhausted);
        }
        Ok(None)
    }
}
impl<K: ChallengeField> Transcript<K> {
    /// Draw one certificate index with replacement; preserve every full K ratchet.
    /// Invalid domains draw nothing. Any error aborts the enclosing proof attempt.
    pub fn certificate_column(&mut self, length: u64) -> Result<u64, Error> {
        self.column(length, ChallengeLabel::CertificateColumn)
    }
    /// Draw one functional-opening index with replacement under its fixed label.
    /// Invalid domains draw nothing; all sampling failures abort the whole attempt.
    pub fn opening_column(&mut self, length: u64) -> Result<u64, Error> {
        self.column(length, ChallengeLabel::OpeningColumn)
    }
    fn column(&mut self, length: u64, label: ChallengeLabel) -> Result<u64, Error> {
        let mut decoder = ColumnDecoder::new(length)?;
        loop {
            self.usage.add(HashUsage {
                column_attempts: 1,
                ..HashUsage::default()
            })?;
            let encoded = self.challenge(label)?.to_le_bytes();
            let bytes = encoded.as_ref();
            let first = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if let Some(index) = decoder.push(first)? {
                return Ok(index);
            }
        }
    }
}

/// Hash the exact completed-certificate frame after full verification (A10).
/// A digest alone authenticates no proof and supplies no certificate handle.
pub fn certificate_id(
    source: &[u8],
    proof: &[u8],
    usage: &mut HashUsage,
) -> Result<[u8; 32], Error> {
    let source_len = u64::try_from(source.len()).map_err(|_| Error::LengthOverflow)?;
    let proof_len = u64::try_from(proof.len()).map_err(|_| Error::LengthOverflow)?;
    usage.hashes(1)?;
    let mut hash = blake3::Hasher::new();
    for part in [
        b"stele/v0.1/pcs-certificate/id".as_slice(),
        &source_len.to_le_bytes(),
        source,
        &proof_len.to_le_bytes(),
        proof,
    ] {
        hash.update(part);
    }
    Ok(*hash.finalize().as_bytes())
}

#[cfg(test)]
#[path = "pcs_tests.rs"]
mod tests;
