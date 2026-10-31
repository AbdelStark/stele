//! RFC-0012 A10 / native-field-pcs §9 — checked local work observations.
use crate::Error;

/// Local work, including failed attempts; neither a proof record nor an adversary cap.
/// Counts evaluations, not distinct oracle queries. Ordinary hashes and XOF requests
/// are disjoint. Copies may be inspected or changed without changing a transcript.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashUsage {
    /// Ordinary unkeyed BLAKE3 evaluations, including initialization and ratchets.
    pub hash_evaluations: u64,
    /// BLAKE3 extendable-output requests (separate from ordinary evaluations).
    pub xof_requests: u64,
    /// Bytes actually requested from extendable output, including unused bytes.
    pub xof_bytes: u64,
    /// Completed public-input, message or challenge updates of transcript state.
    pub state_updates: u64,
    /// Inner candidate words examined, including noncanonical rejected words.
    pub candidate_words: u64,
    /// Outer column attempts; zero until a column sampler is implemented.
    pub column_attempts: u64,
}
impl HashUsage {
    // Reserve all counters atomically before the corresponding infallible work.
    pub(crate) fn add(&mut self, delta: Self) -> Result<(), Error> {
        let add = |a: u64, b| a.checked_add(b).ok_or(Error::UsageOverflow);
        *self = Self {
            hash_evaluations: add(self.hash_evaluations, delta.hash_evaluations)?,
            xof_requests: add(self.xof_requests, delta.xof_requests)?,
            xof_bytes: add(self.xof_bytes, delta.xof_bytes)?,
            state_updates: add(self.state_updates, delta.state_updates)?,
            candidate_words: add(self.candidate_words, delta.candidate_words)?,
            column_attempts: add(self.column_attempts, delta.column_attempts)?,
        };
        Ok(())
    }
    pub(crate) fn hashes(&mut self, count: u64) -> Result<(), Error> {
        self.add(Self {
            hash_evaluations: count,
            ..Self::default()
        })
    }
}
