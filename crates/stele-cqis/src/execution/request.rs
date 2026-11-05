//! RFC-0025 request §§1–2: exact Model-bound request and complete stop boundary.
use super::{copy, reserved, Error};
use crate::model::Model;
use alloc::vec::Vec;

const PREFIX: &[u8] = b"stele/v0.1/cqis/request-boundary";

/// Immutable complete numerical request. Its caller must independently authenticate
/// prompt, policy and seed authority; parsing this object grants no proof admission.
#[derive(Debug, Eq, PartialEq)]
pub struct Request {
    model: [u8; 32],
    prompt: u32,
    maximum: u32,
    eos: Vec<u32>,
    seed: Option<[u8; 32]>,
}
impl Request {
    /// Check the original Model mode, capacity and complete strictly ordered EOS set.
    pub fn new(
        model: &Model,
        prompt: u32,
        maximum: u32,
        eos: &[u32],
        seed: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        let s = model.shape();
        if prompt == 0
            || prompt > s.context()
            || maximum > s.context() - prompt
            || eos.is_empty()
            || eos.len() as u64 > u64::from(s.vocabulary())
            || eos.iter().any(|v| *v >= s.vocabulary())
            || eos.windows(2).any(|p| p[0] >= p[1])
            || seed.is_some() != model.decoding().sampling().is_some()
        {
            return Err(Error::Request);
        }
        Ok(Self {
            model: model.identity(),
            prompt,
            maximum,
            eos: copy(eos)?,
            seed,
        })
    }
    /// Check exact framing/extent before allocating the EOS list. No inactive bytes.
    pub fn decode(model: &Model, raw: &[u8]) -> Result<Self, Error> {
        let head = PREFIX.len() + 13;
        let sampled = model.decoding().sampling().is_some();
        if raw.len() < head || !raw.starts_with(PREFIX) || raw[PREFIX.len()] != u8::from(sampled) {
            return Err(Error::Request);
        }
        let word = |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        let prompt = word(PREFIX.len() + 1);
        let maximum = word(PREFIX.len() + 5);
        let count = word(PREFIX.len() + 9);
        if count == 0
            || count > model.shape().vocabulary()
            || raw.len() as u64 != head as u64 + 4 * u64::from(count) + 32 * u64::from(sampled)
        {
            return Err(Error::Request);
        }
        let mut eos = reserved(count as usize)?;
        for i in 0..count as usize {
            eos.push(word(head + 4 * i));
        }
        let seed = if sampled {
            Some(
                raw[raw.len() - 32..]
                    .try_into()
                    .map_err(|_| Error::Request)?,
            )
        } else {
            None
        };
        Self::new(model, prompt, maximum, &eos, seed)
    }
    /// Complete canonical RequestBoundary bytes, without an enclosing B frame.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut raw = reserved(
            PREFIX.len() + 13 + 4 * self.eos.len() + 32 * usize::from(self.seed.is_some()),
        )?;
        raw.extend_from_slice(PREFIX);
        raw.push(u8::from(self.seed.is_some()));
        for v in [self.prompt, self.maximum, self.eos.len() as u32] {
            raw.extend_from_slice(&v.to_le_bytes());
        }
        for v in &self.eos {
            raw.extend_from_slice(&v.to_le_bytes());
        }
        if let Some(seed) = self.seed {
            raw.extend_from_slice(&seed);
        }
        Ok(raw)
    }
    /// Original prompt extent.
    pub fn prompt_length(&self) -> u32 {
        self.prompt
    }
    /// Maximum generated extent, already checked against the Model capacity.
    pub fn maximum_new(&self) -> u32 {
        self.maximum
    }
    /// Complete ordered terminal-token set; prompt EOS remains legal.
    pub fn eos(&self) -> &[u32] {
        &self.eos
    }
    /// Original sampled seed commitment, absent in greedy mode.
    pub fn seed_commitment(&self) -> Option<[u8; 32]> {
        self.seed
    }
    /// Deterministic seed commitment; this does not establish seed fairness.
    pub fn commit_seed(seed: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"stele/v0.1/cqis/sample-seed");
        h.update(seed);
        *h.finalize().as_bytes()
    }
    pub(super) fn validate_seed(&self, model: &Model, seed: Option<&[u8]>) -> Result<(), Error> {
        if self.model != model.identity() {
            return Err(Error::Request);
        }
        match (self.seed, seed) {
            (None, None) => Ok(()),
            (Some(expected), Some(raw)) if raw.len() == 32 => {
                let raw: &[u8; 32] = raw.try_into().map_err(|_| Error::Seed)?;
                if Self::commit_seed(raw) != expected {
                    Err(Error::Seed)
                } else {
                    Ok(())
                }
            }
            _ => Err(Error::Seed),
        }
    }
    pub(super) fn terminal(&self, token: u32) -> bool {
        self.eos.binary_search(&token).is_ok()
    }
    /// Check complete prefix/token/stop rules against independently expected prompt.
    /// This checks numerical boundaries, not the model/logit provenance of choices.
    pub fn check_completion(
        &self,
        model: &Model,
        prompt: &[u32],
        sequence: &[u32],
        reason: u8,
    ) -> Result<(), Error> {
        if self.model != model.identity() {
            return Err(Error::Request);
        }
        if prompt.len() != self.prompt as usize
            || sequence.len() < prompt.len()
            || sequence.len() as u64 > u64::from(self.prompt) + u64::from(self.maximum)
        {
            return Err(Error::Length);
        }
        if sequence[..prompt.len()] != *prompt {
            return Err(Error::Prefix);
        }
        if sequence.iter().any(|v| *v >= model.shape().vocabulary()) {
            return Err(Error::Token);
        }
        let generated = &sequence[prompt.len()..];
        let expected = u8::from(generated.last().is_some_and(|t| self.terminal(*t)));
        if generated
            .iter()
            .take(generated.len().saturating_sub(1))
            .any(|t| self.terminal(*t))
            || reason != expected
            || (expected == 0 && generated.len() != self.maximum as usize)
        {
            return Err(Error::Stop);
        }
        Ok(())
    }
}
