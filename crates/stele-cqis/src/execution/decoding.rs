//! RFC-0025 decoding/execution: exact temperature, top-p/CDF, absolute draws and EOS.
use super::{copy, reserved, Cache, Error, Executor, Request};
use crate::numerics;
use alloc::vec::Vec;

/// A complete numerical choice from one original vocabulary row, not a proof.
#[derive(Debug)]
pub struct Decision {
    position: u32,
    token: u32,
    arguments: Vec<i32>,
    weights: Vec<u32>,
    order: Vec<u32>,
    cdf: Vec<u64>,
    draw: Option<u32>,
}
impl Decision {
    /// Original absolute generated position, never a local generation counter.
    pub fn position(&self) -> u32 {
        self.position
    }
    /// Selected vocabulary id.
    pub fn token(&self) -> u32 {
        self.token
    }
    /// Complete single-rounded temperature arguments; empty for greedy.
    pub fn arguments(&self) -> &[i32] {
        &self.arguments
    }
    /// Actual integer exp weights in original vocabulary order; empty for greedy.
    pub fn weights(&self) -> &[u32] {
        &self.weights
    }
    /// Complete decreasing-weight/increasing-id permutation; empty for greedy.
    pub fn order(&self) -> &[u32] {
        &self.order
    }
    /// Retained inclusive floor CDF endpoints, including 2^32; empty for greedy.
    pub fn cdf(&self) -> &[u64] {
        &self.cdf
    }
    /// Deterministic absolute-position hash draw; absent for greedy.
    pub fn draw(&self) -> Option<u32> {
        self.draw
    }
}
/// Complete generation with the final EOS evaluated and its exact stopping reason.
#[derive(Debug)]
pub struct Generation {
    cache: Cache,
    reason: u8,
    decisions: Vec<Decision>,
}
impl Generation {
    /// Complete prefix state, including every returned token and final EOS.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }
    /// Limit=0, EOS=1; EOS takes precedence at the final allowed token.
    pub fn reason(&self) -> u8 {
        self.reason
    }
    /// Every numerical decoding choice, in original absolute-position order.
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }
}
impl Executor<'_> {
    /// Choose from exactly one complete vocabulary row after validating the
    /// original prompt, whole current prefix, Model policy and original seed.
    /// The caller remains responsible for the logits' original-position source.
    pub fn choose(
        &mut self,
        request: &Request,
        prompt: &[u32],
        prefix: &[u32],
        logits: &[i16],
        seed: Option<&[u8]>,
    ) -> Result<Decision, Error> {
        let model = self.data.model;
        request.validate_seed(model, seed)?;
        self.tokens(prefix)?;
        if prompt.len() != request.prompt_length() as usize
            || prefix.len() < prompt.len()
            || prefix.len() as u64
                >= u64::from(request.prompt_length()) + u64::from(request.maximum_new())
            || prefix[..prompt.len()] != *prompt
        {
            return Err(Error::Prefix);
        }
        if prefix[prompt.len()..].iter().any(|t| request.terminal(*t)) {
            return Err(Error::Stop);
        }
        if logits.len() != model.shape().vocabulary() as usize {
            return Err(Error::Logits);
        }
        let maximum = *logits.iter().max().ok_or(Error::Logits)?;
        let Some(sampling) = model.decoding().sampling() else {
            let token = logits
                .iter()
                .position(|v| *v == maximum)
                .ok_or(Error::Logits)? as u32;
            return Ok(Decision {
                position: prefix.len() as u32,
                token,
                arguments: Vec::new(),
                weights: Vec::new(),
                order: Vec::new(),
                cdf: Vec::new(),
                draw: None,
            });
        };
        let (tn, td) = sampling.temperature();
        let ep = sampling.exponential().function().parameters();
        let mut arguments = reserved(logits.len())?;
        let mut weights = reserved(logits.len())?;
        let mut sum = 0u64;
        for value in logits {
            let n = (i128::from(*value) - i128::from(maximum)) * i128::from(td);
            let argument = numerics::scaled_sum(
                n,
                i32::from(ep[1]) - i32::from(model.logits_fraction()),
                0,
                0,
                u64::from(tn),
            )
            .map_err(|e| {
                if e == numerics::Error::Range {
                    Error::ExpDomain
                } else {
                    Error::from(e)
                }
            })?;
            let weight = self.exponential(sampling.exponential(), argument, None)? as u32;
            arguments.push(i32::try_from(argument).map_err(|_| Error::ExpDomain)?);
            weights.push(weight);
            sum += u64::from(weight);
        }
        if sum == 0 {
            return Err(Error::Arithmetic);
        }
        let mut order = reserved(logits.len())?;
        order.extend(0..model.shape().vocabulary());
        order.sort_unstable_by(|a, b| {
            weights[*b as usize]
                .cmp(&weights[*a as usize])
                .then_with(|| a.cmp(b))
        });
        let (pn, pd) = sampling.top_p();
        let mut mass = 0u64;
        let mut count = 0;
        for token in &order {
            mass += u64::from(weights[*token as usize]);
            count += 1;
            if u128::from(pd) * u128::from(mass) >= u128::from(pn) * u128::from(sum) {
                break;
            }
        }
        if mass == 0 {
            return Err(Error::Arithmetic);
        }
        let mut h = blake3::Hasher::new();
        h.update(b"stele/v0.1/cqis/sample-draw");
        h.update(seed.ok_or(Error::Seed)?);
        h.update(&(prefix.len() as u32).to_le_bytes());
        let hash = h.finalize();
        let raw = hash.as_bytes();
        let draw = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let mut cdf = reserved(count)?;
        let mut cumulative = 0u64;
        let mut selected = None;
        for token in &order[..count] {
            cumulative += u64::from(weights[*token as usize]);
            let endpoint = ((u128::from(cumulative) << 32) / u128::from(mass)) as u64;
            if selected.is_none() && u64::from(draw) < endpoint {
                selected = Some(*token);
            }
            cdf.push(endpoint);
        }
        Ok(Decision {
            position: prefix.len() as u32,
            token: selected.ok_or(Error::Arithmetic)?,
            arguments,
            weights,
            order,
            cdf,
            draw: Some(draw),
        })
    }
    /// Evaluate the prompt, then choose and evaluate each generated token before
    /// testing EOS. Seed validation runs even at a zero limit. Failure returns no
    /// Generation, including a failed evaluation of a chosen EOS token.
    pub fn generate(
        &mut self,
        request: &Request,
        prompt: &[u32],
        seed: Option<&[u8]>,
    ) -> Result<Generation, Error> {
        request.validate_seed(self.data.model, seed)?;
        self.tokens(prompt)?;
        if prompt.len() != request.prompt_length() as usize {
            return Err(Error::Prefix);
        }
        Self::admit(
            self.data.model,
            prompt.len() + request.maximum_new() as usize,
            self.memory_limit,
        )?;
        let full = self.full(prompt)?;
        let mut logits = copy(full.logits().last().ok_or(Error::Arithmetic)?)?;
        let mut cache = full.into_cache();
        let mut decisions = reserved(request.maximum_new() as usize)?;
        let mut reason = 0;
        for _ in 0..request.maximum_new() {
            let decision = self.choose(request, prompt, cache.tokens(), &logits, seed)?;
            let (step, next) = self.step(decision.token(), Some(&cache))?;
            logits = copy(step.logits())?;
            cache = next;
            let eos = request.terminal(decision.token());
            decisions.push(decision);
            if eos {
                reason = 1;
                break;
            }
        }
        request.check_completion(self.data.model, prompt, cache.tokens(), reason)?;
        Ok(Generation {
            cache,
            reason,
            decisions,
        })
    }
}
