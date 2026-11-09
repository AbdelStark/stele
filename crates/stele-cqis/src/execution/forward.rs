//! RFC-0025 §2.5–2.6: complete block order and atomic immutable full-prefix caches.
use super::{
    capture::{self, put, Capture, Quantised},
    copy, reserved, signed, wide, Error, Executor,
};
use crate::{model::Role, numerics, row::QuantisedRow};
use alloc::vec::Vec;

/// Internal numerical K/V state, scoped to the complete Model/Scales/Artifact.
/// It is not a proof of prior inference or externally authenticated cache history.
#[derive(Debug, Eq, PartialEq)]
pub struct Cache {
    scope: [[u8; 32]; 3],
    tokens: Vec<u32>,
    layers: Vec<Vec<(QuantisedRow, QuantisedRow)>>,
}
impl Cache {
    /// Complete original dense token prefix, without eviction or renumbering.
    pub fn tokens(&self) -> &[u32] {
        &self.tokens
    }
    /// Layer/position order: post-rotation K and V, each retaining whole-row units.
    pub fn layers(&self) -> &[Vec<(QuantisedRow, QuantisedRow)>] {
        &self.layers
    }
    /// Model, Scales and complete Artifact identities, in that order.
    pub fn scope(&self) -> &[[u8; 32]; 3] {
        &self.scope
    }
}
/// Complete causal result; every original position and configured layer is present.
#[derive(Debug)]
pub struct Full {
    cuts: Vec<Vec<Vec<i32>>>,
    logits: Vec<Vec<i16>>,
    cache: Cache,
}
impl Full {
    pub(super) fn into_cache(self) -> Cache {
        self.cache
    }
    /// Initial embedding residual, then each complete layer output; cut/position/lane.
    /// R_0 is int16; R_1..R_L are int24 in a wide Model (RFC-0004 A14), else int16.
    pub fn cuts(&self) -> &[Vec<Vec<i32>>] {
        &self.cuts
    }
    /// Complete vocabulary outputs in original position order.
    pub fn logits(&self) -> &[Vec<i16>] {
        &self.logits
    }
    /// Complete immutable numerical cache after every output has succeeded.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }
}
/// One successful appended position, including all residual cuts and the full head.
#[derive(Debug)]
pub struct Step {
    cuts: Vec<Vec<i32>>,
    logits: Vec<i16>,
}
impl Step {
    /// Initial residual followed by every layer output for the appended position.
    pub fn cuts(&self) -> &[Vec<i32>] {
        &self.cuts
    }
    /// Complete vocabulary output at the appended absolute position.
    pub fn logits(&self) -> &[i16] {
        &self.logits
    }
}

fn residual(
    left: &[i32],
    fx: u8,
    right: &[i32],
    fy: u8,
    fo: u8,
    bits: u32,
    mut record: Option<&mut capture::Division>,
) -> Result<Vec<i32>, Error> {
    if left.len() != right.len() {
        return Err(Error::Arithmetic);
    }
    let mut out = reserved(left.len())?;
    for (x, y) in left.iter().zip(right) {
        let (l, r) = (
            (i128::from(*x), i32::from(fo) - i32::from(fx)),
            (i128::from(*y), i32::from(fo) - i32::from(fy)),
        );
        let value = numerics::scaled_sum(l.0, l.1, r.0, r.1, 1)?;
        if let Some(w) = record.as_deref_mut() {
            w.scaled(l, r, 1, value)?;
        }
        out.push(signed(value, bits)?);
    }
    Ok(out)
}
/// Convert one row and, when captured, record its pieces.
fn quantise(
    q: &crate::row::Quantiser,
    input: &[i16],
    record: Option<&mut Quantised>,
) -> Result<QuantisedRow, Error> {
    let row = q.convert_wide(input)?;
    if let Some(w) = record {
        let mut x = reserved(input.len())?;
        x.extend(input.iter().map(|v| i64::from(*v)));
        *w = Quantised::record(&x, &row)?;
    }
    Ok(row)
}
fn filled<T: Default>(n: usize) -> Result<Vec<T>, Error> {
    let mut out = reserved(n)?;
    out.resize_with(n, T::default);
    Ok(out)
}
impl Executor<'_> {
    /// R_0 stays int16 even in a wide Model; it is carried as an in-range int24 row.
    fn embed(
        &self,
        token: u32,
        position: usize,
        record: Option<&mut capture::Embedding>,
    ) -> Result<Vec<i32>, Error> {
        let row = self.data.embed(token, position, record)?;
        let mut out = reserved(row.len())?;
        out.extend(row.into_iter().map(i32::from));
        Ok(out)
    }
    fn project(
        &mut self,
        layer: usize,
        values: &[i32],
        position: usize,
        mut w: Option<&mut capture::Block>,
    ) -> Result<(QuantisedRow, (QuantisedRow, QuantisedRow)), Error> {
        let b = self.data.model.blocks()[layer].clone();
        let s = self.data.model.shape();
        let f = b.projection_fractions();
        let l = Some(layer as u16);
        let norm = self.data.normalize(
            b.first_norm(),
            values,
            Role::FirstGain,
            l,
            w.as_deref_mut().map(|w| &mut w.first_norm),
        )?;
        let qs = &self.quantisers[layer];
        let input = quantise(&qs[0], &norm, w.as_deref_mut().map(|w| &mut w.first_row))?;
        let q = self.data.linear(
            Role::Query,
            l,
            &input,
            f[0],
            w.as_deref_mut().map(|w| &mut w.query),
        )?;
        let k = self.data.linear(
            Role::Key,
            l,
            &input,
            f[1],
            w.as_deref_mut().map(|w| &mut w.key),
        )?;
        let v = self.data.linear(
            Role::Value,
            l,
            &input,
            f[2],
            w.as_deref_mut().map(|w| &mut w.value),
        )?;
        let q = self.rotate(
            b.rotation(),
            &q,
            position,
            s.heads(),
            w.as_deref_mut().map(|w| &mut w.query_rotation),
        )?;
        let k = self.rotate(
            b.rotation(),
            &k,
            position,
            s.groups(),
            w.as_deref_mut().map(|w| &mut w.key_rotation),
        )?;
        let qs = &self.quantisers[layer];
        Ok((
            quantise(&qs[1], &q, w.as_deref_mut().map(|w| &mut w.query_row))?,
            (
                quantise(&qs[2], &k, w.as_deref_mut().map(|w| &mut w.key_row))?,
                quantise(&qs[3], &v, w.map(|w| &mut w.value_row))?,
            ),
        ))
    }
    fn finish_block(
        &mut self,
        layer: usize,
        values: &[i32],
        position: usize,
        q: &QuantisedRow,
        keys: &[(QuantisedRow, QuantisedRow)],
        mut w: Option<&mut capture::Block>,
    ) -> Result<Vec<i32>, Error> {
        let b = self.data.model.blocks()[layer].clone();
        let f = b.projection_fractions();
        let l = Some(layer as u16);
        let attention = self.attend(
            layer,
            q,
            position,
            keys,
            w.as_deref_mut().map(|w| &mut w.attention),
        )?;
        let input = quantise(
            &self.quantisers[layer][4],
            &attention,
            w.as_deref_mut().map(|w| &mut w.attention_row),
        )?;
        let o = self.data.linear_residual(
            Role::Output,
            l,
            &input,
            f[3],
            w.as_deref_mut().map(|w| &mut w.output),
        )?;
        let incoming = if layer == 0 {
            self.data.model.initial_fraction()
        } else {
            self.data.model.blocks()[layer - 1].output_fraction()
        };
        let bits = self.data.width();
        let mid = residual(
            values,
            incoming,
            &o,
            f[3],
            b.mid_fraction(),
            bits,
            w.as_deref_mut().map(|w| &mut w.mid),
        )?;
        let norm = self.data.normalize(
            b.second_norm(),
            &mid,
            Role::SecondGain,
            l,
            w.as_deref_mut().map(|w| &mut w.second_norm),
        )?;
        let input = quantise(
            &self.quantisers[layer][5],
            &norm,
            w.as_deref_mut().map(|w| &mut w.second_row),
        )?;
        let up = self.data.linear(
            Role::Up,
            l,
            &input,
            f[4],
            w.as_deref_mut().map(|w| &mut w.up),
        )?;
        let table = b.activation().components()[0];
        let down_input = if self.data.model.shape().family() == 1 {
            let gate = self.data.linear(
                Role::Gate,
                l,
                &input,
                f[5],
                w.as_deref_mut().map(|w| &mut w.gate),
            )?;
            let mut products = reserved(up.len())?;
            for (u, g) in up.iter().zip(gate) {
                let a = wide(i64::from(self.points.value(table, i32::from(g))?))?;
                products.push(i32::from(*u) * i32::from(a));
                if let Some(w) = w.as_deref_mut() {
                    w.activation.push(i64::from(g), i64::from(a))?;
                    put(
                        &mut w.gated,
                        i64::from(*products.last().ok_or(Error::Arithmetic)?),
                    )?;
                }
            }
            let row = self.quantisers[layer][6].convert_gated(&products)?;
            if let Some(w) = w.as_deref_mut() {
                w.down_row = Quantised::record(&w.gated, &row)?;
            }
            row
        } else {
            let mut activated = reserved(up.len())?;
            for u in up {
                activated.push(wide(i64::from(self.points.value(table, i32::from(u))?))?);
                if let Some(w) = w.as_deref_mut() {
                    let a = *activated.last().ok_or(Error::Arithmetic)?;
                    w.activation.push(i64::from(u), i64::from(a))?;
                }
            }
            quantise(
                &self.quantisers[layer][6],
                &activated,
                w.as_deref_mut().map(|w| &mut w.down_row),
            )?
        };
        let df = *f.last().ok_or(Error::Arithmetic)?;
        let down = self.data.linear_residual(
            Role::Down,
            l,
            &down_input,
            df,
            w.as_deref_mut().map(|w| &mut w.down),
        )?;
        residual(
            &mid,
            b.mid_fraction(),
            &down,
            df,
            b.output_fraction(),
            bits,
            w.map(|w| &mut w.residual),
        )
    }
    fn finish(&self, values: &[i32], mut w: Option<&mut capture::Head>) -> Result<Vec<i16>, Error> {
        let norm = self.data.normalize(
            self.data.model.final_norm(),
            values,
            Role::FinalGain,
            None,
            w.as_deref_mut().map(|w| &mut w.norm),
        )?;
        let input = quantise(
            &self.final_quantiser,
            &norm,
            w.as_deref_mut().map(|w| &mut w.row),
        )?;
        let logits = self.data.linear(
            Role::Head,
            None,
            &input,
            self.data.model.logits_fraction(),
            w.as_deref_mut().map(|w| &mut w.logits),
        )?;
        if let Some(w) = w {
            // Greedy choice (RFC-0025 §2.6): the first index of the maximum.
            let maximum = *logits.iter().max().ok_or(Error::Logits)?;
            w.maximum = i64::from(maximum);
            w.argmax = logits
                .iter()
                .position(|v| *v == maximum)
                .ok_or(Error::Logits)? as u32;
        }
        Ok(logits)
    }
    /// Evaluate all real positions causally and retain every residual and logit row.
    /// Masked scores still execute; only unmasked keys enter maxima/exp weights.
    pub fn full(&mut self, tokens: &[u32]) -> Result<Full, Error> {
        self.prefill(tokens, None)
    }
    /// As `full`, also returning every intermediate integer of the prefill
    /// (task E16-03). The returned `Full` is the one `full` computes.
    /// Capture memory is outside the `memory_limit` budget; allocation stays fallible.
    pub fn capture(&mut self, tokens: &[u32]) -> Result<Capture, Error> {
        let mut w = Capture {
            full: Full {
                cuts: Vec::new(),
                logits: Vec::new(),
                cache: Cache {
                    scope: self.data.scope,
                    tokens: Vec::new(),
                    layers: Vec::new(),
                },
            },
            embedding: Vec::new(),
            blocks: Vec::new(),
            head: Vec::new(),
        };
        w.full = self.prefill(tokens, Some(&mut w))?;
        Ok(w)
    }
    fn prefill(&mut self, tokens: &[u32], mut w: Option<&mut Capture>) -> Result<Full, Error> {
        self.tokens(tokens)?;
        if let Some(w) = w.as_deref_mut() {
            let n = tokens.len();
            w.embedding = filled(n)?;
            w.head = filled(n)?;
            w.blocks = reserved(self.data.model.blocks().len())?;
            for _ in self.data.model.blocks() {
                w.blocks.push(filled(n)?);
            }
        }
        let mut initial = reserved(tokens.len())?;
        for (position, token) in tokens.iter().enumerate() {
            let e = w.as_deref_mut().map(|w| &mut w.embedding[position]);
            initial.push(self.embed(*token, position, e)?);
        }
        let mut cuts = reserved(self.data.model.blocks().len() + 1)?;
        cuts.push(initial);
        let mut layers = reserved(self.data.model.blocks().len())?;
        for layer in 0..self.data.model.blocks().len() {
            let mut queries = reserved(tokens.len())?;
            let mut keys = reserved(tokens.len())?;
            for (position, row) in cuts[layer].iter().enumerate() {
                let b = w.as_deref_mut().map(|w| &mut w.blocks[layer][position]);
                let (q, kv) = self.project(layer, row, position, b)?;
                queries.push(q);
                keys.push(kv);
            }
            let mut rows = reserved(tokens.len())?;
            for (position, (row, q)) in cuts[layer].iter().zip(&queries).enumerate() {
                let b = w.as_deref_mut().map(|w| &mut w.blocks[layer][position]);
                rows.push(self.finish_block(layer, row, position, q, &keys, b)?);
            }
            cuts.push(rows);
            layers.push(keys);
        }
        let mut logits = reserved(tokens.len())?;
        for (position, row) in cuts.last().ok_or(Error::Arithmetic)?.iter().enumerate() {
            let h = w.as_deref_mut().map(|w| &mut w.head[position]);
            logits.push(self.finish(row, h)?);
        }
        let cache = Cache {
            scope: self.data.scope,
            tokens: copy(tokens)?,
            layers,
        };
        Ok(Full {
            cuts,
            logits,
            cache,
        })
    }
    fn validate_cache(&self, cache: &Cache) -> Result<(), Error> {
        if cache.scope != self.data.scope {
            return Err(Error::CacheScope);
        }
        self.tokens(&cache.tokens)?;
        let s = self.data.model.shape();
        if cache.layers.len() != self.data.model.blocks().len() {
            return Err(Error::Cache);
        }
        for (layer, rows) in cache.layers.iter().enumerate() {
            if rows.len() != cache.tokens.len() {
                return Err(Error::Cache);
            }
            for (k, v) in rows {
                for (j, row) in [k, v].iter().enumerate() {
                    let q = &self.quantisers[layer][j + 2];
                    let p = q.parameters();
                    if row.parameters() != p
                        || row.codes().len() != usize::from(s.groups() * s.head_width())
                    {
                        return Err(Error::Cache);
                    }
                    let scale = row.scale();
                    if (p.policy == 1 && scale != p.scale) || (p.policy == 0 && scale > 259) {
                        return Err(Error::Cache);
                    }
                    let bound = if scale == 0 {
                        0
                    } else {
                        127.min((65536 + scale) / (2 * scale))
                    };
                    if row
                        .codes()
                        .iter()
                        .any(|code| u32::from(code.unsigned_abs()) > bound)
                    {
                        return Err(Error::Cache);
                    }
                }
            }
        }
        Ok(())
    }
    /// Append at the original absolute prefix position. The borrowed cache stays
    /// unchanged on every error; a new immutable cache is returned only after all
    /// layers and the complete vocabulary head have succeeded.
    pub fn step(&mut self, token: u32, cache: Option<&Cache>) -> Result<(Step, Cache), Error> {
        if let Some(cache) = cache {
            self.validate_cache(cache)?;
        }
        let position = cache.map_or(0, |c| c.tokens.len());
        if position as u64 >= u64::from(self.data.model.shape().context()) {
            return Err(Error::Length);
        }
        if token >= self.data.model.shape().vocabulary() {
            return Err(Error::Token);
        }
        Self::admit(self.data.model, position + 1, self.memory_limit)?;
        let mut tokens = reserved(position + 1)?;
        if let Some(cache) = cache {
            tokens.extend_from_slice(&cache.tokens);
        }
        tokens.push(token);
        let mut cuts = reserved(self.data.model.blocks().len() + 1)?;
        cuts.push(self.embed(token, position, None)?);
        let mut layers = reserved(self.data.model.blocks().len())?;
        for layer in 0..self.data.model.blocks().len() {
            let (q, kv) = self.project(layer, &cuts[layer], position, None)?;
            let mut keys = reserved(position + 1)?;
            if let Some(cache) = cache {
                for (k, v) in &cache.layers[layer] {
                    keys.push((k.try_clone()?, v.try_clone()?));
                }
            }
            keys.push(kv);
            cuts.push(self.finish_block(layer, &cuts[layer], position, &q, &keys, None)?);
            layers.push(keys);
        }
        let logits = self.finish(cuts.last().ok_or(Error::Arithmetic)?, None)?;
        Ok((
            Step { cuts, logits },
            Cache {
                scope: self.data.scope,
                tokens,
                layers,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bounds::arithmetic::Row,
        execution::{tests::Fixture, Request},
        row::Quantiser,
    };

    #[test]
    fn rejects_failed_append_without_changing_prefix_and_evaluates_eos() {
        for name in ["early_failure", "late_failure"] {
            let fixture = Fixture::new(name);
            let mut executor = fixture.executor().expect("executor");
            let original = executor.full(&[0]).expect("complete prefix");
            assert_eq!(
                executor
                    .step(1, Some(original.cache()))
                    .expect_err("range failure"),
                Error::Range
            );
            assert_eq!(
                original.cache(),
                executor.full(&[0]).expect("unchanged replay").cache()
            );
            if name == "early_failure" {
                let request = Request::new(&fixture.model, 1, 1, &[1], None).expect("request");
                assert_eq!(
                    executor
                        .choose(&request, &[0], &[0], &original.logits()[0], None)
                        .expect("chosen EOS")
                        .token(),
                    1
                );
                assert_eq!(
                    executor
                        .generate(&request, &[0], None)
                        .expect_err("EOS must execute"),
                    Error::Range
                );
            }
        }
    }

    #[test]
    fn rejects_cache_scope_geometry_tokens_and_units() {
        let fixture = Fixture::new("early_failure");
        let mut executor = fixture.executor().expect("executor");
        for index in 0..3 {
            let mut cache = executor.full(&[0]).expect("full").into_cache();
            cache.scope[index][0] ^= 1;
            assert_eq!(
                executor.step(0, Some(&cache)).expect_err("scope"),
                Error::CacheScope
            );
        }
        let mut cache = executor.full(&[0]).expect("full").into_cache();
        cache.layers.pop();
        assert_eq!(
            executor.step(0, Some(&cache)).expect_err("missing layer"),
            Error::Cache
        );
        let mut cache = executor.full(&[0]).expect("full").into_cache();
        cache.layers[0].pop();
        assert_eq!(
            executor.step(0, Some(&cache)).expect_err("missing key"),
            Error::Cache
        );
        let mut cache = executor.full(&[0]).expect("full").into_cache();
        cache.tokens[0] = fixture.model.shape().vocabulary();
        assert_eq!(
            executor.step(0, Some(&cache)).expect_err("token"),
            Error::Token
        );
        let mut cache = executor.full(&[0]).expect("full").into_cache();
        let parameters = cache.layers[0][0].0.parameters();
        let wrong = Quantiser::new(Row {
            fraction: (parameters.fraction + 1) % 31,
            ..parameters
        })
        .expect("different units");
        cache.layers[0][0].0 = wrong.convert_wide(&[0, 0]).expect("row");
        assert_eq!(
            executor.step(0, Some(&cache)).expect_err("units"),
            Error::Cache
        );
    }
}
