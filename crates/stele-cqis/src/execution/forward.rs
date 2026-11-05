//! RFC-0025 §2.5–2.6: complete block order and atomic immutable full-prefix caches.
use super::{copy, reserved, wide, Error, Executor};
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
    cuts: Vec<Vec<Vec<i16>>>,
    logits: Vec<Vec<i16>>,
    cache: Cache,
}
impl Full {
    pub(super) fn into_cache(self) -> Cache {
        self.cache
    }
    /// Initial embedding residual, then each complete layer output; cut/position/lane.
    pub fn cuts(&self) -> &[Vec<Vec<i16>>] {
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
    cuts: Vec<Vec<i16>>,
    logits: Vec<i16>,
}
impl Step {
    /// Initial residual followed by every layer output for the appended position.
    pub fn cuts(&self) -> &[Vec<i16>] {
        &self.cuts
    }
    /// Complete vocabulary output at the appended absolute position.
    pub fn logits(&self) -> &[i16] {
        &self.logits
    }
}

fn residual(left: &[i16], fx: u8, right: &[i16], fy: u8, fo: u8) -> Result<Vec<i16>, Error> {
    if left.len() != right.len() {
        return Err(Error::Arithmetic);
    }
    let mut out = reserved(left.len())?;
    for (x, y) in left.iter().zip(right) {
        out.push(wide(numerics::scaled_sum(
            i128::from(*x),
            i32::from(fo) - i32::from(fx),
            i128::from(*y),
            i32::from(fo) - i32::from(fy),
            1,
        )?)?);
    }
    Ok(out)
}
impl Executor<'_> {
    fn project(
        &mut self,
        layer: usize,
        values: &[i16],
        position: usize,
    ) -> Result<(QuantisedRow, (QuantisedRow, QuantisedRow)), Error> {
        let b = self.data.model.blocks()[layer].clone();
        let s = self.data.model.shape();
        let f = b.projection_fractions();
        let norm =
            self.data
                .normalize(b.first_norm(), values, Role::FirstGain, Some(layer as u16))?;
        let input = self.quantisers[layer][0].convert_wide(&norm)?;
        let q = self
            .data
            .linear(Role::Query, Some(layer as u16), &input, f[0])?;
        let k = self
            .data
            .linear(Role::Key, Some(layer as u16), &input, f[1])?;
        let v = self
            .data
            .linear(Role::Value, Some(layer as u16), &input, f[2])?;
        let q = self.rotate(b.rotation(), &q, position, s.heads())?;
        let k = self.rotate(b.rotation(), &k, position, s.groups())?;
        Ok((
            self.quantisers[layer][1].convert_wide(&q)?,
            (
                self.quantisers[layer][2].convert_wide(&k)?,
                self.quantisers[layer][3].convert_wide(&v)?,
            ),
        ))
    }
    fn finish_block(
        &mut self,
        layer: usize,
        values: &[i16],
        position: usize,
        q: &QuantisedRow,
        keys: &[(QuantisedRow, QuantisedRow)],
    ) -> Result<Vec<i16>, Error> {
        let b = self.data.model.blocks()[layer].clone();
        let f = b.projection_fractions();
        let attention = self.attend(layer, q, position, keys)?;
        let input = self.quantisers[layer][4].convert_wide(&attention)?;
        let o = self
            .data
            .linear(Role::Output, Some(layer as u16), &input, f[3])?;
        let incoming = if layer == 0 {
            self.data.model.initial_fraction()
        } else {
            self.data.model.blocks()[layer - 1].output_fraction()
        };
        let mid = residual(values, incoming, &o, f[3], b.mid_fraction())?;
        let norm =
            self.data
                .normalize(b.second_norm(), &mid, Role::SecondGain, Some(layer as u16))?;
        let input = self.quantisers[layer][5].convert_wide(&norm)?;
        let up = self
            .data
            .linear(Role::Up, Some(layer as u16), &input, f[4])?;
        let down_input = if self.data.model.shape().family() == 1 {
            let gate = self
                .data
                .linear(Role::Gate, Some(layer as u16), &input, f[5])?;
            let mut products = reserved(up.len())?;
            for (u, g) in up.iter().zip(gate) {
                let a = wide(i64::from(
                    self.points
                        .value(b.activation().components()[0], i32::from(g))?,
                ))?;
                products.push(i32::from(*u) * i32::from(a));
            }
            self.quantisers[layer][6].convert_gated(&products)?
        } else {
            let mut activated = reserved(up.len())?;
            for u in up {
                activated.push(wide(i64::from(
                    self.points
                        .value(b.activation().components()[0], i32::from(u))?,
                ))?);
            }
            self.quantisers[layer][6].convert_wide(&activated)?
        };
        let df = *f.last().ok_or(Error::Arithmetic)?;
        let down = self
            .data
            .linear(Role::Down, Some(layer as u16), &down_input, df)?;
        residual(&mid, b.mid_fraction(), &down, df, b.output_fraction())
    }
    fn finish(&self, values: &[i16]) -> Result<Vec<i16>, Error> {
        let norm =
            self.data
                .normalize(self.data.model.final_norm(), values, Role::FinalGain, None)?;
        let input = self.final_quantiser.convert_wide(&norm)?;
        self.data
            .linear(Role::Head, None, &input, self.data.model.logits_fraction())
    }
    /// Evaluate all real positions causally and retain every residual and logit row.
    /// Masked scores still execute; only unmasked keys enter maxima/exp weights.
    pub fn full(&mut self, tokens: &[u32]) -> Result<Full, Error> {
        self.tokens(tokens)?;
        let mut initial = reserved(tokens.len())?;
        for (position, token) in tokens.iter().enumerate() {
            initial.push(self.data.embed(*token, position)?);
        }
        let mut cuts = reserved(self.data.model.blocks().len() + 1)?;
        cuts.push(initial);
        let mut layers = reserved(self.data.model.blocks().len())?;
        for layer in 0..self.data.model.blocks().len() {
            let mut queries = reserved(tokens.len())?;
            let mut keys = reserved(tokens.len())?;
            for (position, row) in cuts[layer].iter().enumerate() {
                let (q, kv) = self.project(layer, row, position)?;
                queries.push(q);
                keys.push(kv);
            }
            let mut rows = reserved(tokens.len())?;
            for (position, (row, q)) in cuts[layer].iter().zip(&queries).enumerate() {
                rows.push(self.finish_block(layer, row, position, q, &keys)?);
            }
            cuts.push(rows);
            layers.push(keys);
        }
        let mut logits = reserved(tokens.len())?;
        for row in cuts.last().ok_or(Error::Arithmetic)? {
            logits.push(self.finish(row)?);
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
        cuts.push(self.data.embed(token, position)?);
        let mut layers = reserved(self.data.model.blocks().len())?;
        for layer in 0..self.data.model.blocks().len() {
            let (q, kv) = self.project(layer, &cuts[layer], position)?;
            let mut keys = reserved(position + 1)?;
            if let Some(cache) = cache {
                for (k, v) in &cache.layers[layer] {
                    keys.push((k.try_clone()?, v.try_clone()?));
                }
            }
            keys.push(kv);
            cuts.push(self.finish_block(layer, &cuts[layer], position, &q, &keys)?);
            layers.push(keys);
        }
        let logits = self.finish(cuts.last().ok_or(Error::Arithmetic)?)?;
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
