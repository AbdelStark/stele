//! RFC-0006 A2 mode 1: claims on one virtual tensor, with verifier-computed A(r).
use crate::{
    append,
    batch::{field_degree, Claim, Reduction, RlcRecord},
    reserve, round, Dense, Error, Instance, Proof, ScRecord, Summand, Term,
};
use alloc::vec::Vec;
use stele_hash::{AbsorbLabel, ChallengeField, ChallengeLabel, Transcript};
/// The leading Boolean prefix of a point: its length and the block index it selects.
fn boolean_prefix<K: ChallengeField + Eq>(point: &[K]) -> (usize, usize) {
    let (zero, one) = (K::from_i64(0), K::from_i64(1));
    let (mut prefix, mut start) = (0, 0);
    for x in point {
        if *x != zero && *x != one {
            break;
        }
        start = 2 * start + usize::from(*x == one);
        prefix += 1;
    }
    (prefix, start)
}
/// `out += weight · eq(point, ·)`. A leading Boolean prefix selects a contiguous block;
/// overlapping blocks accumulate.
fn add_eq<K: ChallengeField + Eq>(out: &mut [K], point: &[K], weight: K) -> Result<(), Error> {
    let (prefix, start) = boolean_prefix(point);
    let suffix = crate::parallel::eq_table_scaled(&point[prefix..], weight)?;
    // A2: start < 2^prefix and suffix.len() = 2^(m-prefix), so the block fits.
    let begin = start * suffix.len();
    let block = &mut out[begin..begin + suffix.len()];
    crate::parallel::for_each_chunk(block, |offset, chunk| {
        for (target, value) in chunk.iter_mut().zip(&suffix[offset..]) {
            *target = *target + *value;
        }
    });
    Ok(())
}
/// In a batch of at least `MANY` claims, a block below `HUGE_BLOCK` entries is summed and
/// filled on one thread: the claims are the parallel items there. A batch of a few claims
/// splits every block on the pool, because nothing else runs beside it.
const MANY: usize = 64;
const HUGE_BLOCK: usize = 1 << 22;
/// The window of the smaller of those blocks, see [`Batch::fill_windows`].
const SMALL_BLOCK: usize = 1 << 15;
/// A claim's coefficient once its leading coordinate `z0` is set aside:
/// `weight · eq(point, ·)` on the block of `2^point.len()` entries at `begin`.
struct Piece<'a, K> {
    begin: usize,
    point: &'a [K],
    z0: K,
    weight: K,
}
impl<K> Piece<'_, K> {
    fn len(&self) -> usize {
        1 << self.point.len()
    }
    /// Whether this block of a batch of `claims` claims stays on one thread.
    fn serial(&self, claims: usize) -> bool {
        claims >= MANY && self.len() < HUGE_BLOCK
    }
}
/// Verifier-owned claims. The caller must derive the virtual role from its verified plan;
/// committed tensors use PCS functional openings, never a proof-supplied routing flag.
pub struct Batch<'a, K> {
    /// Plan batch identity, unique among invocations.
    pub id: u64,
    /// The virtual tensor identity.
    pub tensor: u64,
    /// Its hypercube dimension.
    pub num_vars: u32,
    /// Nonempty ordered (point, value) claims; overlaps and duplicates are allowed.
    pub claims: &'a [(Vec<K>, K)],
}
impl<K: ChallengeField + Eq> Batch<'_, K> {
    fn validate(&self) -> Result<(), Error> {
        if self.claims.is_empty()
            || u32::try_from(self.claims.len()).is_err()
            || self
                .claims
                .iter()
                .any(|(z, _)| z.len() != self.num_vars as usize)
        {
            return Err(Error::InvalidBatch);
        }
        Ok(())
    }
    fn table(&self, table: &[K]) -> Result<(), Error> {
        self.validate()?;
        if !table.len().is_power_of_two() || table.len().trailing_zeros() != self.num_vars {
            return Err(Error::PublicShape);
        }
        Ok(())
    }
    /// Canonical mode-1 descriptor, binding every point/value before gamma.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        append(&mut out, &[1, field_degree::<K>(), 1])?;
        append(&mut out, &self.id.to_le_bytes())?;
        append(&mut out, &self.tensor.to_le_bytes())?;
        append(&mut out, &self.num_vars.to_le_bytes())?;
        append(&mut out, &(self.claims.len() as u32).to_le_bytes())?;
        for (z, value) in self.claims {
            for x in z.iter().chain(core::iter::once(value)) {
                append(&mut out, x.to_le_bytes().as_ref())?;
            }
        }
        Ok(out)
    }
    /// Pure coefficient construction, not a way to supply a protocol challenge.
    /// Maximal leading Boolean prefixes select contiguous blocks; overlaps accumulate.
    pub fn coefficient_table(&self, gamma: K) -> Result<Vec<K>, Error> {
        self.validate()?;
        let n = 1usize.checked_shl(self.num_vars).ok_or(Error::Capacity)?;
        let mut out = crate::parallel::build(n, |_| K::from_i64(0))?;
        let mut weight = K::from_i64(1);
        for (z, _) in self.claims {
            add_eq(&mut out, z, weight)?;
            weight = weight * gamma;
        }
        Ok(out)
    }
    /// Each claim's coefficient over the domain without its leading coordinate.
    fn pieces(&self, gamma: K) -> Result<Vec<Piece<'_, K>>, Error> {
        let mut out = Vec::new();
        reserve(&mut out, self.claims.len())?;
        let mut weight = K::from_i64(1);
        for (z, _) in self.claims {
            let (prefix, start) = boolean_prefix(&z[1..]);
            let point = &z[1 + prefix..];
            out.push(Piece {
                begin: start << point.len(),
                point,
                z0: z[0],
                weight,
            });
            weight = weight * gamma;
        }
        Ok(out)
    }
    /// The three values of round 0 over a base-field table, with each claim's coefficient
    /// kept as its factors (RFC-0006 A2, A5; task E20-24), so no extension table of the
    /// full domain is built. Claim `j` contributes `γ^j · eq(z_0, X) · (P + X·(Q − P))`,
    /// where `P` and `Q` are the sums of `eq(z', ·)` against its block of the lower and of
    /// the upper half of `table`.
    fn round0_base(
        &self,
        table: &[stele_field::M31],
        pieces: &[Piece<'_, K>],
    ) -> Result<[K; 3], Error> {
        let half = table.len() / 2;
        let (zero, one) = (K::from_i64(0), K::from_i64(1));
        let sums = crate::parallel::map(pieces.len(), |j| -> Result<[K; 2], Error> {
            let piece = &pieces[j];
            let low = &table[piece.begin..piece.begin + piece.len()];
            let high = &table[half + piece.begin..half + piece.begin + piece.len()];
            let mut sums = [zero; 2];
            if piece.serial(pieces.len()) {
                let eq = stele_poly::eq_table(piece.point).map_err(|_| Error::Capacity)?;
                for ((e, a), b) in eq.iter().zip(low).zip(high) {
                    sums[0] = sums[0] + e.mul_m31(*a);
                    sums[1] = sums[1] + e.mul_m31(*b);
                }
            } else {
                let eq = crate::parallel::eq_table(piece.point)?;
                crate::parallel::sum_ranges(eq.len(), &mut sums, |range, out| {
                    out.fill(zero);
                    for i in range {
                        out[0] = out[0] + eq[i].mul_m31(low[i]);
                        out[1] = out[1] + eq[i].mul_m31(high[i]);
                    }
                    Ok(())
                })?;
            }
            Ok(sums)
        });
        let mut values = [zero; 3];
        for (piece, sums) in pieces.iter().zip(sums) {
            let ([p, q], z0, w) = (sums?, piece.z0, piece.weight);
            values[0] = values[0] + w * (one - z0) * p;
            values[1] = values[1] + w * z0 * q;
            values[2] = values[2] + w * (z0 + z0 + z0 - one) * (q + q - p);
        }
        Ok(values)
    }
    /// [`Self::coefficient_table`] with its leading coordinate bound to `r0`, built at
    /// half the size: claim `j` weighs `γ^j · eq(z_0, r0)` over its other coordinates.
    /// A block that is not [`Piece::serial`] is filled on the pool, one after another. The
    /// serial ones are filled through disjoint windows, the smaller ones first.
    fn folded_coefficient_table(&self, pieces: &[Piece<'_, K>], r0: K) -> Result<Vec<K>, Error> {
        let one = K::from_i64(1);
        let weight =
            |piece: &Piece<'_, K>| piece.weight * ((one - piece.z0) * (one - r0) + piece.z0 * r0);
        let n = 1usize
            .checked_shl(self.num_vars - 1)
            .ok_or(Error::Capacity)?;
        let mut out = crate::parallel::build(n, |_| K::from_i64(0))?;
        for piece in pieces.iter().filter(|p| !p.serial(pieces.len())) {
            let eq = crate::parallel::eq_table_scaled(piece.point, weight(piece))?;
            let target = &mut out[piece.begin..piece.begin + piece.len()];
            crate::parallel::for_each_chunk(target, |offset, chunk| {
                for (t, e) in chunk.iter_mut().zip(&eq[offset..]) {
                    *t = *t + *e;
                }
            });
        }
        if pieces.len() >= MANY {
            Self::fill_windows(&mut out, pieces, 0..SMALL_BLOCK, &weight)?;
            Self::fill_windows(&mut out, pieces, SMALL_BLOCK..HUGE_BLOCK, &weight)?;
        }
        Ok(out)
    }
    /// `out += weight(piece) · eq(piece.point, ·)` for the pieces whose length is in
    /// `sizes`. Such a block is dyadic and shorter than `sizes.end`, so it lies inside one
    /// aligned window of `sizes.end` entries, and the windows are disjoint tasks.
    fn fill_windows(
        out: &mut [K],
        pieces: &[Piece<'_, K>],
        sizes: core::ops::Range<usize>,
        weight: &(impl Fn(&Piece<'_, K>) -> K + Sync),
    ) -> Result<(), Error> {
        let (n, window) = (out.len(), sizes.end);
        let mut inside = Vec::new();
        reserve(&mut inside, pieces.len())?;
        inside.extend((0..pieces.len()).filter(|&j| sizes.contains(&pieces[j].len())));
        inside.sort_by_key(|&j| pieces[j].begin);
        let mut windows: Vec<(usize, usize)> = Vec::new();
        reserve(&mut windows, inside.len())?;
        // `members[g]` is the range of `inside` that lies in window `g`.
        let mut members: Vec<core::ops::Range<usize>> = Vec::new();
        reserve(&mut members, inside.len())?;
        for (at, &j) in inside.iter().enumerate() {
            let begin = pieces[j].begin / window * window;
            match (windows.last(), members.last_mut()) {
                (Some(&(last, _)), Some(run)) if last == begin => run.end = at + 1,
                _ => {
                    windows.push((begin, window.min(n - begin)));
                    members.push(at..at + 1);
                }
            }
        }
        crate::parallel::for_each_block(out, &windows, |g, block| {
            for &j in &inside[members[g].clone()] {
                let (piece, weight) = (&pieces[j], weight(&pieces[j]));
                let eq = stele_poly::eq_table(piece.point).map_err(|_| Error::Capacity)?;
                let target = &mut block[piece.begin - windows[g].0..][..piece.len()];
                for (t, e) in target.iter_mut().zip(eq) {
                    *t = *t + e * weight;
                }
            }
            Ok(())
        })
    }
    /// Direct verifier evaluation in O(t*(m+1)); no coefficient table or final A value.
    pub fn coefficient(&self, point: &[K], gamma: K) -> Result<K, Error> {
        self.validate()?;
        if point.len() != self.num_vars as usize {
            return Err(Error::PublicShape);
        }
        let (mut weight, mut sum) = (K::from_i64(1), K::from_i64(0));
        for (z, _) in self.claims {
            sum =
                sum + weight * stele_poly::eq_evaluate(z, point).map_err(|_| Error::PublicShape)?;
            weight = weight * gamma;
        }
        Ok(sum)
    }
    fn start(&self, transcript: &mut Transcript<K>) -> Result<(K, K), Error> {
        transcript.absorb(AbsorbLabel::Batch, &self.encode()?)?;
        let gamma = transcript.challenge(ChallengeLabel::BatchCoefficient)?;
        let (mut weight, mut sum) = (K::from_i64(1), K::from_i64(0));
        for (_, value) in self.claims {
            sum = sum + weight * *value;
            weight = weight * gamma;
        }
        Ok((gamma, sum))
    }
    fn finish(
        &self,
        value: K,
        point: &[K],
        gamma: K,
        running: K,
        transcript: &mut Transcript<K>,
    ) -> Result<(), Error> {
        if value * self.coefficient(point, gamma)? != running {
            return Err(Error::FinalEvaluationMismatch);
        }
        let mut out = Vec::new();
        append(&mut out, &self.id.to_le_bytes())?;
        append(&mut out, &[1])?;
        append(&mut out, &self.tensor.to_le_bytes())?;
        append(&mut out, value.to_le_bytes().as_ref())?;
        transcript.absorb(AbsorbLabel::BatchFinal, &out)?;
        Ok(())
    }
    // Local polynomial description for Dense only; never a transcript instance.
    fn product(&self, sum: K) -> Result<Instance<K>, Error> {
        let mut inputs = Vec::new();
        reserve(&mut inputs, 2)?;
        inputs.extend([0, 1]);
        let mut factors = Vec::new();
        reserve(&mut factors, 2)?;
        factors.extend([0, 1]);
        let mut terms = Vec::new();
        reserve(&mut terms, 1)?;
        terms.push(Term {
            coefficient: K::from_i64(1),
            factors,
        });
        Ok(Instance {
            id: self.id,
            num_vars: self.num_vars,
            inputs,
            terms,
            claimed_sum: sum,
        })
    }
    /// Prove with gamma drawn only by the engine after the complete descriptor.
    pub fn prove(&self, table: Vec<K>, transcript: &mut Transcript<K>) -> Result<Proof<K>, Error> {
        self.prove_with_point(table, transcript)
            .map(|(proof, _)| proof)
    }
    /// The same producer, also returning its reduced point for the source opening.
    /// The returned point grants no verifier authority.
    pub fn prove_with_point(
        &self,
        table: Vec<K>,
        transcript: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Vec<K>), Error> {
        self.table(&table)?;
        let (gamma, mut running) = self.start(transcript)?;
        let mut tables = Vec::new();
        reserve(&mut tables, 2)?;
        tables.push(table);
        tables.push(self.coefficient_table(gamma)?);
        let product = self.product(running)?;
        let mut dense = Dense::new(&product, tables)?;
        let mut rounds = Vec::new();
        reserve(&mut rounds, self.num_vars as usize)?;
        let mut point = Vec::new();
        reserve(&mut point, self.num_vars as usize)?;
        for index in 0..self.num_vars {
            let values = dense.round(&product)?;
            let (r, next) = round(self.id, index, &values, running, transcript)?;
            dense.fold(r)?;
            rounds.push(values);
            point.push(r);
            running = next;
        }
        let mut final_values = Vec::new();
        reserve(&mut final_values, 1)?;
        final_values.push(dense.final_values()?[0]);
        self.finish(final_values[0], &point, gamma, running, transcript)?;
        Ok((
            Proof {
                rounds,
                final_values,
            },
            point,
        ))
    }
    /// Base-field first-round variant of [`Self::prove_with_point`] (RFC-0006 A5, task E20-01):
    /// reads `&[M31]` directly in round 0 and folds into a half-sized `Vec<K>`, avoiding a
    /// full-sized extension-field copy of `table`. Output proof bytes and point are bit-identical.
    pub fn prove_base_with_point(
        &self,
        table: &[stele_field::M31],
        transcript: &mut Transcript<K>,
    ) -> Result<(Proof<K>, Vec<K>), Error> {
        self.validate()?;
        if !table.len().is_power_of_two() || table.len().trailing_zeros() != self.num_vars {
            return Err(Error::PublicShape);
        }
        let (gamma, mut running) = self.start(transcript)?;
        let mut rounds = Vec::new();
        reserve(&mut rounds, self.num_vars as usize)?;
        let mut point = Vec::new();
        reserve(&mut point, self.num_vars as usize)?;
        if self.num_vars == 0 {
            let mut final_values = Vec::new();
            reserve(&mut final_values, 1)?;
            final_values.push(K::from_i64(1).mul_m31(table[0]));
            self.finish(final_values[0], &point, gamma, running, transcript)?;
            return Ok((
                Proof {
                    rounds,
                    final_values,
                },
                point,
            ));
        }
        let pieces = self.pieces(gamma)?;
        let values0 = self.round0_base(table, &pieces)?;
        let (r0, next) = round(self.id, 0, &values0, running, transcript)?;
        let mut round0 = Vec::new();
        reserve(&mut round0, 3)?;
        round0.extend_from_slice(&values0);
        rounds.push(round0);
        point.push(r0);
        running = next;

        let folded_table = crate::parallel::fold_base(table, r0)?;
        let coeff = self.folded_coefficient_table(&pieces, r0)?;
        let mut tables = Vec::new();
        reserve(&mut tables, 2)?;
        tables.push(folded_table);
        tables.push(coeff);
        let product = self.product(running)?;
        let mut dense = Dense::from_folded(tables, self.num_vars - 1)?;
        for index in 1..self.num_vars {
            let values = dense.round(&product)?;
            let (r, next) = round(self.id, index, &values, running, transcript)?;
            dense.fold(r)?;
            rounds.push(values);
            point.push(r);
            running = next;
        }
        let mut final_values = Vec::new();
        reserve(&mut final_values, 1)?;
        final_values.push(dense.final_values()?[0]);
        self.finish(final_values[0], &point, gamma, running, transcript)?;
        Ok((
            Proof {
                rounds,
                final_values,
            },
            point,
        ))
    }
    /// Reduce to one y(r) obligation, even when A(r)=0; this is not statement acceptance.
    pub fn verify(
        &self,
        proof: &Proof<K>,
        transcript: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        self.validate()?;
        if proof.rounds.len() != self.num_vars as usize
            || proof.rounds.iter().any(|r| r.len() != 3)
            || proof.final_values.len() != 1
        {
            return Err(Error::ProofShape);
        }
        let (gamma, mut running) = self.start(transcript)?;
        let mut point = Vec::new();
        reserve(&mut point, self.num_vars as usize)?;
        for (index, values) in proof.rounds.iter().enumerate() {
            let (r, next) = round(self.id, index as u32, values, running, transcript)?;
            point.push(r);
            running = next;
        }
        self.finish(proof.final_values[0], &point, gamma, running, transcript)?;
        let mut copy = Vec::new();
        reserve(&mut copy, point.len())?;
        copy.extend_from_slice(&point);
        let mut claims = Vec::new();
        reserve(&mut claims, 1)?;
        claims.push(Claim {
            tensor: self.tensor,
            point: copy,
            value: proof.final_values[0],
        });
        Ok(Reduction {
            point,
            claims,
            sc: ScRecord {
                id: self.id,
                m: self.num_vars,
                degree: 2,
                field_degree: field_degree::<K>(),
                numerator: 2 * u64::from(self.num_vars),
            },
            rlc: RlcRecord {
                id: self.id,
                t: self.claims.len() as u32,
                field_degree: field_degree::<K>(),
                numerator: self.claims.len() as u64,
            },
        })
    }
    /// Discharge the sole tensor evaluation against verifier-owned public data.
    pub fn verify_public(
        &self,
        proof: &Proof<K>,
        table: &[K],
        transcript: &mut Transcript<K>,
    ) -> Result<Reduction<K>, Error> {
        self.table(table)?;
        let result = self.verify(proof, transcript)?;
        let weights = stele_poly::eq_table(&result.point).map_err(|_| Error::Capacity)?;
        let actual = table
            .iter()
            .zip(weights)
            .fold(K::from_i64(0), |s, (v, w)| s + *v * w);
        if actual != result.claims[0].value {
            return Err(Error::ClaimMismatch);
        }
        Ok(result)
    }
}
