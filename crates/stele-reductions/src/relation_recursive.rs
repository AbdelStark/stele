//! RFC-0026 A29 / RFC-0029 §2: joined recursive openings for segments, stacked
//! multiplicity sources, and certified model sources (profile byte 6, task E19-04).
//!
//! Every committed source uses RFC-0010 A17 version-4 `CircleCoeff` (`b = 2`, Policy 3,
//! `T = 100`, QM31):
//! - Segment witness stacks and segment multiplicity stacks commit in fresh mode
//!   (`PreparedRecursive`, 32-byte root only, no registration certificate), batch their
//!   claims via RFC-0006 A2 mode 1 (`claim_batch`), close level 0 into the shared
//!   `l1_spec`, and drop their level-0 matrix and codeword immediately by value.
//! - Model weight sources commit in certified mode (`CertifiedModelSource`, streaming
//!   column recomputation so full codewords are never resident) and close level 0 into the
//!   same `l1_spec`.
//! - All pending level-1 sources join ONE recursion per proof (`prove_joined_tail` /
//!   `verify_joined_tail`, `PcsLevelGamma`).
//! - Non-power-of-two multiplicity tables (`check.t < 2^k`) reduce their prefix-mask
//!   functional to a fresh point claim via one `k`-variable sumcheck against the exact
//!   `O(k)` closed-form verifier MLE `eq_prefix_mle` (resolving Q51).
use super::*;
use stele_pcs::recursive::{
    circle_coeff_params, fresh_level0_proof_size, policy3_fresh_queries, prove_joined_tail,
    verify_certified_level0, verify_certified_registration, verify_fresh_level0_at_point,
    verify_joined_tail, CertifiedModelSource, CertifiedPlan, CertifiedSource, ColumnFunctional,
    JoinedTailPlan, LevelSpec, PendingLevel1Prover, PendingLevel1Verifier, PreparedRecursive,
    RecursivePlan, RecursiveSource, VerifiedCertifiedSource, DEFAULT_TARGET_BITS,
};

const EXT_DEGREE: u8 = 4;
const TARGET_BITS: u16 = DEFAULT_TARGET_BITS;
const BLOWUP: u8 = 2;

/// Disjoint instance ID namespaces for RFC-0026 A29 (continuation of `relation.rs` tags 0..=6).
const PREFIX_MASK_ID: u64 = (1 << 62) | (7 << 48);
const MU_BATCH_ID: u64 = (1 << 62) | (8 << 48);
const WITNESS_OPENING_ID: u64 = (1 << 62) | (9 << 48);
const MU_OPENING_ID: u64 = (1 << 62) | (10 << 48);
const MODEL_OPENING_ID: u64 = (1 << 62) | (11 << 48);
const JOINED_TAIL_ID: u64 = (1 << 62) | (12 << 48);

/// One RFC-0029 certified model source layout derived from the relation (RFC-0026 A5, A29).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveModelLayout {
    pub id: u64,
    pub plan: CertifiedPlan,
    pub bits: u8,
    pub blocks: Vec<(usize, usize)>,
}

/// Prover-side registered RFC-0029 certified model source together with its raw M31 weight message
/// (full codewords are never stored; queried columns are recomputed on the fly, RFC-0029 §1.3).
pub struct RecursiveModelSource<'a> {
    pub prepared: CertifiedModelSource<K>,
    pub message: alloc::borrow::Cow<'a, [M31]>,
}

impl<'a> RecursiveModelSource<'a> {
    /// Register a certified model source borrowing `message` without copying weights.
    pub fn register(layout: &RecursiveModelLayout, message: &'a [M31]) -> Result<Self, Error> {
        let prepared =
            CertifiedModelSource::<K>::register(layout.id, layout.plan.clone(), message)?;
        Ok(Self {
            prepared,
            message: alloc::borrow::Cow::Borrowed(message),
        })
    }
}

/// Exact `O(k)` multilinear extension of `f(x) = eq(z, x) * [x < t]` evaluated at `r`
/// (both `z` and `r` MSB-first of length `k`, `0 <= t <= 2^k`; resolves RFC-0029 Q51).
pub(crate) fn eq_prefix_mle(z: &[K], t: usize, r: &[K]) -> K {
    debug_assert_eq!(z.len(), r.len());
    let k = z.len();
    let one = K::from_i64(1);
    let zero = K::from_i64(0);
    if t == 0 {
        return zero;
    }
    let full_cap = 1usize.checked_shl(k as u32);
    if full_cap.is_some_and(|cap| t >= cap) {
        return z.iter().zip(r).fold(one, |acc, (&zi, &ri)| {
            acc * ((one - zi) * (one - ri) + zi * ri)
        });
    }
    let mut suf = vec![one; k + 1];
    for j in (0..k).rev() {
        let w0 = (one - z[j]) * (one - r[j]);
        let w1 = z[j] * r[j];
        suf[j] = (w0 + w1) * suf[j + 1];
    }
    let mut total = zero;
    let mut pref = one;
    for j in 0..k {
        let w0 = (one - z[j]) * (one - r[j]);
        let w1 = z[j] * r[j];
        if ((t >> (k - 1 - j)) & 1) == 1 {
            total = total + pref * w0 * suf[j + 1];
            pref = pref * w1;
        } else {
            pref = pref * w0;
        }
    }
    total
}

/// Select the byte-minimising single-level Policy-3 fresh plan (`b = 2`, QM31, `T = 100`)
/// for a source of `2^bits` M31 entries (padded to at least `bits = 2`), enforcing the
/// single-round QM31 proximity cap `2 * ell * (e + 1) <= floor(|K| / 2^100)`.
pub(crate) fn select_fresh_level0(bits: u8) -> Result<RecursivePlan, Error> {
    let total_bits = bits.max(2);
    if total_bits > 30 {
        return Err(Error::Unsupported);
    }
    // `floor((2^31 - 1)^4 / 2^100) = 16,777,215` for QM31 at T = 100.
    let cap: u64 = 16_777_215;
    let mut best: Option<(u64, RecursivePlan)> = None;
    for ell in 1..total_bits {
        let m = total_bits - ell;
        if m + BLOWUP > 30 {
            continue;
        }
        let Ok((q0, _, _, e0)) = policy3_fresh_queries(m, BLOWUP, TARGET_BITS) else {
            continue;
        };
        let Some(prox) = 2u64
            .checked_mul(u64::from(ell))
            .and_then(|v| v.checked_mul(e0.checked_add(1)?))
        else {
            continue;
        };
        if prox > cap || u64::from(q0) > cap {
            continue;
        }
        let spec = LevelSpec::new(ell, m, BLOWUP);
        let Ok(plan) = RecursivePlan::new(vec![spec], EXT_DEGREE, TARGET_BITS) else {
            continue;
        };
        let Some(rows) = 1u64.checked_shl(u32::from(ell)) else {
            continue;
        };
        let col_cost = rows
            .saturating_mul(4)
            .saturating_add(32u64 * u64::from(m + BLOWUP));
        let bytes = u64::from(q0).saturating_mul(col_cost);
        if best.as_ref().is_none_or(|(b, _)| bytes < *b) {
            best = Some((bytes, plan));
        }
    }
    best.map(|(_, p)| p).ok_or(Error::Unsupported)
}

/// Select the byte-minimising single-level Policy-3 certified plan (`b = 2`, QM31, `T = 100`,
/// radius `e_c = floor((D - 1) / 3)`) for a model source of `2^bits` M31 entries.
pub(crate) fn select_certified_level0(bits: u8) -> Result<CertifiedPlan, Error> {
    let total_bits = bits.max(2);
    if total_bits > 30 {
        return Err(Error::Unsupported);
    }
    let mut best: Option<(u64, CertifiedPlan)> = None;
    for ell in 1..total_bits {
        let m = total_bits - ell;
        if m + BLOWUP > 30 {
            continue;
        }
        let Ok((_, _, _, e_c)) = circle_coeff_params(m, BLOWUP) else {
            continue;
        };
        let spec = LevelSpec::new(ell, m, BLOWUP);
        let Ok(plan) = CertifiedPlan::new(vec![spec], EXT_DEGREE, TARGET_BITS, e_c) else {
            continue;
        };
        let qo = plan.level_queries()[0];
        let Some(rows) = 1u64.checked_shl(u32::from(ell)) else {
            continue;
        };
        let col_cost = rows
            .saturating_mul(4)
            .saturating_add(32u64 * u64::from(m + BLOWUP));
        let bytes = u64::from(qo).saturating_mul(col_cost);
        if best.as_ref().is_none_or(|(b, _)| bytes < *b) {
            best = Some((bytes, plan));
        }
    }
    best.map(|(_, p)| p).ok_or(Error::Unsupported)
}

/// Select the shared level-1..L-1 `LevelSpec` tail for `max_l0_m` and `max_blocks`,
/// minimizing exact `JoinedTailPlan::tail_proof_size()` over `ell_1` while satisfying
/// `JoinedTailPlan::new` for any `1..=max_blocks`.
fn select_tail_levels(max_l0_m: u8, max_blocks: u16) -> Result<Vec<LevelSpec>, Error> {
    let total_bits = max_l0_m.max(2);
    let blocks = max_blocks.max(1);
    let mut best: Option<(usize, Vec<LevelSpec>)> = None;
    for ell1 in 1..total_bits {
        let m1 = total_bits - ell1;
        if m1 + BLOWUP > 30 {
            continue;
        }
        let l1 = LevelSpec::new(ell1, m1, BLOWUP);
        let mut candidates = vec![vec![l1]];
        if m1 >= 2 {
            if let Ok(sub) =
                RecursivePlan::fresh_for_size(m1, EXT_DEGREE, TARGET_BITS, true, &[BLOWUP])
            {
                let mut chain = Vec::with_capacity(1 + sub.levels().len());
                chain.push(l1);
                chain.extend_from_slice(sub.levels());
                candidates.push(chain);
            }
        }
        for chain in candidates {
            if let Ok(plan) = JoinedTailPlan::new(chain.clone(), blocks, EXT_DEGREE, TARGET_BITS) {
                if let Ok(sz) = plan.tail_proof_size() {
                    if best.as_ref().is_none_or(|(b, _)| sz < *b) {
                        best = Some((sz, chain));
                    }
                }
            }
        }
    }
    best.map(|(_, levels)| levels).ok_or(Error::Unsupported)
}

/// Derive the RFC-0029 certified model source layouts for weights of `2^lengths[i]` entries in
/// `ColumnId` order (same RFC-0026 A5 sequential split and per-bin largest-first placement).
pub fn recursive_model_layout_for(lengths: &[u8]) -> Result<Vec<RecursiveModelLayout>, Error> {
    if lengths.is_empty() {
        return Ok(Vec::new());
    }
    let mut totals: Vec<usize> = Vec::new();
    let mut placement = vec![(0usize, 0usize); lengths.len()];
    for (w, &n) in lengths.iter().enumerate() {
        if n > 30 {
            return Err(Error::Unsupported);
        }
        let size = 1usize << n;
        if size > MODEL_CAP {
            return Err(Error::Unsupported);
        }
        match totals.last_mut() {
            Some(total) if *total + size <= MODEL_CAP => *total += size,
            _ => totals.push(size),
        }
        placement[w].0 = totals.len() - 1;
    }
    let mut out = Vec::with_capacity(totals.len());
    for (k, &total) in totals.iter().enumerate() {
        let mut order: Vec<usize> = (0..lengths.len())
            .filter(|w| placement[*w].0 == k)
            .collect();
        order.sort_by(|a, b| lengths[*b].cmp(&lengths[*a]));
        let mut offset = 0usize;
        for w in order {
            placement[w].1 = offset;
            offset += 1 << lengths[w];
        }
        let bits = ceil_log2(total).max(2);
        if bits > 30 {
            return Err(Error::Unsupported);
        }
        let plan = select_certified_level0(bits)?;
        let blocks = placement
            .iter()
            .enumerate()
            .filter(|(_, (source, _))| *source == k)
            .map(|(w, (_, off))| (w, *off))
            .collect();
        out.push(RecursiveModelLayout {
            id: MODEL + k as u64,
            plan,
            bits,
            blocks,
        });
    }
    Ok(out)
}

/// Derive the RFC-0029 certified model source layouts for `relation` (same A5 bin packing).
pub fn recursive_model_layout(relation: &Relation) -> Result<Vec<RecursiveModelLayout>, Error> {
    relation.validate().map_err(Error::StatementMismatch)?;
    let lengths: Vec<u8> = (0..relation.columns.len())
        .filter(|i| relation.columns[*i].kind == Kind::Weight)
        .map(|i| relation.columns[i].log_len)
        .collect();
    recursive_model_layout_for(&lengths)
}

/// Build and register every RFC-0029 certified model source of `relation` from `values`.
/// Full codewords are dropped immediately after certificate generation (RFC-0029 §1.3).
pub fn recursive_model_sources(
    relation: &Relation,
    values: &Values,
) -> Result<Vec<RecursiveModelSource<'static>>, Error> {
    let layouts = recursive_model_layout(relation)?;
    let weight_cols: Vec<ColumnId> = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| relation.columns[id.0 as usize].kind == Kind::Weight)
        .collect();
    let mut out = Vec::with_capacity(layouts.len());
    for layout in layouts {
        let mut message = vec![M31::from_i64(0); 1usize << layout.bits];
        for &(w, offset) in &layout.blocks {
            let col = column(relation, values, weight_cols[w])?;
            for (dst, v) in message[offset..].iter_mut().zip(col.iter()) {
                *dst = M31::from_i64(v);
            }
        }
        let prepared = CertifiedModelSource::<K>::register(layout.id, layout.plan, &message)?;
        out.push(RecursiveModelSource {
            prepared,
            message: alloc::borrow::Cow::Owned(message),
        });
    }
    Ok(out)
}

/// Verify one RFC-0029 certified model registration against its derived layout.
pub fn verify_recursive_model(
    layout: &RecursiveModelLayout,
    root: [u8; 32],
    cert_proof: &[u8],
) -> Result<VerifiedCertifiedSource<K>, Error> {
    let source = CertifiedSource::<K>::new(layout.id, layout.plan.clone(), root)?;
    Ok(verify_certified_registration(source, cert_proof)?)
}

/// Stacked multiplicity plan for one segment (RFC-0026 A29).
struct MuStackPlan {
    id: u64,
    bits: u8,
    plan: RecursivePlan,
    /// Aligned starting offset of each check's `2^k` multiplicity vector inside the stack.
    offsets: Vec<usize>,
}

struct RecursiveSegmentPlan {
    segment: u32,
    groups: Vec<Group>,
    witness_bits: u8,
    witness_plan: Option<(u64, RecursivePlan)>,
    checks: Vec<Check>,
    mu_stack: Option<MuStackPlan>,
    sizes: Vec<u8>,
    matmuls: Vec<usize>,
    virtuals: Vec<ColumnId>,
}

struct RecursiveEnginePlan {
    digest: [u8; 32],
    segments: Vec<RecursiveSegmentPlan>,
    weights: Vec<Weight>,
    model: Vec<RecursiveModelLayout>,
    tail_levels: Vec<LevelSpec>,
}

#[cfg(test)]
fn plan_recursive(relation: &Relation) -> Result<RecursiveEnginePlan, Error> {
    plan_recursive_with_bound(relation, DEFAULT_INSTANCE_BOUND)
}

fn plan_recursive_with_bound(
    relation: &Relation,
    instance_bound: u8,
) -> Result<RecursiveEnginePlan, Error> {
    relation.validate().map_err(Error::StatementMismatch)?;
    for col in &relation.columns {
        if let Kind::Virtual(Def::Contraction {
            free,
            summed,
            lhs,
            rhs,
        }) = &col.kind
        {
            let shared = (0..*free)
                .filter(|d| lhs.vars.contains(d) && rhs.vars.contains(d))
                .count();
            if shared + usize::from(*summed) > usize::from(stele_ir::relation::MAX_VARS) {
                return Err(Error::Unsupported);
            }
        }
    }
    let seg_count = relation.segments();
    if seg_count > u32::from(u16::MAX) {
        return Err(Error::Unsupported);
    }
    let col_segs = relation.column_segments();
    let weight_segs = relation.weight_segments();
    let model = recursive_model_layout(relation)?;

    let weight_cols: Vec<ColumnId> = (0..relation.columns.len() as u32)
        .map(ColumnId)
        .filter(|id| relation.columns[id.0 as usize].kind == Kind::Weight)
        .collect();
    let mut weights = Vec::with_capacity(weight_cols.len());
    for (w_idx, col_id) in weight_cols.iter().enumerate() {
        let mut found = None;
        for (src_idx, layout) in model.iter().enumerate() {
            if let Some(&(_, offset)) = layout.blocks.iter().find(|&&(w, _)| w == w_idx) {
                found = Some((src_idx, offset));
                break;
            }
        }
        let (source, offset) = found.ok_or(Error::Weights)?;
        weights.push(Weight {
            column: *col_id,
            n: relation.columns[col_id.0 as usize].log_len,
            source,
            offset,
        });
    }

    let mut max_l0_m: u8 = 2;
    let mut max_blocks: u16 = model.len() as u16;
    for layout in &model {
        max_l0_m = max_l0_m.max(layout.plan.levels()[0].m);
    }

    let mut segments = Vec::with_capacity(seg_count as usize);
    for seg in 0..seg_count {
        let seg_u64 = u64::from(seg);
        let source_base = seg_u64 << 16;
        let mut groups = Vec::new();
        for (g, group_meta) in relation.groups.iter().enumerate() {
            if group_meta.segment != seg {
                continue;
            }
            let columns: Vec<ColumnId> = (0..relation.columns.len() as u32)
                .map(ColumnId)
                .filter(|id| {
                    relation.columns[id.0 as usize].kind
                        == Kind::Witness(stele_ir::relation::GroupId(g as u32))
                })
                .collect();
            let c = ceil_log2(columns.len().max(1));
            groups.push(Group {
                columns,
                n: group_meta.log_len,
                c,
                offset: 0,
            });
        }
        let mut order: Vec<usize> = (0..groups.len()).collect();
        order.sort_by(|a, b| (groups[*b].n + groups[*b].c).cmp(&(groups[*a].n + groups[*a].c)));
        let mut total = 0usize;
        for g in order {
            let bits = u32::from(groups[g].n) + u32::from(groups[g].c);
            if bits > 30 {
                return Err(Error::Unsupported);
            }
            groups[g].offset = total;
            total = total.checked_add(1 << bits).ok_or(Error::Unsupported)?;
        }
        let (witness_bits, witness_plan) = if groups.is_empty() {
            (0u8, None)
        } else {
            let bits = ceil_log2(total).max(2);
            if bits > 30 {
                return Err(Error::Unsupported);
            }
            let plan = select_fresh_level0(bits)?;
            max_l0_m = max_l0_m.max(plan.levels()[0].m);
            max_blocks = max_blocks.checked_add(1).ok_or(Error::Unsupported)?;
            (bits, Some((source_base + 2, plan)))
        };

        let mut targets: Vec<(Target, Vec<Member>)> = Vec::new();
        let mut add =
            |target: Target, member: Member| match targets.iter_mut().find(|(t, _)| *t == target) {
                Some((_, members)) => members.push(member),
                None => targets.push((target, vec![member])),
            };
        for lookup in &relation.lookups {
            if relation.lookup_segment_with(lookup, &col_segs) != seg {
                continue;
            }
            add(
                Target::Table(lookup.table.0),
                Member {
                    m: lookup.vars,
                    block_bits: 0,
                    block_index: 0,
                    tuple: lookup.tuple.iter().map(|r| (r.clone(), 0)).collect(),
                    selector: lookup.selector.clone(),
                    offset: 0,
                },
            );
        }
        for range in &relation.ranges {
            if relation.range_segment_with_segs(range, &col_segs, &weight_segs) != seg {
                continue;
            }
            let log_len = relation.columns[range.column.0 as usize].log_len;
            add(
                Target::Range(range.width.bits),
                Member {
                    m: log_len,
                    block_bits: 0,
                    block_index: 0,
                    tuple: vec![(Ref::identity(range.column, log_len), -range.width.min())],
                    selector: None,
                    offset: 0,
                },
            );
        }
        let checks = build_a8_checks(
            targets,
            relation,
            Sources::CircleRecursive,
            instance_bound,
            source_base,
            source_base + 3,
            Some((1 << 16) - 3),
        )?;
        let mu_stack = if checks.is_empty() {
            None
        } else {
            let mut mu_order: Vec<usize> = (0..checks.len()).collect();
            mu_order.sort_by(|a, b| checks[*b].k.cmp(&checks[*a].k));
            let mut offsets = vec![0usize; checks.len()];
            let mut mu_total = 0usize;
            for idx in mu_order {
                let sz = 1usize
                    .checked_shl(u32::from(checks[idx].k))
                    .ok_or(Error::Unsupported)?;
                offsets[idx] = mu_total;
                mu_total = mu_total.checked_add(sz).ok_or(Error::Unsupported)?;
            }
            let bits = ceil_log2(mu_total).max(2);
            if bits > 30 {
                return Err(Error::Unsupported);
            }
            let plan = select_fresh_level0(bits)?;
            max_l0_m = max_l0_m.max(plan.levels()[0].m);
            max_blocks = max_blocks.checked_add(1).ok_or(Error::Unsupported)?;
            Some(MuStackPlan {
                id: source_base + 3,
                bits,
                plan,
                offsets,
            })
        };

        let mut sizes: Vec<u8> = relation
            .identities
            .iter()
            .filter(|i| relation.identity_segment_with(i, &col_segs) == seg)
            .map(|i| i.vars)
            .collect();
        sizes.extend(
            relation
                .composes
                .iter()
                .filter(|c| relation.compose_segment_with(c, &col_segs) == seg)
                .map(|c| relation.columns[c.column.0 as usize].log_len),
        );
        sizes.sort_unstable();
        sizes.dedup();
        let matmuls: Vec<usize> = relation
            .matmuls
            .iter()
            .enumerate()
            .filter(|(_, mm)| relation.matmul_segment_with(mm, &col_segs) == seg)
            .map(|(idx, _)| idx)
            .collect();
        let virtuals: Vec<ColumnId> = (0..relation.columns.len())
            .rev()
            .filter(|&idx| {
                matches!(relation.columns[idx].kind, Kind::Virtual(_)) && col_segs[idx] == Some(seg)
            })
            .map(|idx| ColumnId(idx as u32))
            .collect();
        segments.push(RecursiveSegmentPlan {
            segment: seg,
            groups,
            witness_bits,
            witness_plan,
            checks,
            mu_stack,
            sizes,
            matmuls,
            virtuals,
        });
    }

    let tail_levels = select_tail_levels(max_l0_m, max_blocks)?;
    Ok(RecursiveEnginePlan {
        digest: digest(relation),
        segments,
        weights,
        model,
        tail_levels,
    })
}

fn absorb_recursive_model(
    t: &mut Transcript<K>,
    sources: &[(&CertifiedSource<K>, [u8; 32])],
) -> Result<(), Error> {
    let mut payload = Vec::new();
    for (source, cert_id) in sources {
        payload.extend_from_slice(&source.bytes()?);
        payload.extend_from_slice(cert_id);
    }
    t.absorb(AbsorbLabel::RelationRoots, &payload)?;
    Ok(())
}

fn recursive_group_claims(groups: &[Group], stack_bits: u8, claims: &Claims) -> Vec<(Vec<K>, K)> {
    let mut out = Vec::new();
    for group in groups {
        for (j, column) in group.columns.iter().enumerate() {
            let index = (group.offset >> group.n) + j;
            for (point, value) in &claims.0[column.0 as usize] {
                out.push((bits_point(index, stack_bits - group.n, point), *value));
            }
        }
    }
    out
}

fn recursive_weight_claims(
    weights: &[Weight],
    model: &[RecursiveModelLayout],
    k: usize,
    claims: &Claims,
) -> Vec<(Vec<K>, K)> {
    let bits = model[k].bits;
    let mut out = Vec::new();
    for w in weights.iter().filter(|w| w.source == k) {
        let index = w.offset >> w.n;
        for (point, value) in &claims.0[w.column.0 as usize] {
            out.push((bits_point(index, bits - w.n, point), *value));
        }
    }
    out
}

/// Build the `prefix_mask` sumcheck instance `sum_{x in {0,1}^k} eq_prefix(z, t, x) * mu(x) = claim`.
fn prefix_mask_instance(check_id: u64, k: u8, claimed: K) -> Instance<K> {
    Instance {
        id: PREFIX_MASK_ID | check_id,
        num_vars: u32::from(k),
        inputs: vec![0, 1],
        terms: vec![Term {
            coefficient: K::from_i64(1),
            factors: vec![0, 1],
        }],
        claimed_sum: claimed,
    }
}

/// Prove one fresh source opening: RFC-0006 A2 mode-1 `claim_batch` followed by
/// `PreparedRecursive::close_fresh_level0_at_point`, consuming `prepared` by value so its
/// matrix and codeword leave memory immediately (RFC-0029 §2).
#[allow(clippy::too_many_arguments)]
fn prove_fresh_close(
    t: &mut Transcript<K>,
    batch_id: u64,
    opening_id: u64,
    tensor_id: u64,
    bits: u8,
    l1_spec: LevelSpec,
    batch_claims: &[(Vec<K>, K)],
    prepared: PreparedRecursive<K>,
) -> Result<(Vec<u8>, PendingLevel1Prover<K>), Error> {
    let batch = claim_batch::Batch {
        id: batch_id,
        tensor: tensor_id,
        num_vars: u32::from(bits),
        claims: batch_claims,
    };
    let (bp, r_star) = batch.prove_base_with_point(prepared.message(), t)?;
    let v_star = bp.final_values[0];
    let mut out = Vec::new();
    for row in &bp.rounds {
        put(&mut out, row);
    }
    put(&mut out, &bp.final_values);
    let (l0_bytes, pending) =
        prepared.close_fresh_level0_at_point(t, opening_id, l1_spec, &r_star, v_star)?;
    out.extend_from_slice(&l0_bytes);
    Ok((out, pending))
}

/// Verify one fresh source opening (`claim_batch` + `verify_fresh_level0_at_point`).
#[allow(clippy::too_many_arguments)]
fn verify_fresh_close(
    t: &mut Transcript<K>,
    batch_id: u64,
    opening_id: u64,
    source: &RecursiveSource<K>,
    bits: u8,
    l1_spec: LevelSpec,
    batch_claims: &[(Vec<K>, K)],
    reader: &mut Reader<'_>,
    ledger: &mut Ledger,
    name: &str,
) -> Result<PendingLevel1Verifier<K>, Error> {
    let batch = claim_batch::Batch {
        id: batch_id,
        tensor: source.id(),
        num_vars: u32::from(bits),
        claims: batch_claims,
    };
    let mut rounds = Vec::with_capacity(usize::from(bits));
    for _ in 0..bits {
        rounds.push(reader.ks(3)?);
    }
    let bp = stele_sumcheck::Proof {
        rounds,
        final_values: reader.ks(1)?,
    };
    let reduction = batch.verify(&bp, t)?;
    ledger.add(
        Line::Rlc,
        name,
        reduction.rlc.numerator,
        reduction.rlc.numerator,
    );
    ledger.add(
        Line::Sc,
        name,
        reduction.sc.numerator,
        u64::from(reduction.sc.degree),
    );
    let claim = &reduction.claims[0];
    let l0_size = fresh_level0_proof_size(source.plan(), l1_spec)?;
    let l0_bytes = reader.take(l0_size)?;
    let pending = verify_fresh_level0_at_point(
        t,
        source,
        opening_id,
        l1_spec,
        &claim.point,
        claim.value,
        l0_bytes,
    )?;
    ledger.recursive_level(name, &pending.level0_ledger(), true);
    Ok(pending)
}

/// Produce an RFC-0026 A29 / RFC-0029 development proof (`stele-dev-e2e-v2`) where all
/// segments, stacked multiplicity sources, and certified model sources join ONE recursion.
/// A caller that keeps its `Values`, to run the plain check beside this, lends them.
pub fn prove_recursive_measured<F, V>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[RecursiveModelSource<'_>],
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<V, Error>,
    V: Borrow<Values>,
{
    prove_recursive_with_bound(t, relation, segment_values, model, DEFAULT_INSTANCE_BOUND)
}

/// [`prove_recursive_measured`] under plan bound `B = instance_bound`. Only the engine's
/// tests pass another bound than the profile's (ADR-155).
fn prove_recursive_with_bound<F, V>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[RecursiveModelSource<'_>],
    instance_bound: u8,
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<V, Error>,
    V: Borrow<Values>,
{
    let plan_timer = Stopwatch::start();
    let plan = plan_recursive_with_bound(relation, instance_bound)?;
    let plan_ns = plan_timer.elapsed_ns();
    prove_recursive_with_plan(t, relation, plan, plan_ns, segment_values, model)
}

/// [`prove_recursive_measured`] as a malicious prover (controls only): the plan and the
/// absorbed relation digest are `relation`'s, and the prover reads the public selector
/// column of `forge.deselect` with that selected entry cleared, so the position is left
/// out of its lookup tree and of its selected product (control NC-1344). The joined
/// recursion supports no other field of `forge`.
#[cfg(feature = "controls")]
pub fn prove_recursive_forged<F, V>(
    t: &mut Transcript<K>,
    relation: &Relation,
    segment_values: F,
    model: &[RecursiveModelSource<'_>],
    forge: &Forge,
) -> Result<ProofV2, Error>
where
    F: FnMut(u32) -> Result<V, Error>,
    V: Borrow<Values>,
{
    if forge.table.is_some()
        || forge.public.is_some()
        || forge.witness.is_some()
        || forge.column_claim.is_some()
    {
        return Err(Error::Unsupported);
    }
    let plan = plan_recursive_with_bound(relation, DEFAULT_INSTANCE_BOUND)?;
    let read = deselected(relation, forge.deselect)?;
    prove_recursive_with_plan(t, &read, plan, 0, segment_values, model).map(|(proof, _)| proof)
}

/// The prover of [`prove_recursive_measured`] over a plan made beforehand. `relation` is
/// the relation the prover reads its public columns from: the plan's own, except under
/// the forging prover of the controls.
fn prove_recursive_with_plan<F, V>(
    t: &mut Transcript<K>,
    relation: &Relation,
    plan: RecursiveEnginePlan,
    plan_ns: u64,
    mut segment_values: F,
    model: &[RecursiveModelSource<'_>],
) -> Result<(ProofV2, Metrics), Error>
where
    F: FnMut(u32) -> Result<V, Error>,
    V: Borrow<Values>,
{
    if model.len() != plan.model.len() {
        return Err(Error::Weights);
    }
    for (src, layout) in model.iter().zip(&plan.model) {
        if src.prepared.source().id() != layout.id || src.prepared.source().plan() != &layout.plan {
            return Err(Error::Weights);
        }
    }

    let l1_spec = plan.tail_levels[0];
    let mut metrics = Metrics {
        plan_ns,
        committed_cells: relation
            .columns
            .iter()
            .filter(|c| matches!(c.kind, Kind::Witness(_)))
            .map(|c| 1u64 << c.log_len)
            .sum(),
        stacked_source_cells_padded: plan
            .segments
            .iter()
            .filter_map(|seg| seg.witness_plan.as_ref().map(|_| 1u64 << seg.witness_bits))
            .sum(),
        ..Metrics::default()
    };
    // One counter per check of a segment: the instances of a split check (A8), which
    // follow one another, are summed under its name.
    for check in plan.segments.iter().flat_map(|seg| &seg.checks) {
        let positions: u64 = check.members.iter().map(|m| 1u64 << m.m).sum();
        match (check.instance, metrics.lookup_checks.last_mut()) {
            (Some(j), Some((_, total))) if j > 0 => *total = total.saturating_add(positions),
            (Some(_), _) => {
                let name = check.name.strip_suffix("/inst0").unwrap_or(&check.name);
                metrics.lookup_checks.push((name.into(), positions));
            }
            (None, _) => metrics.lookup_checks.push((check.name.clone(), positions)),
        }
    }
    metrics.lookup_positions = metrics.lookup_checks.iter().map(|(_, p)| *p).sum();

    let mut weight_index = vec![None; relation.columns.len()];
    for (i, w) in plan.weights.iter().enumerate() {
        weight_index[w.column.0 as usize] = Some(i);
    }
    let mut col_reads = vec![0u64; plan.weights.len()];

    // Step 1: bind relation digest and certified model roots.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    let model_meta: Vec<(&CertifiedSource<K>, [u8; 32])> = model
        .iter()
        .map(|m| (m.prepared.source(), m.prepared.certificate_id()))
        .collect();
    absorb_recursive_model(t, &model_meta)?;

    let mut proof = ProofV2 {
        segments: (0..plan.segments.len())
            .map(|_| SegmentProof::default())
            .collect(),
        model_openings: Vec::new(),
    };
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);
    let mut prev: Option<(usize, PreparedRecursive<K>)> = None;
    let mut pending_l1: Vec<PendingLevel1Prover<K>> = Vec::new();

    for (s, seg) in plan.segments.iter().enumerate() {
        let owner = segment_values(seg.segment)?;
        let values: &Values = owner.borrow();
        let resolved = ResolvedColumns::for_segment(relation, values, &seg.virtuals, None)?;

        // Steps 2.1 & 2.2: commit segment witness stack (fresh mode) and count multiplicities in parallel.
        let witness_commit = || -> (Result<Option<PreparedRecursive<K>>, Error>, u64) {
            let timer = Stopwatch::start();
            let res = seg
                .witness_plan
                .as_ref()
                .map(|(source_id, rec_plan)| {
                    let mut msg = vec![M31::from_i64(0); 1usize << seg.witness_bits];
                    for group in &seg.groups {
                        for (j, id) in group.columns.iter().enumerate() {
                            let col = column(relation, values, *id)?;
                            let start = group.offset + (j << group.n);
                            for (out, v) in msg[start..].iter_mut().zip(col.iter()) {
                                *out = M31::from_i64(v);
                            }
                        }
                    }
                    Ok(PreparedRecursive::<K>::commit(
                        *source_id,
                        rec_plan.clone(),
                        msg,
                    )?)
                })
                .transpose();
            (res, timer.elapsed_ns())
        };
        let count_all = || -> (Result<Vec<Vec<i64>>, Error>, u64) {
            let timer = Stopwatch::start();
            let res = parallel::map(seg.checks.len(), |i| {
                lookup::counts(&seg.checks[i], relation, &resolved)
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>();
            (res, timer.elapsed_ns())
        };
        let ((curr_res, commit_ns), (counts_res, count_ns)) =
            parallel::join(witness_commit, count_all);
        metrics.commitment_ns = metrics.commitment_ns.saturating_add(commit_ns);
        let curr = curr_res?.map(|p| (s, p));
        let counts = counts_res?;

        if let Some((_, ref prepared)) = curr {
            let root = prepared.source().root();
            t.absorb(AbsorbLabel::RelationRoots, &root)?;
            proof.segments[s].groups.push(root.to_vec());
        }

        // Commit stacked multiplicity source for segment `s` (fresh mode, root only).
        let mu_timer = Stopwatch::start();
        let mu_prepared = if let Some(ref mu_plan) = seg.mu_stack {
            let mut mu_msg = vec![M31::from_i64(0); 1usize << mu_plan.bits];
            for (j, check) in seg.checks.iter().enumerate() {
                let start = mu_plan.offsets[j];
                let len = 1usize << check.k;
                for (dst, &cnt) in mu_msg[start..start + len].iter_mut().zip(&counts[j]) {
                    *dst = M31::from_i64(cnt);
                }
            }
            let prepared =
                PreparedRecursive::<K>::commit(mu_plan.id, mu_plan.plan.clone(), mu_msg)?;
            let root = prepared.source().root();
            t.absorb(AbsorbLabel::RelationRoots, &root)?;
            proof.segments[s].multiplicities.push(root.to_vec());
            Some(prepared)
        } else {
            None
        };
        metrics.multiplicities_ns = metrics
            .multiplicities_ns
            .saturating_add(count_ns.saturating_add(mu_timer.elapsed_ns()));

        // Count weight reads for multiplicity counting.
        for check in &seg.checks {
            let member_selected = |member: &Member| -> u64 {
                // A cut member's selector is read at its block (A8).
                let block = (member.block_index as u64) << member.m;
                match &member.selector {
                    None => 1u64 << member.m,
                    Some(r) => match &relation.columns[r.column.0 as usize].kind {
                        Kind::Public(v) => (0..1u64 << member.m)
                            .filter(|&x| v[r.index(block | x)] != 0)
                            .count() as u64,
                        _ => 0,
                    },
                }
            };
            for member in &check.members {
                let mut selected: Option<u64> = None;
                for (r, _) in &member.tuple {
                    if let Some(w_idx) = weight_index[r.column.0 as usize] {
                        let count = *selected.get_or_insert_with(|| member_selected(member));
                        col_reads[w_idx] = col_reads[w_idx].saturating_add(count);
                    }
                }
            }
        }

        // Step 2.3 (a): zerochecks (base-field first round).
        let zc_timer = Stopwatch::start();
        let seg_zc_base = ZEROCHECK | (u64::from(seg.segment) << 16);
        for &m in &seg.sizes {
            let lambdas = identity_lambdas_for(t, relation, Some(seg.segment), m)?;
            let (inputs, instance) = combine_for(
                relation,
                Some(seg.segment),
                m,
                seg_zc_base | u64::from(m),
                &lambdas,
            );
            let zc_reads = 1u64 << m;
            for r in &inputs {
                if let Some(w_idx) = weight_index[r.column.0 as usize] {
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(zc_reads);
                }
            }
            let mut tables = Vec::with_capacity(inputs.len());
            for r in &inputs {
                let col = resolved.get(r.column)?;
                let at = stele_ir::relation::Indexer::new(r, 1 << m);
                let mut table = vec![M31::from_i64(0); 1 << m];
                parallel::for_each_chunk(&mut table, |start, chunk| {
                    for (j, out) in chunk.iter_mut().enumerate() {
                        *out = M31::from_i64(col.at(at.index((start + j) as u64)));
                    }
                });
                tables.push(table);
            }
            let z = zerocheck::Zerocheck {
                instance: &instance,
                skip: 0,
            };
            let (zp, point) = z.prove_base_with_point(&tables, t)?;
            let mut out = Vec::new();
            for row in &zp.rounds {
                put(&mut out, row);
            }
            put(&mut out, &zp.final_values);
            for (r, value) in inputs.iter().zip(&zp.final_values) {
                claims.push(r, &point, *value);
            }
            proof.segments[s].identities.push(out);
        }
        metrics.zerochecks_ns = metrics.zerochecks_ns.saturating_add(zc_timer.elapsed_ns());

        // Step 2.3 (b): lookups + Q51 prefix-mask reduction + immediate close/drop of `mu_stack`.
        let lu_timer = Stopwatch::start();
        if let (Some(mu_plan), Some(mu_prep)) = (&seg.mu_stack, mu_prepared) {
            let mu_binding = mu_prep.source().bytes()?;
            let mut mu_claims: Vec<(Vec<K>, K)> = Vec::with_capacity(seg.checks.len());
            for (j, (check, cnt)) in seg.checks.iter().zip(&counts).enumerate() {
                for member in &check.members {
                    for (r, _) in &member.tuple {
                        if let Some(w_idx) = weight_index[r.column.0 as usize] {
                            col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << member.m);
                        }
                    }
                }
                let mut out = Vec::new();
                let (table_point, table_claim) = lookup::prove_for_stack(
                    t,
                    check,
                    relation,
                    &resolved,
                    cnt,
                    &mu_binding,
                    &mut out,
                    &mut claims,
                )?;
                let full_len = 1usize << check.k;
                let (mu_pt, mu_val) = if check.t == full_len {
                    (table_point, table_claim)
                } else {
                    // RFC-0026 A29 (Q51): reduce prefix-mask functional to one point claim via sumcheck.
                    let mut eq_pref = parallel::eq_table(&table_point)?;
                    for slot in &mut eq_pref[check.t..] {
                        *slot = K::from_i64(0);
                    }
                    let mu_slice: Vec<M31> = cnt.iter().map(|&c| M31::from_i64(c)).collect();
                    let inst = prefix_mask_instance(check.id, check.k, table_claim);
                    let dense = Dense::new_mixed(
                        &inst,
                        vec![DenseTable::Ext(eq_pref), DenseTable::Base(mu_slice)],
                    )?;
                    let mut sc = Vec::new();
                    let sp = stele_sumcheck::prove(
                        &inst,
                        Capture {
                            inner: dense,
                            point: &mut sc,
                        },
                        t,
                    )?;
                    for row in &sp.rounds {
                        put(&mut out, row);
                    }
                    put(&mut out, &sp.final_values);
                    (sc, sp.final_values[1])
                };
                let block_idx = mu_plan.offsets[j] >> check.k;
                mu_claims.push((
                    bits_point(block_idx, mu_plan.bits - check.k, &mu_pt),
                    mu_val,
                ));
                proof.segments[s].lookups.push(out);
            }
            drop(counts);
            let (mu_open_bytes, mu_pending) = prove_fresh_close(
                t,
                MU_BATCH_ID | (u64::from(seg.segment) << 32),
                MU_OPENING_ID | (u64::from(seg.segment) << 32),
                mu_plan.id,
                mu_plan.bits,
                l1_spec,
                &mu_claims,
                mu_prep,
            )?;
            proof.segments[s].multiplicities.push(mu_open_bytes);
            pending_l1.push(mu_pending);
        }
        metrics.lookups_ns = metrics.lookups_ns.saturating_add(lu_timer.elapsed_ns());

        // Step 2.3 (c): explicit matmuls.
        let mm_timer = Stopwatch::start();
        for &mm_idx in &seg.matmuls {
            let mm = &relation.matmuls[mm_idx];
            if let Some(w_idx) = weight_index[mm.out.column.0 as usize] {
                col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << plan.weights[w_idx].n);
            }
            for r in [&mm.lhs, &mm.rhs] {
                if let Some(w_idx) = weight_index[r.column.0 as usize] {
                    let fixed_bits =
                        r.vars.iter().filter(|d| Ref::fixed(**d).is_some()).count() as u32;
                    let elems = (1u64 << plan.weights[w_idx].n) >> fixed_bits;
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(elems);
                }
            }
            let shape = MatmulShape::new(t, mm)?;
            let out_col = resolved.get(mm.out.column)?;
            let out_value = mle(out_col, &restrict(&mm.out, &shape.rho))?;
            let instance = shape.instance(MATMUL | mm_idx as u64, out_value);
            let eq = shape.eq_shared()?;
            let lhs = shape.table_mixed(&mm.lhs, resolved.get(mm.lhs.column)?)?;
            let rhs = shape.table_mixed(&mm.rhs, resolved.get(mm.rhs.column)?)?;
            let mut sc = Vec::new();
            let summand = MatmulSummand {
                rem: 1usize << shape.vars.len(),
                eq,
                lhs,
                rhs,
                point: &mut sc,
            };
            let sp = stele_sumcheck::prove(&instance, summand, t)?;
            let mut out = Vec::new();
            put(&mut out, &[out_value]);
            for row in &sp.rounds {
                put(&mut out, row);
            }
            put(&mut out, &sp.final_values);
            shape.route(mm, &sc, &sp.final_values, out_value, &mut claims);
            proof.segments[s].matmuls.push(out);
        }
        metrics.reductions_ns = metrics.reductions_ns.saturating_add(mm_timer.elapsed_ns());

        // Step 2.4: virtual column reductions in strictly decreasing ColumnId order.
        let v_timer = Stopwatch::start();
        for &col_id in &seg.virtuals {
            let col_claims = core::mem::take(&mut claims.0[col_id.0 as usize]);
            if col_claims.is_empty() {
                continue;
            }
            let col = &relation.columns[col_id.0 as usize];
            match &col.kind {
                Kind::Virtual(Def::Linear { terms, .. }) => {
                    let mut out = Vec::with_capacity(col_claims.len() * terms.len() * 16);
                    for (claim_idx, (z, _)) in col_claims.iter().enumerate() {
                        let mut eq_z: Option<Vec<K>> = None;
                        let mut evals = Vec::with_capacity(terms.len());
                        let mut op_points = Vec::with_capacity(terms.len());
                        for (_, r) in terms {
                            if let Some(w_idx) = weight_index[r.column.0 as usize] {
                                col_reads[w_idx] =
                                    col_reads[w_idx].saturating_add(1u64 << plan.weights[w_idx].n);
                            }
                            let op_data = resolved.get(r.column)?;
                            let op_point = restrict(r, z);
                            let eval = if op_point == *z {
                                let eq = match &eq_z {
                                    Some(table) => table,
                                    None => eq_z.insert(parallel::eq_table(z)?),
                                };
                                mle_dot(op_data, eq)?
                            } else {
                                mle_parallel(op_data, &op_point)?
                            };
                            evals.push(eval);
                            op_points.push(op_point);
                        }
                        put(&mut out, &evals);
                        absorb_linear_evals(t, col_id, claim_idx, &evals)?;
                        for (((_, r), op_point), eval) in terms.iter().zip(op_points).zip(evals) {
                            claims.0[r.column.0 as usize].push((op_point, eval));
                        }
                    }
                    proof.segments[s].reductions.push(out);
                }
                Kind::Virtual(Def::Contraction {
                    free,
                    summed,
                    lhs,
                    rhs,
                }) => {
                    let mut out = Vec::new();
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let col_slice = resolved.get(col_id)?;
                        let mut table = vec![M31::from_i64(0); col_slice.len()];
                        parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, slot) in chunk.iter_mut().enumerate() {
                                *slot = M31::from_i64(col_slice.at(start + j));
                            }
                        });
                        let (bp, point) = batch.prove_base_with_point(&table, t)?;
                        for row in &bp.rounds {
                            put(&mut out, row);
                        }
                        put(&mut out, &bp.final_values);
                        (point, bp.final_values[0])
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    for r in [lhs, rhs] {
                        if let Some(w_idx) = weight_index[r.column.0 as usize] {
                            let fixed_bits =
                                r.vars.iter().filter(|d| Ref::fixed(**d).is_some()).count() as u32;
                            let elems = (1u64 << plan.weights[w_idx].n) >> fixed_bits;
                            col_reads[w_idx] = col_reads[w_idx].saturating_add(elems);
                        }
                    }
                    let shape = MatmulShape::from_point(z, *free, *summed, lhs, rhs);
                    let instance =
                        shape.instance(VIRTUAL_CONTRACTION | u64::from(col_id.0), claimed_val);
                    let eq = shape.eq_shared()?;
                    let lhs_tbl = shape.table_mixed(lhs, resolved.get(lhs.column)?)?;
                    let rhs_tbl = shape.table_mixed(rhs, resolved.get(rhs.column)?)?;
                    metrics.contractions_reduced = metrics.contractions_reduced.saturating_add(1);
                    metrics.contraction_partial_evals =
                        metrics.contraction_partial_evals.saturating_add(2);
                    let mut sc = Vec::new();
                    let summand = MatmulSummand {
                        rem: 1usize << shape.vars.len(),
                        eq,
                        lhs: lhs_tbl,
                        rhs: rhs_tbl,
                        point: &mut sc,
                    };
                    let sp = stele_sumcheck::prove(&instance, summand, t)?;
                    for row in &sp.rounds {
                        put(&mut out, row);
                    }
                    put(&mut out, &sp.final_values);
                    shape.route_operands(lhs, rhs, *free, &sc, &sp.final_values, &mut claims);
                    proof.segments[s].reductions.push(out);
                }
                Kind::Virtual(Def::Pointwise { terms }) => {
                    let mut out = Vec::new();
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let col_slice = resolved.get(col_id)?;
                        let mut table = vec![M31::from_i64(0); col_slice.len()];
                        parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, slot) in chunk.iter_mut().enumerate() {
                                *slot = M31::from_i64(col_slice.at(start + j));
                            }
                        });
                        let (bp, point) = batch.prove_base_with_point(&table, t)?;
                        for row in &bp.rounds {
                            put(&mut out, row);
                        }
                        put(&mut out, &bp.final_values);
                        (point, bp.final_values[0])
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    let (inputs, instance, _) =
                        pointwise_instance(col_id, col.log_len, terms, claimed_val);
                    let pw_reads = 1u64 << col.log_len;
                    for r in &inputs {
                        if let Some(w_idx) = weight_index[r.column.0 as usize] {
                            col_reads[w_idx] = col_reads[w_idx].saturating_add(pw_reads);
                        }
                    }
                    let mut tables = Vec::with_capacity(1 + inputs.len());
                    tables.push(DenseTable::Ext(parallel::eq_table(&z)?));
                    for r in &inputs {
                        let data = resolved.get(r.column)?;
                        let at = stele_ir::relation::Indexer::new(r, 1usize << col.log_len);
                        let mut table = vec![M31::from_i64(0); 1usize << col.log_len];
                        parallel::for_each_chunk(&mut table, |start, chunk| {
                            for (j, slot) in chunk.iter_mut().enumerate() {
                                *slot = M31::from_i64(data.at(at.index((start + j) as u64)));
                            }
                        });
                        tables.push(DenseTable::Base(table));
                    }
                    let dense = Dense::new_mixed(&instance, tables)?;
                    let mut sc = Vec::new();
                    let sp = stele_sumcheck::prove(
                        &instance,
                        Capture {
                            inner: dense,
                            point: &mut sc,
                        },
                        t,
                    )?;
                    for row in &sp.rounds {
                        put(&mut out, row);
                    }
                    put(&mut out, &sp.final_values);
                    for (r, &val) in inputs.iter().zip(&sp.final_values[1..]) {
                        claims.push(r, &sc, val);
                    }
                    proof.segments[s].reductions.push(out);
                }
                _ => return Err(Error::Unsupported),
            }
        }
        metrics.reductions_ns = metrics.reductions_ns.saturating_add(v_timer.elapsed_ns());
        drop(resolved);
        drop(owner);

        // Step 2.5: close segment `s - 1` witness stack into `l1_spec` and drop it by value.
        let open_timer = Stopwatch::start();
        if let Some((prev_s, prev_prep)) = prev.take() {
            let prev_seg = &plan.segments[prev_s];
            if let Some((source_id, _)) = &prev_seg.witness_plan {
                let batch =
                    recursive_group_claims(&prev_seg.groups, prev_seg.witness_bits, &claims);
                if !batch.is_empty() {
                    let (bytes, pending) = prove_fresh_close(
                        t,
                        BATCH | ((prev_s as u64) << 32),
                        WITNESS_OPENING_ID | ((prev_s as u64) << 32),
                        *source_id,
                        prev_seg.witness_bits,
                        l1_spec,
                        &batch,
                        prev_prep,
                    )?;
                    proof.segments[prev_s].openings.push(bytes);
                    pending_l1.push(pending);
                }
            }
        }
        metrics.openings_ns = metrics.openings_ns.saturating_add(open_timer.elapsed_ns());
        prev = curr;
    }

    // Step 3: close the last segment witness stack, close opened certified model sources,
    // and run ONE joined tail recursion over all pending level-1 sources.
    let open_timer = Stopwatch::start();
    if let Some((last_s, last_prep)) = prev.take() {
        let last_seg = &plan.segments[last_s];
        if let Some((source_id, _)) = &last_seg.witness_plan {
            let batch = recursive_group_claims(&last_seg.groups, last_seg.witness_bits, &claims);
            if !batch.is_empty() {
                let (bytes, pending) = prove_fresh_close(
                    t,
                    BATCH | ((last_s as u64) << 32),
                    WITNESS_OPENING_ID | ((last_s as u64) << 32),
                    *source_id,
                    last_seg.witness_bits,
                    l1_spec,
                    &batch,
                    last_prep,
                )?;
                proof.segments[last_s].openings.push(bytes);
                pending_l1.push(pending);
            }
        }
    }
    for (k, src) in model.iter().enumerate() {
        let batch_claims = recursive_weight_claims(&plan.weights, &plan.model, k, &claims);
        if !batch_claims.is_empty() {
            for (w_idx, w) in plan.weights.iter().enumerate() {
                if w.source == k {
                    col_reads[w_idx] = col_reads[w_idx].saturating_add(1u64 << w.n);
                }
            }
            let layout = &plan.model[k];
            let batch = claim_batch::Batch {
                id: BATCH | (1 + k as u64),
                tensor: layout.id,
                num_vars: u32::from(layout.bits),
                claims: &batch_claims,
            };
            let (bp, r_star) = batch.prove_base_with_point(&src.message, t)?;
            let v_star = bp.final_values[0];
            let l0 = layout.plan.levels()[0];
            let ell0 = usize::from(l0.ell);
            let row_weights = parallel::eq_table(&r_star[..ell0])?;
            let (l0_bytes, pending, _work) = src.prepared.close_certified_level0(
                &src.message,
                t,
                MODEL_OPENING_ID | (k as u64),
                l1_spec,
                &row_weights,
                ColumnFunctional::Tensor(&r_star[ell0..]),
                v_star,
            )?;
            let mut out = Vec::new();
            for row in &bp.rounds {
                put(&mut out, row);
            }
            put(&mut out, &bp.final_values);
            out.extend_from_slice(&l0_bytes);
            proof.model_openings.push(out);
            pending_l1.push(pending);
        }
    }
    if !pending_l1.is_empty() {
        let tail_plan = JoinedTailPlan::new(
            plan.tail_levels.clone(),
            pending_l1.len() as u16,
            EXT_DEGREE,
            TARGET_BITS,
        )?;
        let tail_bytes = prove_joined_tail(t, JOINED_TAIL_ID, &tail_plan, &pending_l1)?;
        proof.model_openings.push(tail_bytes);
    }
    metrics.openings_ns = metrics.openings_ns.saturating_add(open_timer.elapsed_ns());

    metrics.weight_elements_read = col_reads.iter().copied().sum();
    metrics.weight_reads = plan
        .weights
        .iter()
        .zip(&col_reads)
        .map(|(w, &reads)| {
            let size = 1u64 << w.n;
            reads.div_ceil(size)
        })
        .max()
        .unwrap_or(0);
    metrics.groups_bytes = proof
        .segments
        .iter()
        .flat_map(|s| s.groups.iter())
        .map(|b| b.len() as u64)
        .sum();
    metrics.multiplicities_bytes = proof
        .segments
        .iter()
        .flat_map(|s| s.multiplicities.iter())
        .map(|b| b.len() as u64)
        .sum();
    metrics.identities_bytes = proof
        .segments
        .iter()
        .flat_map(|s| s.identities.iter())
        .map(|b| b.len() as u64)
        .sum();
    metrics.lookups_bytes = proof
        .segments
        .iter()
        .flat_map(|s| s.lookups.iter())
        .map(|b| b.len() as u64)
        .sum();
    metrics.matmuls_bytes = proof
        .segments
        .iter()
        .flat_map(|s| s.matmuls.iter().chain(s.reductions.iter()))
        .map(|b| b.len() as u64)
        .sum();
    metrics.openings_bytes = proof
        .segments
        .iter()
        .flat_map(|s| s.openings.iter())
        .chain(proof.model_openings.iter())
        .map(|b| b.len() as u64)
        .sum();

    Ok((proof, metrics))
}

/// Verify an RFC-0026 A29 / RFC-0029 development proof (`stele-dev-e2e-v2`) and return its ledger.
pub fn verify_recursive(
    t: &mut Transcript<K>,
    relation: &Relation,
    model: &[VerifiedCertifiedSource<K>],
    proof: &ProofV2,
) -> Result<Ledger, Error> {
    verify_recursive_with_bound(t, relation, model, proof, DEFAULT_INSTANCE_BOUND)
}

/// [`verify_recursive`] under plan bound `B = instance_bound` (see
/// [`prove_recursive_with_bound`]).
fn verify_recursive_with_bound(
    t: &mut Transcript<K>,
    relation: &Relation,
    model: &[VerifiedCertifiedSource<K>],
    proof: &ProofV2,
    instance_bound: u8,
) -> Result<Ledger, Error> {
    let plan = plan_recursive_with_bound(relation, instance_bound)?;
    if model.len() != plan.model.len() {
        return Err(Error::Weights);
    }
    for (verified, layout) in model.iter().zip(&plan.model) {
        if verified.source().id() != layout.id || verified.source().plan() != &layout.plan {
            return Err(Error::Weights);
        }
    }
    if proof.segments.len() != plan.segments.len() {
        return Err(Error::ProofShape);
    }
    // A segment without a witness stack has no opening section (as RFC-0026 A27's verifier).
    if plan
        .segments
        .iter()
        .zip(&proof.segments)
        .any(|(seg, p)| seg.witness_plan.is_none() && !p.openings.is_empty())
    {
        return Err(Error::ProofShape);
    }

    let l1_spec = plan.tail_levels[0];
    let mut ledger = Ledger::default();
    for (k, verified) in model.iter().enumerate() {
        ledger.certified_registration(&alloc::format!("model {k}"), &verified.ledger());
    }
    let mut claims = Claims(vec![Vec::new(); relation.columns.len()]);

    // Step 1: bind relation digest and certified model roots.
    t.absorb(AbsorbLabel::RelationStatement, &plan.digest)?;
    let model_meta: Vec<(&CertifiedSource<K>, [u8; 32])> =
        model.iter().map(|m| (m.source(), m.id())).collect();
    absorb_recursive_model(t, &model_meta)?;

    let mut prev: Option<(usize, RecursiveSource<K>)> = None;
    let mut pending_l1: Vec<PendingLevel1Verifier<K>> = Vec::new();

    for (s, (seg, seg_proof)) in plan.segments.iter().zip(&proof.segments).enumerate() {
        // Step 2.1: fresh witness stack root (32 bytes only).
        let mut sections = Sections(seg_proof.groups.iter());
        let mut curr = None;
        if let Some((source_id, ref rec_plan)) = seg.witness_plan {
            let mut reader = sections.next()?;
            let root = reader.root()?;
            reader.end()?;
            t.absorb(AbsorbLabel::RelationRoots, &root)?;
            let src = RecursiveSource::<K>::new(source_id, rec_plan.clone(), root)?;
            curr = Some((s, src));
        }
        sections.end()?;

        // Step 2.2: fresh stacked multiplicity root (32 bytes), followed by opening section after lookups.
        let mut mu_sections = Sections(seg_proof.multiplicities.iter());
        let mu_source = if let Some(ref mu_plan) = seg.mu_stack {
            let mut reader = mu_sections.next()?;
            let root = reader.root()?;
            reader.end()?;
            t.absorb(AbsorbLabel::RelationRoots, &root)?;
            Some(RecursiveSource::<K>::new(
                mu_plan.id,
                mu_plan.plan.clone(),
                root,
            )?)
        } else {
            None
        };

        // Step 2.3 (a): zerochecks.
        let mut sections = Sections(seg_proof.identities.iter());
        let seg_zc_base = ZEROCHECK | (u64::from(seg.segment) << 16);
        for &m in &seg.sizes {
            let lambdas = identity_lambdas_for(t, relation, Some(seg.segment), m)?;
            let (inputs, instance) = combine_for(
                relation,
                Some(seg.segment),
                m,
                seg_zc_base | u64::from(m),
                &lambdas,
            );
            let mut reader = sections.next()?;
            let degree = instance
                .terms
                .iter()
                .map(|t| t.factors.len())
                .max()
                .unwrap_or(0);
            let mut rounds = Vec::new();
            for _ in 0..m {
                rounds.push(reader.ks(degree + 1)?);
            }
            let zp = zerocheck::Proof {
                skip_values: Vec::new(),
                rounds,
                final_values: reader.ks(inputs.len())?,
            };
            reader.end()?;
            let z = zerocheck::Zerocheck {
                instance: &instance,
                skip: 0,
            };
            let reduction = z.verify(&zp, t)?;
            let name = alloc::format!("s{s}/identities/{m}");
            // RFC-0012 A16: the lambda draw charges n; one SC entry per phase, as A27.
            let lambdas = lambdas.len() as u64;
            ledger.add(Line::Rlc, &name, lambdas, lambdas);
            let [weights, skip, tail] = reduction.sc;
            for (numerator, round) in [
                (weights.numerator, weights.numerator),
                (skip.numerator, skip.numerator),
                (tail.numerator, u64::from(tail.degree)),
            ] {
                if numerator > 0 {
                    ledger.add(Line::Sc, &name, numerator, round);
                }
            }
            for (r, claim) in inputs.iter().zip(reduction.claims) {
                claims.push(r, &claim.point, claim.value);
            }
        }
        sections.end()?;

        // Step 2.3 (b): lookups + Q51 prefix-mask reduction + stacked multiplicity level-0 verify.
        let mut sections = Sections(seg_proof.lookups.iter());
        if let (Some(ref mu_plan), Some(ref mu_src)) = (&seg.mu_stack, &mu_source) {
            let mu_binding = mu_src.bytes()?;
            let mut mu_claims: Vec<(Vec<K>, K)> = Vec::with_capacity(seg.checks.len());
            for (j, check) in seg.checks.iter().enumerate() {
                let mut reader = sections.next()?;
                let (table_point, table_claim) = lookup::verify_for_stack(
                    t,
                    check,
                    relation,
                    &mu_binding,
                    &mut reader,
                    &mut claims,
                    &mut ledger,
                )?;
                let full_len = 1usize << check.k;
                let (mu_pt, mu_val) = if check.t == full_len {
                    (table_point, table_claim)
                } else {
                    let inst = prefix_mask_instance(check.id, check.k, table_claim);
                    let mut rounds = Vec::with_capacity(usize::from(check.k));
                    for _ in 0..check.k {
                        rounds.push(reader.ks(3)?);
                    }
                    let sp = stele_sumcheck::Proof {
                        rounds,
                        final_values: reader.ks(2)?,
                    };
                    let reduction = stele_sumcheck::verify(&inst, &sp, t)?;
                    if sp.final_values[0] != eq_prefix_mle(&table_point, check.t, &reduction.point)
                    {
                        return Err(Error::EqMismatch);
                    }
                    ledger.add(
                        Line::Sc,
                        &alloc::format!("s{s}/{}/prefix", check.name),
                        reduction.sc.numerator,
                        u64::from(reduction.sc.degree),
                    );
                    (reduction.point, sp.final_values[1])
                };
                reader.end()?;
                let block_idx = mu_plan.offsets[j] >> check.k;
                mu_claims.push((
                    bits_point(block_idx, mu_plan.bits - check.k, &mu_pt),
                    mu_val,
                ));
            }
            let mut mu_open_reader = mu_sections.next()?;
            let mu_pending = verify_fresh_close(
                t,
                MU_BATCH_ID | (u64::from(seg.segment) << 32),
                MU_OPENING_ID | (u64::from(seg.segment) << 32),
                mu_src,
                mu_plan.bits,
                l1_spec,
                &mu_claims,
                &mut mu_open_reader,
                &mut ledger,
                &alloc::format!("s{s}/mu_stack"),
            )?;
            mu_open_reader.end()?;
            pending_l1.push(mu_pending);
        }
        sections.end()?;
        mu_sections.end()?;

        // Step 2.3 (c): explicit matmuls.
        let mut sections = Sections(seg_proof.matmuls.iter());
        for &mm_idx in &seg.matmuls {
            let mm = &relation.matmuls[mm_idx];
            let shape = MatmulShape::new(t, mm)?;
            let mut reader = sections.next()?;
            let out_value = reader.k()?;
            let instance = shape.instance(MATMUL | mm_idx as u64, out_value);
            let k = usize::from(!shape.shared.is_empty());
            let mut rounds = Vec::new();
            for _ in 0..shape.vars.len() {
                rounds.push(reader.ks(3 + k)?);
            }
            let sp = stele_sumcheck::Proof {
                rounds,
                final_values: reader.ks(2 + k)?,
            };
            reader.end()?;
            let reduction = stele_sumcheck::verify(&instance, &sp, t)?;
            if k == 1 && sp.final_values[0] != shape.eq_at(&reduction.point) {
                return Err(Error::EqMismatch);
            }
            ledger.add(Line::Sz, &mm.name, u64::from(mm.free), u64::from(mm.free));
            ledger.add(
                Line::Sc,
                &mm.name,
                reduction.sc.numerator,
                u64::from(reduction.sc.degree),
            );
            shape.route(
                mm,
                &reduction.point,
                &sp.final_values,
                out_value,
                &mut claims,
            );
        }
        sections.end()?;

        // Step 2.4: virtual column reductions in strictly decreasing ColumnId order.
        let mut sections = Sections(seg_proof.reductions.iter());
        for &col_id in &seg.virtuals {
            let col_claims = core::mem::take(&mut claims.0[col_id.0 as usize]);
            if col_claims.is_empty() {
                continue;
            }
            let col = &relation.columns[col_id.0 as usize];
            match &col.kind {
                Kind::Virtual(Def::Linear { constant, terms }) => {
                    let mut reader = sections.next()?;
                    for (claim_idx, (z, claimed_val)) in col_claims.iter().enumerate() {
                        let evals = reader.ks(terms.len())?;
                        let sum = terms
                            .iter()
                            .zip(&evals)
                            .fold(K::from_i64(*constant), |acc, ((c, _), v)| {
                                acc + K::from_i64(*c) * *v
                            });
                        if sum != *claimed_val {
                            return Err(Error::LinearMismatch(col_id));
                        }
                        absorb_linear_evals(t, col_id, claim_idx, &evals)?;
                        for ((_, r), eval) in terms.iter().zip(evals) {
                            claims.0[r.column.0 as usize].push((restrict(r, z), eval));
                        }
                    }
                    reader.end()?;
                }
                Kind::Virtual(Def::Contraction {
                    free,
                    summed,
                    lhs,
                    rhs,
                }) => {
                    let mut reader = sections.next()?;
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let mut rounds = Vec::with_capacity(usize::from(col.log_len));
                        for _ in 0..col.log_len {
                            rounds.push(reader.ks(3)?);
                        }
                        let bp = stele_sumcheck::Proof {
                            rounds,
                            final_values: reader.ks(1)?,
                        };
                        let reduction = batch.verify(&bp, t)?;
                        ledger.add(
                            Line::Rlc,
                            &col.name,
                            reduction.rlc.numerator,
                            reduction.rlc.numerator,
                        );
                        ledger.add(
                            Line::Sc,
                            &col.name,
                            reduction.sc.numerator,
                            u64::from(reduction.sc.degree),
                        );
                        let claim = &reduction.claims[0];
                        (claim.point.clone(), claim.value)
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    let shape = MatmulShape::from_point(z, *free, *summed, lhs, rhs);
                    let instance =
                        shape.instance(VIRTUAL_CONTRACTION | u64::from(col_id.0), claimed_val);
                    let k = usize::from(!shape.shared.is_empty());
                    let mut rounds = Vec::with_capacity(shape.vars.len());
                    for _ in 0..shape.vars.len() {
                        rounds.push(reader.ks(3 + k)?);
                    }
                    let sp = stele_sumcheck::Proof {
                        rounds,
                        final_values: reader.ks(2 + k)?,
                    };
                    reader.end()?;
                    let reduction = stele_sumcheck::verify(&instance, &sp, t)?;
                    if k == 1 && sp.final_values[0] != shape.eq_at(&reduction.point) {
                        return Err(Error::EqMismatch);
                    }
                    ledger.add(
                        Line::Sc,
                        &col.name,
                        reduction.sc.numerator,
                        u64::from(reduction.sc.degree),
                    );
                    shape.route_operands(
                        lhs,
                        rhs,
                        *free,
                        &reduction.point,
                        &sp.final_values,
                        &mut claims,
                    );
                }
                Kind::Virtual(Def::Pointwise { terms }) => {
                    let mut reader = sections.next()?;
                    let (z, claimed_val) = if col_claims.len() > 1 {
                        let batch = claim_batch::Batch {
                            id: VIRTUAL_BATCH | u64::from(col_id.0),
                            tensor: u64::from(col_id.0),
                            num_vars: u32::from(col.log_len),
                            claims: &col_claims,
                        };
                        let mut rounds = Vec::with_capacity(usize::from(col.log_len));
                        for _ in 0..col.log_len {
                            rounds.push(reader.ks(3)?);
                        }
                        let bp = stele_sumcheck::Proof {
                            rounds,
                            final_values: reader.ks(1)?,
                        };
                        let reduction = batch.verify(&bp, t)?;
                        ledger.add(
                            Line::Rlc,
                            &col.name,
                            reduction.rlc.numerator,
                            reduction.rlc.numerator,
                        );
                        ledger.add(
                            Line::Sc,
                            &col.name,
                            reduction.sc.numerator,
                            u64::from(reduction.sc.degree),
                        );
                        let claim = &reduction.claims[0];
                        (claim.point.clone(), claim.value)
                    } else {
                        col_claims.into_iter().next().ok_or(Error::ProofShape)?
                    };
                    let (inputs, instance, degree) =
                        pointwise_instance(col_id, col.log_len, terms, claimed_val);
                    let mut rounds = Vec::with_capacity(usize::from(col.log_len));
                    for _ in 0..col.log_len {
                        rounds.push(reader.ks(degree + 1)?);
                    }
                    let sp = stele_sumcheck::Proof {
                        rounds,
                        final_values: reader.ks(1 + inputs.len())?,
                    };
                    reader.end()?;
                    let reduction = stele_sumcheck::verify(&instance, &sp, t)?;
                    let expected_eq = stele_poly::eq_evaluate(&z, &reduction.point)
                        .map_err(|_| Error::Capacity)?;
                    if sp.final_values[0] != expected_eq {
                        return Err(Error::EqMismatch);
                    }
                    ledger.add(
                        Line::Sc,
                        &col.name,
                        reduction.sc.numerator,
                        u64::from(reduction.sc.degree),
                    );
                    for (r, &val) in inputs.iter().zip(&sp.final_values[1..]) {
                        claims.push(r, &reduction.point, val);
                    }
                }
                _ => return Err(Error::Unsupported),
            }
        }
        sections.end()?;

        // Step 2.5: verify segment `s - 1` witness stack level-0 close.
        if let Some((prev_s, prev_src)) = prev.take() {
            let prev_seg = &plan.segments[prev_s];
            let mut open_sections = Sections(proof.segments[prev_s].openings.iter());
            if prev_seg.witness_plan.is_some() {
                let batch =
                    recursive_group_claims(&prev_seg.groups, prev_seg.witness_bits, &claims);
                if !batch.is_empty() {
                    let mut reader = open_sections.next()?;
                    let pending = verify_fresh_close(
                        t,
                        BATCH | ((prev_s as u64) << 32),
                        WITNESS_OPENING_ID | ((prev_s as u64) << 32),
                        &prev_src,
                        prev_seg.witness_bits,
                        l1_spec,
                        &batch,
                        &mut reader,
                        &mut ledger,
                        &alloc::format!("s{prev_s}/stack"),
                    )?;
                    reader.end()?;
                    pending_l1.push(pending);
                }
            }
            open_sections.end()?;
        }
        prev = curr;
    }

    // Step 3: verify last segment witness stack, certified model level-0 closes, and joined tail.
    if let Some((last_s, last_src)) = prev.take() {
        let last_seg = &plan.segments[last_s];
        let mut open_sections = Sections(proof.segments[last_s].openings.iter());
        if last_seg.witness_plan.is_some() {
            let batch = recursive_group_claims(&last_seg.groups, last_seg.witness_bits, &claims);
            if !batch.is_empty() {
                let mut reader = open_sections.next()?;
                let pending = verify_fresh_close(
                    t,
                    BATCH | ((last_s as u64) << 32),
                    WITNESS_OPENING_ID | ((last_s as u64) << 32),
                    &last_src,
                    last_seg.witness_bits,
                    l1_spec,
                    &batch,
                    &mut reader,
                    &mut ledger,
                    &alloc::format!("s{last_s}/stack"),
                )?;
                reader.end()?;
                pending_l1.push(pending);
            }
        }
        open_sections.end()?;
    }

    let mut model_sections = Sections(proof.model_openings.iter());
    for (k, verified_model) in model.iter().enumerate() {
        let batch_claims = recursive_weight_claims(&plan.weights, &plan.model, k, &claims);
        if !batch_claims.is_empty() {
            let layout = &plan.model[k];
            let name = alloc::format!("model {k}");
            let mut reader = model_sections.next()?;
            let batch = claim_batch::Batch {
                id: BATCH | (1 + k as u64),
                tensor: layout.id,
                num_vars: u32::from(layout.bits),
                claims: &batch_claims,
            };
            let mut rounds = Vec::with_capacity(usize::from(layout.bits));
            for _ in 0..layout.bits {
                rounds.push(reader.ks(3)?);
            }
            let bp = stele_sumcheck::Proof {
                rounds,
                final_values: reader.ks(1)?,
            };
            let reduction = batch.verify(&bp, t)?;
            ledger.add(
                Line::Rlc,
                &name,
                reduction.rlc.numerator,
                reduction.rlc.numerator,
            );
            ledger.add(
                Line::Sc,
                &name,
                reduction.sc.numerator,
                u64::from(reduction.sc.degree),
            );
            let claim = &reduction.claims[0];
            let l0 = layout.plan.levels()[0];
            let ell0 = usize::from(l0.ell);
            let row_weights = parallel::eq_table(&claim.point[..ell0])?;
            let l0_size = stele_pcs::recursive::certified_level0_proof_size(&layout.plan, l1_spec)?;
            let l0_bytes = reader.take(l0_size)?;
            reader.end()?;
            let expected = CertifiedSource::new(
                layout.id,
                layout.plan.clone(),
                verified_model.source().root(),
            )?;
            let pending = verify_certified_level0(
                t,
                verified_model,
                &expected,
                MODEL_OPENING_ID | (k as u64),
                l1_spec,
                &row_weights,
                ColumnFunctional::Tensor(&claim.point[ell0..]),
                claim.value,
                l0_bytes,
            )?;
            ledger.recursive_level(&name, &pending.level0_ledger(), false);
            pending_l1.push(pending);
        }
    }

    if !pending_l1.is_empty() {
        let tail_plan = JoinedTailPlan::new(
            plan.tail_levels.clone(),
            pending_l1.len() as u16,
            EXT_DEGREE,
            TARGET_BITS,
        )?;
        let tail_reader = model_sections.next()?;
        let verified_tail =
            verify_joined_tail(t, JOINED_TAIL_ID, &tail_plan, &pending_l1, tail_reader.0)?;
        for lvl in &verified_tail.ledger().levels {
            ledger.recursive_level(&alloc::format!("joined/L{}", lvl.level), lvl, true);
        }
    }
    model_sections.end()?;
    ledger.pcs_sources = pending_l1.len();

    // Every virtual-column claim must have been discharged during its owning segment's Step 2.4.
    for (i, column) in relation.columns.iter().enumerate() {
        if matches!(column.kind, Kind::Virtual(_)) && !claims.0[i].is_empty() {
            return Err(Error::ProofShape);
        }
    }
    // Public-column claims, evaluated by the verifier.
    for (i, column) in relation.columns.iter().enumerate() {
        if let Kind::Public(values) = &column.kind {
            for (point, value) in &claims.0[i] {
                if mle(ColumnSlice::I64(values), point)? != *value {
                    return Err(Error::PublicMismatch(ColumnId(i as u32)));
                }
            }
        }
    }
    Ok(ledger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_ir::relation::{Identity, Lookup, Range, Table, Term as IdTerm, Width};
    use stele_pcs::recursive::RecursiveError;

    #[test]
    fn matches_reference_eq_prefix_mle_all_prefixes() {
        let mut t = Transcript::<K>::new(b"stele/test/eq-prefix-mle").expect("t");
        let mut point = |k: usize| -> Vec<K> {
            (0..k)
                .map(|_| t.challenge(ChallengeLabel::RelationPoint).expect("point"))
                .collect()
        };
        let reference = |z: &[K], prefix: usize, r: &[K]| {
            let eq_z = parallel::eq_table(z).expect("eq_z");
            let eq_r = parallel::eq_table(r).expect("eq_r");
            eq_z[..prefix]
                .iter()
                .zip(&eq_r[..prefix])
                .fold(K::from_i64(0), |acc, (&a, &b)| acc + a * b)
        };
        // Every prefix for small k.
        for k in 0..=6usize {
            let (z, r) = (point(k), point(k));
            for prefix in 0..=(1usize << k) {
                assert_eq!(
                    eq_prefix_mle(&z, prefix, &r),
                    reference(&z, prefix, &r),
                    "k={k} prefix={prefix}"
                );
            }
        }
        // 10^4 random (k, t, z, r).
        let mut state = 0x5354_454c_u64;
        for _ in 0..10_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let k = 1 + (state >> 60) as usize % 8;
            let prefix = (state >> 20) as usize % ((1 << k) + 1);
            let (z, r) = (point(k), point(k));
            assert_eq!(
                eq_prefix_mle(&z, prefix, &r),
                reference(&z, prefix, &r),
                "k={k} prefix={prefix}"
            );
        }
    }

    /// Two-segment relation with a carried boundary, virtual Linear and Pointwise columns, two
    /// weight columns, power-of-two ranges and two non-power-of-two tables (Q51 prefix mask),
    /// one of them read under an all-zero selector. No matmul or public-column claim: the
    /// one-layer window of `stele-prover` covers those.
    fn composed_fixture() -> (Relation, Vec<Values>, Values) {
        let mut rel = Relation::default();
        let g0 = Kind::Witness(rel.add_group_in("s0/w", 3, 0));
        let g1 = Kind::Witness(rel.add_group_in("s1/w", 3, 1));
        let w_col = rel.add_column("W", Kind::Weight, Width::signed(4), 3);
        rel.ranges.push(Range {
            name: "r_w".into(),
            column: w_col,
            width: Width::signed(4),
        });
        // 128 further weights: the model source is large enough for a certified radius above
        // one, which the composed NC-0635 needs.
        let w_wide = rel.add_column("W/wide", Kind::Weight, Width::signed(4), 7);
        rel.ranges.push(Range {
            name: "r_w_wide".into(),
            column: w_wide,
            width: Width::signed(4),
        });
        let x0 = rel.add_column("s0/x", g0.clone(), Width::unsigned(3), 3);
        let c0 = rel.add_column("s0/carry", g0, Width::unsigned(4), 3);
        rel.mark_carried(c0);
        // Non-power-of-two lookup table (t = 5 < 8 = 2^3) exercising Q51 prefix-mask reduction.
        let tbl = rel.add_table(Table {
            name: "small5".into(),
            widths: vec![Width::unsigned(3)],
            rows: vec![vec![0], vec![1], vec![2], vec![3], vec![4]],
        });
        rel.ranges.push(Range {
            name: "r_x0".into(),
            column: x0,
            width: Width::unsigned(3),
        });
        rel.ranges.push(Range {
            name: "r_c0".into(),
            column: c0,
            width: Width::unsigned(4),
        });
        rel.lookups.push(Lookup {
            name: "lu_small5".into(),
            vars: 3,
            selector: None,
            tuple: vec![Ref::identity(x0, 3)],
            table: tbl,
        });
        // A second non-power-of-two table (t = 3 < 4), read only under an all-zero public
        // selector: its multiplicities are zero, so the prefix sumcheck accepts any `eq` final
        // and only the closed-form mask check binds it (NC-0636).
        let off = rel.add_column("s0/off", Kind::Public(vec![0; 8]), Width::unsigned(1), 3);
        let unread = rel.add_table(Table {
            name: "small3".into(),
            widths: vec![Width::unsigned(3)],
            rows: vec![vec![0], vec![1], vec![2]],
        });
        rel.lookups.push(Lookup {
            name: "lu_small3".into(),
            vars: 3,
            selector: Some(Ref::identity(off, 3)),
            tuple: vec![Ref::identity(x0, 3)],
            table: unread,
        });
        let v_lin = rel.add_virtual(
            "s0/v_lin",
            Def::Linear {
                constant: 1,
                terms: vec![(1, Ref::identity(x0, 3))],
            },
            3,
        );
        rel.identities.push(Identity {
            name: "s0/carry_eq".into(),
            vars: 3,
            terms: vec![
                IdTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(c0, 3)],
                },
                IdTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_lin, 3)],
                },
            ],
        });
        let y1 = rel.add_column("s1/y", g1.clone(), Width::signed(8), 3);
        let z1 = rel.add_column("s1/z", g1, Width::signed(12), 3);
        rel.ranges.push(Range {
            name: "r_y1".into(),
            column: y1,
            width: Width::signed(8),
        });
        rel.ranges.push(Range {
            name: "r_z1".into(),
            column: z1,
            width: Width::signed(12),
        });
        rel.identities.push(Identity {
            name: "s1/y_eq".into(),
            vars: 3,
            terms: vec![
                IdTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(y1, 3)],
                },
                IdTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(c0, 3), Ref::identity(w_col, 3)],
                },
            ],
        });
        let v_pw = rel.add_virtual(
            "s1/v_pw",
            Def::Pointwise {
                terms: vec![IdTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(y1, 3), Ref::identity(w_col, 3)],
                }],
            },
            3,
        );
        rel.identities.push(Identity {
            name: "s1/z_eq".into(),
            vars: 3,
            terms: vec![
                IdTerm {
                    coeff: 1,
                    factors: vec![Ref::identity(z1, 3)],
                },
                IdTerm {
                    coeff: -1,
                    factors: vec![Ref::identity(v_pw, 3)],
                },
            ],
        });

        let w_vals = vec![1, -1, 2, 0, 1, -2, 3, -1];
        let w_wide_vals: Vec<i64> = (0..128).map(|i| (i * 5 + 3) % 16 - 8).collect();
        let x0_vals = vec![0, 1, 2, 3, 4, 2, 1, 0];
        let c0_vals: Vec<i64> = x0_vals.iter().map(|&v| v + 1).collect();
        let y1_vals: Vec<i64> = c0_vals.iter().zip(&w_vals).map(|(&c, &w)| c * w).collect();
        let z1_vals: Vec<i64> = y1_vals.iter().zip(&w_vals).map(|(&y, &w)| y * w).collect();

        let mut all_vals = Values::default();
        all_vals.set(&rel, w_col, w_vals.clone()).expect("w");
        all_vals
            .set(&rel, w_wide, w_wide_vals.clone())
            .expect("w wide");
        all_vals.set(&rel, x0, x0_vals.clone()).expect("x0");
        all_vals.set(&rel, c0, c0_vals.clone()).expect("c0");
        all_vals.set(&rel, y1, y1_vals.clone()).expect("y1");
        all_vals.set(&rel, z1, z1_vals.clone()).expect("z1");
        stele_ir::relation::check(&rel, &all_vals).expect("plain check");

        let mut s0_vals = Values::default();
        s0_vals.set(&rel, w_col, w_vals.clone()).expect("s0 w");
        s0_vals
            .set(&rel, w_wide, w_wide_vals.clone())
            .expect("s0 w wide");
        s0_vals.set(&rel, x0, x0_vals).expect("s0 x0");
        s0_vals.set(&rel, c0, c0_vals.clone()).expect("s0 c0");

        let mut s1_vals = Values::default();
        s1_vals.set(&rel, w_col, w_vals).expect("s1 w");
        s1_vals
            .set(&rel, w_wide, w_wide_vals.clone())
            .expect("s1 w wide");
        s1_vals.set(&rel, c0, c0_vals).expect("s1 c0");
        s1_vals.set(&rel, y1, y1_vals).expect("s1 y1");
        s1_vals.set(&rel, z1, z1_vals).expect("s1 z1");

        (rel, vec![s0_vals, s1_vals], all_vals)
    }

    #[test]
    fn accepts_composed_joined_recursion_and_rejects_nc_0631_and_nc_0633_to_0636() {
        let (rel, seg_vals, all_vals) = composed_fixture();
        let model_sources = recursive_model_sources(&rel, &all_vals).expect("model register");
        let layouts = recursive_model_layout(&rel).expect("layouts");
        let verified_models: Vec<VerifiedCertifiedSource<K>> = model_sources
            .iter()
            .zip(&layouts)
            .map(|(m, l)| {
                verify_recursive_model(
                    l,
                    m.prepared.source().root(),
                    m.prepared.certificate_proof(),
                )
                .expect("verify cert")
            })
            .collect();

        let prove_once = || {
            let mut t = Transcript::<K>::new(b"stele/test/e19-04-composed").expect("t");
            let mut segs = seg_vals.clone();
            prove_recursive_measured(
                &mut t,
                &rel,
                |s| Ok(core::mem::take(&mut segs[s as usize])),
                &model_sources,
            )
            .expect("prove recursive")
        };
        let (proof1, metrics1) = prove_once();
        let (proof2, _) = prove_once();
        assert_eq!(
            proof1, proof2,
            "recursive proof bytes must be deterministic"
        );
        assert!(metrics1.openings_bytes > 0);

        let mut tv = Transcript::<K>::new(b"stele/test/e19-04-composed").expect("tv");
        let ledger = verify_recursive(&mut tv, &rel, &verified_models, &proof1).expect("verify");
        // Joined blocks: s0 mu_stack, s0 witness, s1 mu_stack, s1 witness, model 0 (5 blocks in 1 recursion!).
        assert_eq!(ledger.pcs_sources, 5);
        assert!(ledger.entries.iter().any(|e| e.line == Line::Rlc));

        // NC-0630 and NC-0632 need a forging prover: every level root and `u_L` are absorbed
        // before the column indices are drawn, so a changed byte moves the indices and ends
        // in a Merkle mismatch. They run on the joined recursion in `stele-pcs`
        // (`accepts_joined_multi_source_recursion_and_rejects_composed_tampers`).
        let root_mismatch = |proof: &ProofV2| {
            let mut tv = Transcript::<K>::new(b"stele/test/e19-04-composed").expect("tv");
            matches!(
                verify_recursive(&mut tv, &rel, &verified_models, proof).err(),
                Some(Error::Recursive(RecursiveError::Merkle(
                    stele_hash::merkle::Error::RootMismatch
                )))
            )
        };
        // NC-0631 on the composed proof: a Merkle sibling of segment 0's witness level-0 close.
        let mut bad_l0 = proof1.clone();
        let last = bad_l0.segments[0].openings[0].len() - 1;
        bad_l0.segments[0].openings[0][last] ^= 1;
        assert!(root_mismatch(&bad_l0));

        // NC-0631 in the joined tail: a Merkle sibling of its last level.
        let mut bad_tail = proof1.clone();
        let tail_idx = bad_tail.model_openings.len() - 1;
        let tail_len = bad_tail.model_openings[tail_idx].len();
        bad_tail.model_openings[tail_idx][tail_len - 16] ^= 1;
        assert!(root_mismatch(&bad_tail));

        // The multiplicity evaluation of `small5` (last final of its prefix sumcheck): the
        // sumcheck's own final check rejects it.
        let plan = plan_recursive(&rel).expect("plan");
        let section = |t: usize| {
            plan.segments[0]
                .checks
                .iter()
                .position(|c| c.t == t)
                .expect("check")
        };
        let mut bad_prefix = proof1.clone();
        let lookup = &mut bad_prefix.segments[0].lookups[section(5)];
        *lookup.last_mut().expect("section") ^= 1;
        let mut tv = Transcript::<K>::new(b"stele/test/e19-04-composed").expect("tv");
        assert!(matches!(
            verify_recursive(&mut tv, &rel, &verified_models, &bad_prefix).err(),
            Some(Error::Sumcheck(
                stele_sumcheck::Error::FinalEvaluationMismatch
            ))
        ));

        // NC-0636, the Q51 mask binding: one bit of the `eq` final of `small3`'s prefix
        // sumcheck. Its multiplicities are zero, so the sumcheck accepts any `eq` final and
        // the closed-form mask is the only check that rejects it.
        let mut bad_mask = proof1.clone();
        let lookup = &mut bad_mask.segments[0].lookups[section(3)];
        let eq_final = lookup.len() - 32;
        lookup[eq_final] ^= 1;
        let mut tv = Transcript::<K>::new(b"stele/test/e19-04-composed").expect("tv");
        assert!(matches!(
            verify_recursive(&mut tv, &rel, &verified_models, &bad_mask).err(),
            Some(Error::EqMismatch)
        ));

        // NC-0633 on composed proof: truncate joined tail section header -> ProofShape.
        let mut bad_shape = proof1.clone();
        bad_shape.model_openings[tail_idx].pop();
        let mut tv = Transcript::<K>::new(b"stele/test/e19-04-composed").expect("tv");
        assert!(matches!(
            verify_recursive(&mut tv, &rel, &verified_models, &bad_shape).err(),
            Some(Error::Recursive(RecursiveError::ProofShape))
        ));

        // NC-0634 on composed proof: flip one round byte of segment-0 claim_batch -> RoundSumMismatch.
        let mut bad_batch = proof1.clone();
        bad_batch.segments[0].openings[0][0] ^= 1;
        let mut tv = Transcript::<K>::new(b"stele/test/e19-04-composed").expect("tv");
        assert!(matches!(
            verify_recursive(&mut tv, &rel, &verified_models, &bad_batch).err(),
            Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
        ));

        // NC-0635 on the composed proof: a model certificate registered at another radius.
        let (k, layout) = layouts
            .iter()
            .enumerate()
            .find(|(_, l)| l.plan.certified_radius() >= 2)
            .expect("a certified radius above one");
        let other_plan = CertifiedPlan::new(
            layout.plan.levels().to_vec(),
            EXT_DEGREE,
            TARGET_BITS,
            layout.plan.certified_radius() - 1,
        )
        .expect("plan at another radius");
        let other =
            CertifiedModelSource::<K>::register(layout.id, other_plan, &model_sources[k].message)
                .expect("other certificate");
        assert!(matches!(
            verify_recursive_model(layout, other.source().root(), other.certificate_proof()).err(),
            Some(Error::Recursive(RecursiveError::CertificateContext))
        ));
    }

    /// One line per instance: name, bits, and each member's column, bits and block.
    fn instances(checks: &[Check]) -> Vec<String> {
        checks
            .iter()
            .map(|c| {
                let members: Vec<(u32, u8, usize)> = c
                    .members
                    .iter()
                    .map(|m| (m.tuple[0].0.column.0, m.m, m.block_index))
                    .collect();
                alloc::format!("{} {} {members:?}", c.name, c.m)
            })
            .collect()
    }

    /// RFC-0026 A30 in a plan (review F3): `N` is the sum of a check's members, each check
    /// has its own bound, and a table follows the rule as a range does. `ta` is read by one
    /// lookup of `2^26` positions: two blocks of `2^25`. `tb`, after it, is read by two
    /// lookups of `2^27` positions: `N = 2^28`, `B_c = 26`, four blocks of `2^26`. The other
    /// profiles keep one instance per check (A8, A15 §6.3).
    #[test]
    fn matches_reference_bound_of_each_check_from_the_sum_of_its_members() {
        let mut rel = Relation::default();
        let g = Kind::Witness(rel.add_group("G/a30/sum", 1));
        for (name, sizes) in [("ta", &[26u8][..]), ("tb", &[27, 27])] {
            let table = rel.add_table(Table {
                name: name.into(),
                widths: vec![Width::unsigned(2)],
                rows: (0..4).map(|v| vec![v]).collect(),
            });
            for (i, &vars) in sizes.iter().enumerate() {
                let x = rel.add_column(
                    &alloc::format!("{name}/x{i}"),
                    g.clone(),
                    Width::unsigned(2),
                    1,
                );
                rel.lookups.push(Lookup {
                    name: alloc::format!("{name}/l{i}"),
                    vars,
                    selector: None,
                    tuple: vec![Ref {
                        column: x,
                        vars: vec![0],
                    }],
                    table,
                });
            }
        }
        assert_eq!(rel.validate(), Ok(()));
        let recursive = plan_recursive(&rel).expect("plan");
        assert_eq!(
            instances(&recursive.segments[0].checks),
            [
                "ta/inst0 25 [(0, 25, 0)]",
                "ta/inst1 25 [(0, 25, 1)]",
                "tb/inst0 26 [(1, 26, 0)]",
                "tb/inst1 26 [(1, 26, 1)]",
                "tb/inst2 26 [(2, 26, 0)]",
                "tb/inst3 26 [(2, 26, 1)]",
            ]
        );
        let unsplit = ["ta 26 [(0, 26, 0)]", "tb 28 [(1, 27, 0), (2, 27, 0)]"];
        for sources in [
            Sources::Expander,
            Sources::Circle,
            Sources::CircleAll,
            Sources::CircleAllGrind,
        ] {
            let plain = plan(&rel, sources).expect("plan");
            assert_eq!(instances(&plain.checks), unsplit, "{sources:?}");
            let segmented = plan_segmented(&rel, sources).expect("plan");
            assert_eq!(
                instances(&segmented.segments[0].checks),
                unsplit,
                "{sources:?}"
            );
        }
    }

    /// RFC-0026 A30 on ranges of 8 bits over `2^26 + 2^22 + 2^21 + 2^19` positions: three
    /// instances of `2^25`, `2^25` and `2^23` positions, the first two the blocks of the
    /// largest member. L2a's largest check has these instance sizes, without a cut member.
    /// A check of `2^25` positions stays one instance under its unsplit name.
    #[test]
    fn matches_reference_split_of_a_check_above_the_floor() {
        let mut rel = Relation::default();
        for (i, n) in [26u8, 22, 21, 19].into_iter().enumerate() {
            let g = Kind::Witness(rel.add_group(&alloc::format!("G/a30/{i}"), n));
            let x = rel.add_column(&alloc::format!("x{i}"), g, Width::unsigned(8), n);
            rel.ranges.push(Range {
                name: alloc::format!("r{i}"),
                column: x,
                width: Width::unsigned(8),
            });
        }
        let g = Kind::Witness(rel.add_group("G/a30/whole", 25));
        let y = rel.add_column("y", g, Width::unsigned(4), 25);
        rel.ranges.push(Range {
            name: "whole".into(),
            column: y,
            width: Width::unsigned(4),
        });
        assert_eq!(rel.validate(), Ok(()));
        let plan = plan_recursive(&rel).expect("plan");
        assert_eq!(
            instances(&plan.segments[0].checks),
            [
                "range_8/inst0 25 [(0, 25, 0)]",
                "range_8/inst1 25 [(0, 25, 1)]",
                "range_8/inst2 23 [(1, 22, 0), (2, 21, 0), (3, 19, 0)]",
                "range_4 25 [(4, 25, 0)]",
            ]
        );
    }

    /// The joined recursion on split checks (review F4): under plan bounds 1 to 6 the
    /// composed fixture has cut members. The honest proof verifies; a verifier under another
    /// bound, one member value of a later block, two swapped sections of one length and a
    /// weight outside its range in a later block are each rejected.
    #[test]
    fn rejects_tampers_of_split_checks_under_small_bounds() {
        let (rel, seg_vals, all_vals) = composed_fixture();
        let layouts = recursive_model_layout(&rel).expect("layouts");
        let run = |bound: u8, seg_vals: &[Values], all_vals: &Values| {
            let model_sources = recursive_model_sources(&rel, all_vals).expect("model register");
            let verified: Vec<VerifiedCertifiedSource<K>> = model_sources
                .iter()
                .zip(&layouts)
                .map(|(m, l)| {
                    verify_recursive_model(
                        l,
                        m.prepared.source().root(),
                        m.prepared.certificate_proof(),
                    )
                    .expect("cert")
                })
                .collect();
            let mut t = Transcript::<K>::new(b"stele/test/review-a30").expect("t");
            let mut segs = seg_vals.to_vec();
            let (proof, metrics) = prove_recursive_with_bound(
                &mut t,
                &rel,
                |s| Ok(core::mem::take(&mut segs[s as usize])),
                &model_sources,
                bound,
            )
            .expect("prove");
            // What the prover counts does not depend on the split.
            let counted = (
                metrics.lookup_checks,
                metrics.lookup_positions,
                metrics.weight_elements_read,
            );
            (proof, verified, counted)
        };
        let verify_under = |bound: u8, verified: &[VerifiedCertifiedSource<K>], proof: &ProofV2| {
            let mut t = Transcript::<K>::new(b"stele/test/review-a30").expect("t");
            verify_recursive_with_bound(&mut t, &rel, verified, proof, bound).map(|_| ())
        };
        // An out-of-range weight (100 in a signed 4-bit column) at index 100 of `W/wide`.
        let w_wide = ColumnId(1);
        let mut wide: Vec<i64> = (0..128).map(|i| (i * 5 + 3) % 16 - 8).collect();
        wide[100] = 100;
        let mut bad_all = all_vals.clone();
        bad_all.set(&rel, w_wide, wide.clone()).expect("bad all");
        let mut bad_segs = seg_vals.clone();
        for v in &mut bad_segs {
            v.set(&rel, w_wide, wide.clone()).expect("bad seg");
        }
        let mut swaps = 0;
        let (reference, verified, unsplit) = run(DEFAULT_INSTANCE_BOUND, &seg_vals, &all_vals);
        assert_eq!(
            verify_under(DEFAULT_INSTANCE_BOUND, &verified, &reference),
            Ok(())
        );
        for bound in [1u8, 2, 3, 4, 5, 6] {
            let (proof, verified, counted) = run(bound, &seg_vals, &all_vals);
            assert_eq!(counted, unsplit, "bound {bound}");
            let plan = plan_recursive_with_bound(&rel, bound).expect("plan");
            let checks0 = &plan.segments[0].checks;
            let blocks: usize = plan
                .segments
                .iter()
                .flat_map(|s| s.checks.iter())
                .flat_map(|c| c.members.iter())
                .filter(|m| m.block_bits > 0)
                .count();
            assert!(blocks > 0, "bound {bound}");
            assert!(proof != reference);
            assert_eq!(
                verify_under(bound, &verified, &proof),
                Ok(()),
                "bound {bound}"
            );
            // Another bound is another plan.
            for other in [1u8, 2, 3, 4, 5, 6, 30] {
                if other != bound {
                    let outcome = verify_under(other, &verified, &proof);
                    assert!(outcome.is_err(), "bound {bound} under {other}");
                }
            }
            // One member value of an instance that starts with a later block of a range.
            let j = checks0
                .iter()
                .position(|c| c.t == 1 << c.k && c.members[0].block_index >= 1)
                .expect("a later block");
            let mut bad = proof.clone();
            let section = &mut bad.segments[0].lookups[j];
            let at = section.len() - 16 * checks0[j].c * checks0[j].members.len();
            section[at] ^= 1;
            assert_eq!(
                verify_under(bound, &verified, &bad),
                Err(Error::MemberSumMismatch),
                "bound {bound}"
            );
            // Two instances of one check with sections of one length, swapped.
            let pair = (0..checks0.len() - 1).find(|&i| {
                checks0[i].t == checks0[i + 1].t
                    && checks0[i].m == checks0[i + 1].m
                    && checks0[i].members.len() == checks0[i + 1].members.len()
                    && checks0[i].members[0].block_bits > 0
                    && checks0[i + 1].members[0].block_bits > 0
                    && proof.segments[0].lookups[i].len() == proof.segments[0].lookups[i + 1].len()
            });
            if let Some(i) = pair {
                let mut bad = proof.clone();
                bad.segments[0].lookups.swap(i, i + 1);
                assert!(
                    verify_under(bound, &verified, &bad).is_err(),
                    "bound {bound}"
                );
                swaps += 1;
            }
            // The out-of-range weight sits in block `100 >> bound` of its member.
            let (forged, forged_model, _) = run(bound, &bad_segs, &bad_all);
            assert_eq!(
                verify_under(bound, &forged_model, &forged),
                Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch)),
                "bound {bound}"
            );
        }
        // At the default bound the same forged witness fails its one unsplit instance.
        let (forged, forged_model, _) = run(DEFAULT_INSTANCE_BOUND, &bad_segs, &bad_all);
        assert_eq!(
            verify_under(DEFAULT_INSTANCE_BOUND, &forged_model, &forged),
            Err(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
        );
        assert!(swaps > 0, "no bound had two sections of one length to swap");
    }
}
