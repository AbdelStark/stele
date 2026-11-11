//! RFC-0026 §4 step 5 (A3): one RFC-0008 A5 grouped LogUp per table. Every lookup
//! into a table, or every range of one width, is a member; the members' position
//! sets are concatenated, largest first, into one original domain of `2^m >= Σ 2^m_i`
//! positions with the padding unselected. The A2 item 2 derivation is N = 2^m,
//! b = min(m,30) (so h = 0 units), r = 1, d = 4.
//!
//! The message schedule, labels, trees, selected product and rank-two multiplicity
//! prefix functionals are A5's (`lookup_verifier.rs`). Only the originals differ:
//! each tuple entry is a column of a group or weight source read through a `Ref`,
//! possibly shifted by `-width.min()` (RFC-0026 §3.4), so the selected-product claims
//! are routed to RFC-0026 §4 step 7 instead of being opened here (RFC-0008 A2
//! as amended for RFC-0026; every root is fixed before the first lookup draw).
use super::{column, put, Check, Claims, Error, Ledger, Line, Reader, K};
use crate::lookup::{functionals, phase};
use alloc::vec::Vec;
use stele_field::{Field, Serialize, M31};
use stele_hash::{AbsorbLabel, ChallengeLabel, Transcript};
use stele_ir::relation::{Relation, Values};
use stele_lookup::fraction::{self, LeafDescriptor, SelectedProduct};
use stele_pcs::{verify_opening, Functional, PreparedSource, Source, VerifiedCertificate};
use stele_sumcheck::parallel::{for_each_chunk, sum_ranges};

const FRACTION: fn(fraction::Error) -> Error = Error::Fraction;

/// Expected A5 statement bytes: identity, derived dimensions, multiplicity layout and
/// tuple tensor ids. Table and tuple contents are bound by the relation digest.
fn statement(check: &Check) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[1, 4]);
    out.extend_from_slice(&check.id.to_le_bytes());
    out.extend_from_slice(&[check.m, check.m.min(30), 1, check.c as u8]);
    out.extend_from_slice(&(check.t as u32).to_le_bytes());
    out.push(check.k);
    out.extend_from_slice(&check.layout.id.to_le_bytes());
    out.extend_from_slice(&[check.layout.ell, check.layout.blowup]);
    out.extend_from_slice(&(check.members.len() as u32).to_le_bytes());
    for member in &check.members {
        out.push(member.m);
    }
    for i in 0..check.c {
        out.extend_from_slice(&check.tuple_id(i).to_le_bytes());
    }
    out
}

/// The concatenated selector: each member's public selector (or ones) on its block,
/// zero on the padding.
fn sigma(check: &Check, relation: &Relation) -> Vec<K> {
    let mut out = alloc::vec![K::from_i64(0); 1 << check.m];
    for member in &check.members {
        let block = &mut out[member.offset..member.offset + (1 << member.m)];
        for_each_chunk(block, |start, chunk| {
            for (j, s) in chunk.iter_mut().enumerate() {
                let x = start + j;
                *s = match &member.selector {
                    None => K::from_i64(1),
                    // Validated public 0/1 column (RFC-0026 §3.3).
                    Some(r) => match &relation.columns[r.column.0 as usize].kind {
                        stele_ir::relation::Kind::Public(v) => K::from_i64(v[r.index(x as u64)]),
                        _ => K::from_i64(0),
                    },
                };
            }
        });
    }
    out
}

/// Concatenated tuple column `i`: on each member block,
/// `x_i(local) = column(ref.index(local)) + offset`; zero on the padding.
fn originals(check: &Check, relation: &Relation, values: &Values) -> Result<Vec<Vec<K>>, Error> {
    let mut out = alloc::vec![alloc::vec![K::from_i64(0); 1 << check.m]; check.c];
    for member in &check.members {
        for (x, (r, offset)) in out.iter_mut().zip(&member.tuple) {
            let col = column(relation, values, r.column)?;
            let shift = K::from_i64(*offset);
            let block = &mut x[member.offset..member.offset + (1 << member.m)];
            for_each_chunk(block, |start, chunk| {
                for (j, v) in chunk.iter_mut().enumerate() {
                    *v = K::from_i64(col[r.index((start + j) as u64)]) + shift;
                }
            });
        }
    }
    Ok(out)
}

/// eq(z_high, bits(block index)) of a member, with z MSB-first over the whole domain.
fn block_weight(check: &Check, member: &super::Member, z: &[K]) -> K {
    let high = usize::from(check.m - member.m);
    let block = member.offset >> member.m;
    let one = K::from_i64(1);
    z[..high].iter().enumerate().fold(one, |w, (j, x)| {
        w * if (block >> (high - 1 - j)) & 1 == 1 {
            *x
        } else {
            one - *x
        }
    })
}

/// Each member's tuple evaluations at the low coordinates of `z`, member-major.
fn split(check: &Check, xs: &[Vec<K>], z: &[K]) -> Result<Vec<K>, Error> {
    let mut out = Vec::new();
    for member in &check.members {
        let low = &z[usize::from(check.m - member.m)..];
        let eq = stele_sumcheck::parallel::eq_table(low)?;
        for x in xs {
            let block = &x[member.offset..member.offset + (1 << member.m)];
            let mut dot = [K::from_i64(0)];
            sum_ranges(eq.len(), &mut dot, |range, out| {
                for i in range {
                    out[0] = out[0] + block[i] * eq[i];
                }
                Ok(())
            })?;
            out.push(dot[0]);
        }
    }
    Ok(out)
}

fn compress(row: &[K], beta: K) -> K {
    row.iter().rev().fold(K::from_i64(0), |v, x| v * beta + *x)
}

/// Grouped multiplicities (b = m, so every unit weight is one) per table row.
pub(super) fn counts(
    check: &Check,
    relation: &Relation,
    values: &Values,
) -> Result<Vec<i64>, Error> {
    let key = |row: &[i64]| -> [u32; 2] {
        let mut key = [0; 2];
        for (k, v) in key.iter_mut().zip(row) {
            *k = M31::from_i64(*v).as_u32();
        }
        key
    };
    let mut index: Vec<([u32; 2], usize)> = check
        .entries
        .chunks_exact(check.c)
        .take(check.t)
        .enumerate()
        .map(|(i, row)| (key(row), i))
        .collect();
    index.sort_unstable();
    let selected = sigma(check, relation);
    let mut mu = alloc::vec![0i64; 1 << check.k];
    for member in &check.members {
        let mut xs = Vec::new();
        for (r, offset) in &member.tuple {
            xs.push((
                r,
                column(relation, values, r.column)?,
                M31::from_i64(*offset),
            ));
        }
        // Each position's table row is found in parallel and counted in order below.
        let mut rows = alloc::vec![usize::MAX; 1 << member.m];
        for_each_chunk(&mut rows, |start, chunk| {
            for (j, row) in chunk.iter_mut().enumerate() {
                let local = start + j;
                if selected[member.offset + local] == K::from_i64(0) {
                    continue;
                }
                let mut k = [0u32; 2];
                for (k, (r, col, shift)) in k.iter_mut().zip(&xs) {
                    *k = (M31::from_i64(col[r.index(local as u64)]) + *shift).as_u32();
                }
                // Unmatched tuples stay in the lookup leaves; the roots decide (A5 producer).
                if let Ok(p) = index.binary_search_by_key(&k, |e| e.0) {
                    *row = index[p].1;
                }
            }
        });
        for row in rows.into_iter().filter(|row| *row != usize::MAX) {
            mu[row] += 1;
        }
    }
    Ok(mu)
}

/// The committed multiplicity message: [`counts`] as A5 §4 K limbs.
pub(super) fn multiplicities(
    #[allow(unused_variables)] check: &Check,
    counts: &[i64],
) -> Result<Vec<M31>, Error> {
    #[allow(unused_mut)]
    let mut mu = counts.to_vec();
    #[cfg(test)]
    {
        mu[0] += check.skew; // Malicious-prover seam for the piece-sum control.
    }
    let mut limbs = Vec::with_capacity(mu.len() * 4);
    for count in mu {
        for word in K::from_i64(count).to_le_bytes().chunks_exact(4) {
            limbs.push(
                M31::from_le_bytes(word.try_into().map_err(|_| Error::Capacity)?)
                    .ok_or(Error::Capacity)?,
            );
        }
    }
    Ok(limbs)
}

struct Phase {
    left: fraction::Descriptor<K>,
    right: fraction::Descriptor<K>,
    beta: K,
    alpha: K,
}

/// A5 prefix: statement, (empty) units, multiplicity bundle, beta/alpha, phase 1.
fn start(
    t: &mut Transcript<K>,
    check: &Check,
    mu: &VerifiedCertificate<K>,
) -> Result<Phase, Error> {
    t.absorb(AbsorbLabel::LookupStatement, &statement(check))?;
    t.absorb(AbsorbLabel::LookupUnits, &phase(check.id, 0, 0)[..9])?;
    let mut bundle = Vec::new();
    bundle.extend_from_slice(&check.id.to_le_bytes());
    bundle.push(1);
    bundle.push(0);
    bundle.extend_from_slice(&mu.record().source().bytes());
    bundle.extend_from_slice(&mu.record().id());
    t.absorb(AbsorbLabel::LookupMultiplicities, &bundle)?;
    t.absorb(AbsorbLabel::LookupRepetition, &phase(check.id, 0, 0))?;
    let beta = t.challenge(ChallengeLabel::LookupBeta)?;
    let alpha = t.challenge(ChallengeLabel::LookupAlpha)?;
    t.absorb(AbsorbLabel::LookupRepetition, &phase(check.id, 0, 1))?;
    let (tree, leaf) = (4 * check.id, 8 * check.id);
    let m = u32::from(check.m);
    let k = u32::from(check.k);
    Ok(Phase {
        left: fraction::Descriptor::new(tree, m, m.min(30), [leaf, leaf + 1], &[])
            .map_err(FRACTION)?,
        right: fraction::Descriptor::new(tree + 1, k, k, [leaf + 2, leaf + 3], &[])
            .map_err(FRACTION)?,
        beta,
        alpha,
    })
}

/// Table columns and valid-row count at `point`, padded rows reading zero.
fn table_at(check: &Check, point: &[K]) -> Result<(Vec<K>, K), Error> {
    let eq = stele_poly::eq_table(point).map_err(|_| Error::Capacity)?;
    let mut columns = alloc::vec![K::from_i64(0); check.c];
    let mut valid = K::from_i64(0);
    for (i, (w, row)) in eq
        .iter()
        .zip(check.entries.chunks_exact(check.c))
        .enumerate()
    {
        for (c, v) in columns.iter_mut().zip(row) {
            *c = *c + *w * K::from_i64(*v);
        }
        if i < check.t {
            valid = valid + *w;
        }
    }
    Ok((columns, valid))
}

fn check_table(
    check: &Check,
    p: &Phase,
    table: &stele_lookup::fraction::Reduction<K>,
) -> Result<(), Error> {
    let (columns, valid) = table_at(check, &table.point)?;
    let one = K::from_i64(1);
    if table.claims[1].1 != one + (p.alpha - one) * valid - compress(&columns, p.beta) {
        return Err(Error::Lookup(
            crate::lookup::Error::TableDenominatorMismatch,
        ));
    }
    Ok(())
}

fn claims_payload(check: &Check, point: &[K], numerator: K, pieces: &[(u8, K)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&phase(check.id, 0, pieces.len() as u8));
    for v in point.iter().chain([&numerator]) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for (id, v) in pieces {
        out.push(*id);
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// RFC-0026 A3: the concatenated claim is `Σ_i eq_i · v_i` exactly, because each
/// member block is the sub-cube selected by its high coordinates.
fn check_members(
    check: &Check,
    selected: &stele_lookup::fraction::LeafReduction<K>,
    members: &[K],
) -> Result<(), Error> {
    let z = &selected.point;
    for (col, (_, value)) in selected.claims.iter().enumerate() {
        let total = check
            .members
            .iter()
            .zip(members.chunks_exact(check.c))
            .fold(K::from_i64(0), |s, (member, v)| {
                s + block_weight(check, member, z) * v[col]
            });
        if total != *value {
            return Err(Error::MemberSumMismatch);
        }
    }
    Ok(())
}

/// Route each member value to its column at the member's low coordinates (minus its
/// shift), as RFC-0008 A6 column claims.
fn route(check: &Check, z: &[K], members: &[K], claims: &mut Claims) {
    for (member, v) in check.members.iter().zip(members.chunks_exact(check.c)) {
        let low = &z[usize::from(check.m - member.m)..];
        for ((r, offset), value) in member.tuple.iter().zip(v) {
            claims.push(r, low, *value - K::from_i64(*offset));
        }
    }
}

/// Produce one lookup section; never checks the verifier's equations itself.
/// `counts` is [`counts`] of `(check, relation, values)`, made once in step 3.
#[allow(clippy::too_many_arguments)]
pub(super) fn prove(
    t: &mut Transcript<K>,
    check: &Check,
    relation: &Relation,
    values: &Values,
    counts: &[i64],
    mu: (&PreparedSource<'_, K>, &VerifiedCertificate<K>),
    out: &mut Vec<u8>,
    claims: &mut Claims,
) -> Result<(), Error> {
    let p = start(t, check, mu.1)?;
    let xs = originals(check, relation, values)?;
    let sigma = sigma(check, relation);
    let one = K::from_i64(1);
    // compress(row) without the row: the same Horner fold over the tuple columns.
    let mut leaves = alloc::vec![[K::from_i64(0); 2]; sigma.len()];
    for_each_chunk(&mut leaves, |start, chunk| {
        for (j, leaf) in chunk.iter_mut().enumerate() {
            let (i, s) = (start + j, sigma[start + j]);
            let row = xs
                .iter()
                .rev()
                .fold(K::from_i64(0), |v, x| v * p.beta + x[i]);
            *leaf = [s, one - s + s * (p.alpha - row)];
        }
    });
    let (left_proof, lookup) = p.left.prove(&leaves, t).map_err(FRACTION)?;
    out.extend_from_slice(&left_proof.encode(&p.left).map_err(FRACTION)?);
    let message = mu.0.message();
    let mut right = alloc::vec![[K::from_i64(0), one]; check.entries.len() / check.c];
    for_each_chunk(&mut right, |start, chunk| {
        for (j, out) in chunk.iter_mut().enumerate() {
            let i = start + j;
            if i < check.t {
                let row = &check.entries[i * check.c..(i + 1) * check.c];
                let row = row
                    .iter()
                    .rev()
                    .fold(K::from_i64(0), |v, x| v * p.beta + K::from_i64(*x));
                *out = [K::from_i64(counts[i]), p.alpha - row];
            }
        }
    });
    let (right_proof, table) = p.right.prove(&right, t).map_err(FRACTION)?;
    out.extend_from_slice(&right_proof.encode(&p.right).map_err(FRACTION)?);
    let ids: Vec<u64> = (0..check.c).map(|i| check.tuple_id(i)).collect();
    let leaf = LeafDescriptor::new(&p.left, &ids).map_err(FRACTION)?;
    let (proof, selected) = SelectedProduct::new(leaf, &lookup, &sigma, p.alpha, p.beta)
        .map_err(FRACTION)?
        .prove(&xs, t)
        .map_err(FRACTION)?;
    out.extend_from_slice(&leaf.encode(&proof).map_err(FRACTION)?);
    #[allow(unused_mut)]
    let mut members = split(check, &xs, &selected.point)?;
    #[cfg(test)]
    if let Some(other) = &check.split {
        members = split(check, &originals(check, relation, other)?, &selected.point)?;
    }
    put(out, &members);
    route(check, &selected.point, &members, claims);
    let pieces =
        functionals::pieces(mu.0.source(), &table.point, check.t).map_err(Error::Lookup)?;
    let values: Vec<(u8, K)> = pieces.iter().map(|q| (q.id, q.value(message))).collect();
    for (_, v) in &values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    t.absorb(
        AbsorbLabel::LookupMultiplicityClaims,
        &claims_payload(check, &table.point, table.claims[0].1, &values),
    )?;
    for (piece, (_, value)) in pieces.iter().zip(&values) {
        let functional = Functional {
            id: u64::from(piece.id),
            a: &piece.a,
            b: &piece.b,
            value: *value,
        };
        let (bytes, _) =
            mu.0.opening(t, mu.1, functional)
                .map_err(|f| Error::Pcs(f.cause))?;
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

/// Replay one lookup section; tuple claims are routed, multiplicities opened here.
pub(super) fn verify(
    t: &mut Transcript<K>,
    check: &Check,
    relation: &Relation,
    mu: &VerifiedCertificate<K>,
    reader: &mut Reader<'_>,
    claims: &mut Claims,
    ledger: &mut Ledger,
) -> Result<(), Error> {
    let p = start(t, check, mu)?;
    let bytes = reader.take(p.left.proof_size().map_err(FRACTION)?)?;
    let left = fraction::Proof::decode(&p.left, bytes).map_err(FRACTION)?;
    let lookup = p.left.verify(&left, t).map_err(FRACTION)?;
    let bytes = reader.take(p.right.proof_size().map_err(FRACTION)?)?;
    let right = fraction::Proof::decode(&p.right, bytes).map_err(FRACTION)?;
    let table = p.right.verify(&right, t).map_err(FRACTION)?;
    fraction::check_roots(left.root, right.root).map_err(FRACTION)?;
    check_table(check, &p, &table)?;
    let ids: Vec<u64> = (0..check.c).map(|i| check.tuple_id(i)).collect();
    let leaf = LeafDescriptor::new(&p.left, &ids).map_err(FRACTION)?;
    let sigma = sigma(check, relation);
    let leaf_proof = leaf
        .decode(reader.take(leaf.proof_size().map_err(FRACTION)?)?)
        .map_err(FRACTION)?;
    let selected = SelectedProduct::new(leaf, &lookup, &sigma, p.alpha, p.beta)
        .map_err(FRACTION)?
        .verify(&leaf_proof, t)
        .map_err(FRACTION)?;
    let members = reader.ks(check.members.len() * check.c)?;
    check_members(check, &selected, &members)?;
    route(check, &selected.point, &members, claims);
    let source: &Source<K> = mu.record().source();
    let pieces = functionals::pieces(source, &table.point, check.t).map_err(Error::Lookup)?;
    let mut values = Vec::new();
    let mut total = K::from_i64(0);
    for piece in &pieces {
        let v = reader.k()?;
        total = total + v;
        values.push((piece.id, v));
    }
    if total != table.claims[0].1 {
        return Err(Error::Lookup(crate::lookup::Error::PieceSumMismatch));
    }
    t.absorb(
        AbsorbLabel::LookupMultiplicityClaims,
        &claims_payload(check, &table.point, table.claims[0].1, &values),
    )?;
    let size = source
        .proof_size(stele_pcs::ProofKind::Opening)
        .map_err(Error::Pcs)?;
    for (piece, (_, value)) in pieces.iter().zip(&values) {
        let functional = Functional {
            id: u64::from(piece.id),
            a: &piece.a,
            b: &piece.b,
            value: *value,
        };
        verify_opening(t, mu, functional, reader.take(size)?).map_err(|f| Error::Pcs(f.cause))?;
    }
    // RFC-0012 A8/A11 LU numerator h+N+c*t-1 with h = 0, plus the A3 tree/leaf lines.
    let n = 1u64 << check.m;
    ledger.add(Line::Lu, &check.name, n + (check.c * check.t) as u64 - 1);
    for tree in [&lookup, &table] {
        let a = &tree.accounting;
        ledger.add(Line::Rlc, &check.name, a.gamma + a.fold);
        ledger.add(
            Line::Sc,
            &check.name,
            a.layers.iter().map(|l| l.numerator).sum(),
        );
    }
    ledger.add(Line::Sc, &check.name, selected.sc.numerator);
    Ok(())
}
