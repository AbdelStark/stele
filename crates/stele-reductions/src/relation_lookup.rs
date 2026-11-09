//! RFC-0026 §4 step 5: one RFC-0008 A5 grouped LogUp per lookup or range, with the
//! A2 item 2 derivation N = 2^vars, b = min(m,30) (so h = 0 units), r = 1, d = 4.
//!
//! The message schedule, labels, trees, selected product and rank-two multiplicity
//! prefix functionals are A5's (`lookup_verifier.rs`). Only the originals differ:
//! each tuple entry is a column of a group or weight source read through a `Ref`,
//! possibly shifted by `-width.min()` (RFC-0026 §3.4), so the selected-product claims
//! are routed to RFC-0026 §4 step 7 instead of being opened here (RFC-0008 A2
//! as amended for RFC-0026; every root is fixed before the first lookup draw).
use super::{column, Check, Claims, Error, Ledger, Line, Reader, K};
use crate::lookup::{functionals, phase};
use alloc::vec::Vec;
use stele_field::{Field, Serialize, M31};
use stele_hash::{AbsorbLabel, ChallengeLabel, Transcript};
use stele_ir::relation::{Relation, Values};
use stele_lookup::fraction::{self, LeafDescriptor, SelectedProduct};
use stele_pcs::{verify_opening, Functional, PreparedSource, Source, VerifiedCertificate};

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
    for i in 0..check.c {
        out.extend_from_slice(&check.tuple_id(i).to_le_bytes());
    }
    out
}

fn sigma(check: &Check, relation: &Relation) -> Vec<K> {
    let n = 1u64 << check.m;
    match &check.selector {
        None => (0..n).map(|_| K::from_i64(1)).collect(),
        // Validated public 0/1 column (RFC-0026 §3.3).
        Some(r) => {
            let values = match &relation.columns[r.column.0 as usize].kind {
                stele_ir::relation::Kind::Public(v) => v,
                _ => return Vec::new(),
            };
            (0..n).map(|x| K::from_i64(values[r.index(x)])).collect()
        }
    }
}

/// Tuple entries as field elements, `x_i(pos) = column(ref.index(pos)) + offset`.
fn originals(check: &Check, relation: &Relation, values: &Values) -> Result<Vec<Vec<K>>, Error> {
    let mut out = Vec::new();
    for (r, offset) in &check.tuple {
        let col = column(relation, values, r.column)?;
        let shift = K::from_i64(*offset);
        out.push(
            (0..1u64 << check.m)
                .map(|x| K::from_i64(col[r.index(x)]) + shift)
                .collect(),
        );
    }
    Ok(out)
}

fn compress(row: &[K], beta: K) -> K {
    row.iter().rev().fold(K::from_i64(0), |v, x| v * beta + *x)
}

/// Grouped multiplicities (b = m, so every unit weight is one) per table row.
fn counts(check: &Check, relation: &Relation, values: &Values) -> Result<Vec<i64>, Error> {
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
    let mut xs = Vec::new();
    for (r, offset) in &check.tuple {
        let col = column(relation, values, r.column)?;
        let shift = M31::from_i64(*offset);
        xs.push((r, col, shift));
    }
    let selected = sigma(check, relation);
    let mut mu = alloc::vec![0i64; 1 << check.k];
    for (pos, s) in selected.iter().enumerate() {
        if *s == K::from_i64(0) {
            continue;
        }
        let mut k = [0u32; 2];
        for (k, (r, col, shift)) in k.iter_mut().zip(&xs) {
            *k = (M31::from_i64(col[r.index(pos as u64)]) + *shift).as_u32();
        }
        // Unmatched tuples stay in the lookup leaves; the roots decide (A5 producer).
        if let Ok(p) = index.binary_search_by_key(&k, |e| e.0) {
            mu[index[p].1] += 1;
        }
    }
    Ok(mu)
}

/// The committed multiplicity message: counts as A5 §4 K limbs.
pub(super) fn multiplicities(
    check: &Check,
    relation: &Relation,
    values: &Values,
) -> Result<Vec<M31>, Error> {
    #[allow(unused_mut)]
    let mut mu = counts(check, relation, values)?;
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

fn route(check: &Check, selected: &stele_lookup::fraction::LeafReduction<K>, claims: &mut Claims) {
    for ((r, offset), (_, value)) in check.tuple.iter().zip(&selected.claims) {
        claims.push(r, &selected.point, *value - K::from_i64(*offset));
    }
}

/// Produce one lookup section; never checks the verifier's equations itself.
pub(super) fn prove(
    t: &mut Transcript<K>,
    check: &Check,
    relation: &Relation,
    values: &Values,
    mu: (&PreparedSource<'_, K>, &VerifiedCertificate<K>),
    out: &mut Vec<u8>,
    claims: &mut Claims,
) -> Result<(), Error> {
    let p = start(t, check, mu.1)?;
    let xs = originals(check, relation, values)?;
    let sigma = sigma(check, relation);
    let one = K::from_i64(1);
    let leaves: Vec<[K; 2]> = sigma
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let row: Vec<K> = xs.iter().map(|x| x[i]).collect();
            [*s, one - *s + *s * (p.alpha - compress(&row, p.beta))]
        })
        .collect();
    let (left_proof, lookup) = p.left.prove(&leaves, t).map_err(FRACTION)?;
    out.extend_from_slice(&left_proof.encode(&p.left).map_err(FRACTION)?);
    let message = mu.0.message();
    let counts = counts(check, relation, values)?;
    let mut right = Vec::with_capacity(1 << check.k);
    for (i, row) in check.entries.chunks_exact(check.c).enumerate() {
        let row: Vec<K> = row.iter().map(|v| K::from_i64(*v)).collect();
        let count = K::from_i64(counts[i]);
        right.push(if i < check.t {
            [count, p.alpha - compress(&row, p.beta)]
        } else {
            [K::from_i64(0), one]
        });
    }
    let (right_proof, table) = p.right.prove(&right, t).map_err(FRACTION)?;
    out.extend_from_slice(&right_proof.encode(&p.right).map_err(FRACTION)?);
    let ids: Vec<u64> = (0..check.c).map(|i| check.tuple_id(i)).collect();
    let leaf = LeafDescriptor::new(&p.left, &ids).map_err(FRACTION)?;
    let (proof, selected) = SelectedProduct::new(leaf, &lookup, &sigma, p.alpha, p.beta)
        .map_err(FRACTION)?
        .prove(&xs, t)
        .map_err(FRACTION)?;
    out.extend_from_slice(&leaf.encode(&proof).map_err(FRACTION)?);
    route(check, &selected, claims);
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
    route(check, &selected, claims);
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
