//! RFC-0026 A9 with RFC-0013 A5 and RFC-0008 A7 (E12-14a): controls for the dev-zk
//! relation statement through the actual dev-zk verifier (`zk::relation::verify`).
//! Each changes one committed value of an honest witness (the prover skips the
//! plain checker) or the public weight root.
use crate::{check_control, ProverHook};
use stele_field::QM31;
use stele_hash::Transcript;
use stele_reductions::stele_ir::relation::{
    ColumnId, Identity, Kind, Lookup, Matmul, Range, Ref, Relation, Table, Term, Values, Width,
};
use stele_reductions::zk::{claims::Proof, relation as zk_relation, Error, Seed};
use stele_sumcheck::Error as SumcheckError;

const SEED: [u8; 32] = [21; 32];

fn r(column: ColumnId, vars: &[u8]) -> Ref {
    Ref {
        column,
        vars: vars.to_vec(),
    }
}

/// Columns of [`fixture`], by name.
struct Ids {
    c: ColumnId,
    sel3: ColumnId,
    sq: ColumnId,
    sq2: ColumnId,
    u: ColumnId,
    z: ColumnId,
    t: ColumnId,
    o: ColumnId,
}

/// Two members of one table (the second selected), a signed range, a padded range
/// (one variable), an identity with a public coefficient column, a witness × weight
/// product and a matmul with a shared bit. `split` cuts the matmuls into row
/// blocks with fixed bits (RFC-0026 A6).
fn fixture(split: bool) -> (Relation, Values, Ids) {
    let mut rel = Relation::default();
    let g2 = Kind::Witness(rel.add_group("G/zk/2", 2));
    let g1 = Kind::Witness(rel.add_group("G/zk/1", 1));
    let g3 = Kind::Witness(rel.add_group("G/zk/3", 3));
    let s4 = Width::signed(4);
    let x = rel.add_column("x", g2.clone(), s4, 2);
    let sq = rel.add_column("sq", g2.clone(), Width::unsigned(7), 2);
    let y = rel.add_column("y", g2.clone(), s4, 2);
    let sq2 = rel.add_column("sq2", g2.clone(), Width::unsigned(7), 2);
    let u = rel.add_column("u", g2.clone(), Width::signed(3), 2);
    let z = rel.add_column("z", g1, Width::unsigned(2), 1);
    let c = rel.add_column("c", Kind::Public(vec![1, 2, 3, 4]), Width::unsigned(3), 2);
    let t = rel.add_column("t", g2.clone(), Width::signed(8), 2);
    let sel = rel.add_column("sel", Kind::Public(vec![1, 0, 1, 1]), Width::unsigned(1), 2);
    let q = rel.add_column("q", g2.clone(), s4, 2);
    let sel3 = rel.add_column(
        "sel3",
        Kind::Public(vec![1, 1, 0, 1]),
        Width::unsigned(1),
        2,
    );
    let w = rel.add_column("w", Kind::Weight, s4, 2);
    let yw = rel.add_column("yw", g2.clone(), Width::signed(9), 2);
    let p = rel.add_column("p", g3, s4, 3);
    let v = rel.add_column("v", g2.clone(), s4, 2);
    let o = rel.add_column("o", g2, Width::signed(9), 2);
    let squares = rel.add_table(Table {
        name: "squares".into(),
        widths: vec![s4, Width::unsigned(7)],
        rows: (-8..8).map(|v| vec![v, v * v]).collect(),
    });
    // The selected lookup does not discipline its tuple (RFC-0026 §3.6).
    for (id, width) in [
        (x, s4),
        (y, s4),
        (q, s4),
        (sq2, Width::unsigned(7)),
        (u, Width::signed(3)),
        (z, Width::unsigned(2)),
    ] {
        rel.ranges.push(Range {
            name: format!("range{}", id.0),
            column: id,
            width,
        });
    }
    for (id, bits) in [(t, 8), (w, 4), (p, 4), (v, 4), (yw, 9), (o, 9)] {
        rel.ranges.push(Range {
            name: format!("range{}", id.0),
            column: id,
            width: Width::signed(bits),
        });
    }
    rel.lookups.push(Lookup {
        name: "squares/x".into(),
        vars: 2,
        selector: None,
        tuple: vec![r(x, &[0, 1]), r(sq, &[0, 1])],
        table: squares,
    });
    rel.lookups.push(Lookup {
        name: "squares/y".into(),
        vars: 2,
        selector: Some(r(sel, &[0, 1])),
        tuple: vec![r(y, &[0, 1]), r(sq2, &[0, 1])],
        table: squares,
    });
    // One selected member exactly filling its tree: `S` is the only selector input.
    let allowed = rel.add_table(Table {
        name: "allowed".into(),
        widths: vec![s4],
        rows: vec![vec![4], vec![5], vec![-6]],
    });
    rel.lookups.push(Lookup {
        name: "allowed/q".into(),
        vars: 2,
        selector: Some(r(sel3, &[0, 1])),
        tuple: vec![r(q, &[0, 1])],
        table: allowed,
    });
    rel.identities.push(Identity {
        name: "t = c·x".into(),
        vars: 2,
        terms: vec![
            Term {
                coeff: 1,
                factors: vec![r(c, &[0, 1]), r(x, &[0, 1])],
            },
            Term {
                coeff: -1,
                factors: vec![r(t, &[0, 1])],
            },
        ],
    });
    let products = [
        // Bits: 0 = j, 1 = i (free), 2 = k: YW[i,j] = Σ_k Y[i,k] W[k,j].
        Matmul {
            name: "yw".into(),
            free: 2,
            summed: 1,
            out: r(yw, &[0, 1]),
            lhs: r(y, &[2, 1]),
            rhs: r(w, &[0, 2]),
        },
        // Bits: 0 = i, 1 = h (shared), 2 = k: O[h,i] = Σ_k P[h,k,i] V[h,k].
        Matmul {
            name: "pv".into(),
            free: 2,
            summed: 1,
            out: r(o, &[0, 1]),
            lhs: r(p, &[0, 2, 1]),
            rhs: r(v, &[2, 1]),
        },
    ];
    for mm in products {
        if split {
            rel.add_matmul_within(mm, 2);
        } else {
            rel.matmuls.push(mm);
        }
    }
    let mut values = Values::new(&rel);
    let xv = vec![-8, 3, 0, 7];
    let yv = vec![4, 5, -6, 5];
    let (wv, pv, vv) = (
        vec![1, -2, 3, -4],
        vec![1, 2, -3, 4, -5, 6, -7, 0],
        vec![2, -1, 0, 3],
    );
    let at = |col: &[i64], r: &Ref, x: u64| col[r.index(x)];
    let product = |out: &Ref, lhs: (&[i64], &Ref), rhs: (&[i64], &Ref)| -> Vec<i64> {
        let mut o = vec![0; 4];
        for xf in 0..4u64 {
            o[out.index(xf)] = (0..2u64)
                .map(|k| at(lhs.0, lhs.1, xf | k << 2) * at(rhs.0, rhs.1, xf | k << 2))
                .sum();
        }
        o
    };
    let ywv = product(
        &r(yw, &[0, 1]),
        (&yv, &r(y, &[2, 1])),
        (&wv, &r(w, &[0, 2])),
    );
    let ov = product(
        &r(o, &[0, 1]),
        (&pv, &r(p, &[0, 2, 1])),
        (&vv, &r(v, &[2, 1])),
    );
    let square = |col: &[i64]| col.iter().map(|v| v * v).collect::<Vec<_>>();
    let tv: Vec<i64> = xv.iter().zip([1, 2, 3, 4]).map(|(a, b)| a * b).collect();
    for (id, col) in [
        (x, xv.clone()),
        (sq, square(&xv)),
        (y, yv.clone()),
        (sq2, square(&yv)),
        // q[2] = 7 is not allowed; `sel3` leaves it unselected.
        (q, vec![4, 5, 7, -6]),
        (u, vec![-4, 3, 0, -1]),
        (z, vec![0, 3]),
        (t, tv),
        (w, wv),
        (yw, ywv),
        (p, pv),
        (v, vv),
        (o, ov),
    ] {
        values.set(&rel, id, col).expect("shape");
    }
    (
        rel,
        values,
        Ids {
            c,
            sel3,
            sq,
            sq2,
            u,
            z,
            t,
            o,
        },
    )
}

fn prove(rel: &Relation, values: &Values) -> Result<(Proof<QM31>, Option<[u8; 32]>), Error> {
    let root = zk_relation::weight_root(rel, values, &Seed::new(SEED))?;
    let mut t = Transcript::new(b"dev-zk relation control").expect("transcript");
    let proof = zk_relation::prove(&mut t, rel, values, Seed::new(SEED))?;
    Ok((proof, root))
}

fn verify(rel: &Relation, root: Option<[u8; 32]>, proof: &Proof<QM31>) -> Result<(), Error> {
    let mut t = Transcript::new(b"dev-zk relation control").expect("transcript");
    zk_relation::verify(&mut t, rel, root, proof).map(|_| ())
}

/// Which claims relation the adversary sends unchecked: a check's `Σ h = 0`, or
/// an index.
enum Relation_ {
    Check(usize),
    Index(usize),
}

/// Add `delta` to entry `index` of column `id`.
struct Entry {
    rel: Relation,
    id: ColumnId,
    index: usize,
    delta: i64,
}
impl ProverHook<Values> for Entry {
    fn tamper(&self, values: &mut Values) {
        let mut col = values.get(&self.rel, self.id).expect("column").to_vec();
        col[self.index] += self.delta;
        values.set(&self.rel, self.id, col).expect("shape");
    }
}

fn forged(
    rel: &Relation,
    values: &Values,
    index: usize,
) -> Result<(Proof<QM31>, Option<[u8; 32]>), Error> {
    let root = zk_relation::weight_root(rel, values, &Seed::new(SEED))?;
    let mut t = Transcript::new(b"dev-zk relation control").expect("transcript");
    zk_relation::forge(&mut t, rel, values, Seed::new(SEED), index).map(|proof| (proof, root))
}

/// NC-0920..0926: the false witness reaches the verifier through
/// `zk::relation::forge` on claims relation `target` (the check's `Σ h = 0`, or the
/// identity or product): honest rounds, the true `μ`, no producer self-check. That
/// relation's first-round check is the only one that rejects it. The same
/// adversary on the honest witness is accepted (mutation M0).
fn entry_control(
    split: bool,
    pick: impl Fn(&Ids) -> ColumnId,
    index: usize,
    delta: i64,
    target: Relation_,
    expected: Error,
) -> Result<(), String> {
    let (rel, values, ids) = fixture(split);
    let layout = zk_relation::layout(&rel).map_err(|e| format!("{e:?}"))?;
    let target = match target {
        Relation_::Check(l) => zk_relation::check_sum(&layout, l),
        Relation_::Index(i) => i,
    };
    let (proof, root) = forged(&rel, &values, target).map_err(|e| format!("M0 prover: {e:?}"))?;
    verify(&rel, root, &proof).map_err(|e| format!("M0: honest witness rejected: {e:?}"))?;
    let hook = Entry {
        rel: rel.clone(),
        id: pick(&ids),
        index,
        delta,
    };
    let honest = values.clone();
    check_control(
        &values,
        &hook,
        |values| match values == &honest {
            true => prove(&rel, values),
            false => forged(&rel, values, target),
        },
        |(proof, root)| verify(&rel, *root, proof),
        expected,
    )
    .map_err(|e| format!("{e:?}"))
}

/// The relation with public column `id` replaced by `values`.
fn substituted(rel: &Relation, id: ColumnId, values: Vec<i64>) -> Relation {
    let mut used = rel.clone();
    used.columns[id.0 as usize].kind = Kind::Public(values);
    used
}

/// NC-0928, NC-0929: an honest proof of a relation that differs in one public
/// column (`c` of the identity, or `sel3` of the selected check), under the true
/// relation's digest. Every round, final and `μ` is honest for the substitute; only
/// the verifier's own evaluation of that public final rejects it. The same column
/// substituted by itself is accepted (mutation M0).
fn public_control(nc: u16) -> Result<(), String> {
    let (rel, mut values, ids) = fixture(false);
    let (id, column) = match nc {
        928 => (ids.c, vec![1, 2, 3, 5]),
        _ => (ids.sel3, vec![1, 1, 0, 1]),
    };
    let run = |used: &Relation, values: &Values| -> Result<(), Error> {
        let root = zk_relation::weight_root(used, values, &Seed::new(SEED))?;
        let mut t = Transcript::new(b"dev-zk relation control").expect("transcript");
        let proof = zk_relation::forge_substituted(&mut t, &rel, used, values, Seed::new(SEED))?;
        verify(&rel, root, &proof)
    };
    let (statement, used) = match nc {
        928 => {
            // The true `c` with the substitute's witness: t[3] = 5·x[3].
            let mut t = values.get(&rel, ids.t).ok_or("t")?.to_vec();
            t[3] = 35;
            values.set(&rel, ids.t, t).map_err(|e| format!("{e:?}"))?;
            (rel.clone(), substituted(&rel, id, column))
        }
        // The true statement selects q[2] = 7, which is not allowed.
        _ => (substituted(&rel, id, vec![1, 1, 1, 1]), rel.clone()),
    };
    let honest = run(&rel, &fixture(false).1);
    if honest.is_err() {
        return Err(format!("M0: honest substitution rejected: {honest:?}"));
    }
    let root =
        zk_relation::weight_root(&used, &values, &Seed::new(SEED)).map_err(|e| format!("{e:?}"))?;
    let mut t = Transcript::new(b"dev-zk relation control").expect("transcript");
    let proof = zk_relation::forge_substituted(&mut t, &statement, &used, &values, Seed::new(SEED))
        .map_err(|e| format!("adversary: {e:?}"))?;
    match verify(&statement, root, &proof) {
        Err(Error::Sumcheck(SumcheckError::ClaimMismatch)) => Ok(()),
        other => Err(format!("unexpected: {other:?}")),
    }
}

/// NC-0921's positive half: an out-of-table entry at an unselected position of
/// the selected member is accepted (honest prover); the same entry selected is
/// rejected (NC-0921 itself).
fn unselected_is_free() -> Result<(), String> {
    let (rel, mut values, ids) = fixture(false);
    let mut sq2 = values.get(&rel, ids.sq2).ok_or("sq2")?.to_vec();
    sq2[1] = 35; // (y[1], 35) is no square; `sel` leaves position 1 unselected.
    values
        .set(&rel, ids.sq2, sq2)
        .map_err(|e| format!("{e:?}"))?;
    let (proof, root) = prove(&rel, &values).map_err(|e| format!("prover: {e:?}"))?;
    verify(&rel, root, &proof).map_err(|e| format!("unselected entry rejected: {e:?}"))
}

/// NC-0927: the dev-zk model commitment. The verifier's public weight root is
/// changed in one bit; the proof's weight source no longer carries it.
fn nc_0927() -> Result<(), String> {
    let (rel, values, _) = fixture(false);
    let (proof, root) = prove(&rel, &values).map_err(|e| format!("prover: {e:?}"))?;
    let mut other = root.ok_or("no weight root")?;
    verify(&rel, Some(other), &proof).map_err(|e| format!("honest rejected: {e:?}"))?;
    other[0] ^= 1;
    match verify(&rel, Some(other), &proof) {
        Err(Error::Pcs(stele_pcs::Error::Merkle(stele_hash::merkle::Error::RootMismatch))) => {
            Ok(())
        }
        other => Err(format!("unexpected: {other:?}")),
    }
}

/// Execute one dev-zk relation control.
pub fn run(id: u16) -> Result<(), String> {
    let sum = Error::Sumcheck(SumcheckError::RoundSumMismatch);
    match id {
        // NC-0920: the first member's tuple (unselected check member) leaves the table.
        920 => entry_control(false, |i| i.sq, 0, -1, Relation_::Check(0), sum),
        // NC-0921: a selected entry of the selected member leaves the table; the
        // same kind of entry unselected is accepted.
        921 => unselected_is_free()
            .and_then(|()| entry_control(false, |i| i.sq2, 2, -1, Relation_::Check(0), sum)),
        // NC-0922: a signed range (shift −min) below its width (range check 4: bits 3).
        922 => entry_control(false, |i| i.u, 0, -1, Relation_::Check(4), sum),
        // NC-0923: a padded range member (one variable) above its width (check 5).
        923 => entry_control(false, |i| i.z, 1, 1, Relation_::Check(5), sum),
        // NC-0924: a matmul with a shared bit, one out entry +1.
        924 => entry_control(false, |i| i.o, 0, 1, Relation_::Index(2), sum),
        // NC-0925: the same product in row blocks with fixed bits, one out entry +1.
        925 => entry_control(true, |i| i.o, 3, 1, Relation_::Index(4), sum),
        // NC-0926: an identity with a public coefficient column, one entry +1.
        926 => entry_control(false, |i| i.t, 1, 1, Relation_::Index(0), sum),
        927 => nc_0927(),
        // NC-0928: the identity's public coefficient column substituted.
        // NC-0929: the selected check's selector substituted (one entry unselected).
        928 | 929 => public_control(id),
        _ => Err(format!("unknown control {id}")),
    }
}
