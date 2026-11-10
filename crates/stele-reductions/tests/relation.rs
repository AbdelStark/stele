//! RFC-0026 §§3-4, §9: the relation engine accepts what the plain checker accepts and
//! rejects each tamper through the real verifier for the stated reason.
use stele_field::{Field, Inverse, Serialize, M31, QM31};
use stele_hash::{HashUsage, Transcript};
use stele_ir::relation::{
    check, ColumnId, Compose, Identity, Kind, Lookup, Matmul, Range, Ref, Relation, Table, Term,
    Values, Violation, Width,
};
use stele_pcs::{verify_certificate, PreparedSource, VerifiedCertificate};
use stele_reductions::relation::{self, Error, Ledger, Proof};

const PUBLIC: &[u8] = b"stele/test/relation-engine";

fn r(column: ColumnId, vars: &[u8]) -> Ref {
    Ref {
        column,
        vars: vars.to_vec(),
    }
}
fn range(rel: &mut Relation, column: ColumnId, width: Width) {
    rel.ranges.push(Range {
        name: format!("range{}", column.0),
        column,
        width,
    });
}
fn identity(rel: &mut Relation, name: &str, vars: u8, terms: Vec<(i64, Vec<Ref>)>) {
    rel.identities.push(Identity {
        name: name.into(),
        vars,
        terms: terms
            .into_iter()
            .map(|(coeff, factors)| Term { coeff, factors })
            .collect(),
    });
}

/// Deterministic small-value generator.
struct Rng(u64);
impl Rng {
    fn next(&mut self, lo: i64, hi: i64) -> i64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        lo + ((self.0 >> 33) % (hi - lo) as u64) as i64
    }
    fn vec(&mut self, n: usize, w: Width) -> Vec<i64> {
        (0..n).map(|_| self.next(w.min(), w.max() + 1)).collect()
    }
}

struct Fixture {
    rel: Relation,
    values: Values,
}
impl Fixture {
    fn set(&mut self, id: ColumnId, v: Vec<i64>) {
        self.values.set(&self.rel, id, v).expect("shape");
    }
    fn get(&self, id: ColumnId) -> Vec<i64> {
        self.values.get(&self.rel, id).expect("set").to_vec()
    }
}

/// The model sources (RFC-0026 A5): messages, preparations and certificates.
fn prepare<'a>(rel: &Relation, messages: &'a [Vec<M31>]) -> Vec<PreparedSource<'a, QM31>> {
    let layouts = relation::model_layout(rel).unwrap_or_default();
    layouts
        .iter()
        .zip(messages)
        .map(|(layout, message)| {
            PreparedSource::from_code_id(
                layout.id,
                layout.ell,
                &layout.code,
                message,
                &mut HashUsage::default(),
            )
            .expect("model source")
        })
        .collect()
}
fn certify(prepared: &[PreparedSource<'_, QM31>]) -> Vec<VerifiedCertificate<QM31>> {
    prepared
        .iter()
        .map(|p| {
            let (bytes, _) = p.certificate().expect("certificate");
            verify_certificate(*p.source(), &bytes)
                .expect("model certificate")
                .0
        })
        .collect()
}

fn produce(rel: &Relation, values: &Values) -> Result<(Proof, Vec<Vec<M31>>), Error> {
    let messages = relation::model_messages(rel, values)?;
    let prepared = prepare(rel, &messages);
    let certificates = certify(&prepared);
    let model: Vec<_> = prepared.iter().zip(&certificates).collect();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = relation::prove(&mut t, rel, values, &model)?;
    Ok((proof, messages))
}
fn check_proof(rel: &Relation, messages: &[Vec<M31>], proof: &Proof) -> Result<Ledger, Error> {
    let prepared = prepare(rel, messages);
    let certificates = certify(&prepared);
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    relation::verify(&mut t, rel, &certificates.iter().collect::<Vec<_>>(), proof)
}
fn run(f: &Fixture) -> Result<Ledger, Error> {
    let (proof, messages) = produce(&f.rel, &f.values)?;
    check_proof(&f.rel, &messages, &proof)
}

/// Ranges only: signed and unsigned 8 and 16 bits, plus narrow widths.
fn ranges() -> Fixture {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/ranges/3", 3));
    let widths = [
        Width::signed(8),
        Width::unsigned(8),
        Width::signed(16),
        Width::unsigned(16),
        Width::signed(3),
        Width::unsigned(1),
    ];
    let ids: Vec<_> = widths
        .iter()
        .enumerate()
        .map(|(i, w)| rel.add_column(&format!("c{i}"), g.clone(), *w, 3))
        .collect();
    for (id, w) in ids.iter().zip(widths) {
        range(&mut rel, *id, w);
    }
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    let mut rng = Rng(1);
    for (id, w) in ids.iter().zip(widths) {
        let mut v = rng.vec(8, w);
        v[0] = w.min();
        v[1] = w.max();
        f.set(*id, v);
    }
    f
}

/// Identities of degree 1..3 with a broadcast factor and a public coefficient column.
fn identities() -> Fixture {
    let mut rel = Relation::default();
    let g3 = Kind::Witness(rel.add_group("G/id/3", 3));
    let g1 = Kind::Witness(rel.add_group("G/id/1", 1));
    let b = rel.add_column("b", g3.clone(), Width::signed(4), 3);
    let c = rel.add_column("c", g3.clone(), Width::signed(4), 3);
    let a = rel.add_column("a", g3.clone(), Width::signed(8), 3);
    let s = rel.add_column("s", g1, Width::unsigned(2), 1);
    let e = rel.add_column("e", g3.clone(), Width::signed(9), 3);
    let coeff = vec![3, -2, 1, 0, -3, 2, 1, -1];
    let p = rel.add_column("p", Kind::Public(coeff.clone()), Width::signed(3), 3);
    let pb = rel.add_column("pb", g3, Width::signed(6), 3);
    for (id, w) in [(b, 4), (c, 4), (a, 8), (e, 9), (pb, 6)] {
        range(&mut rel, id, Width::signed(w));
    }
    range(&mut rel, s, Width::unsigned(2));
    let all = [0u8, 1, 2];
    identity(
        &mut rel,
        "product",
        3,
        vec![(1, vec![r(a, &all)]), (-1, vec![r(b, &all), r(c, &all)])],
    );
    // Degree 3, with s broadcast along the high domain bit.
    identity(
        &mut rel,
        "cubic",
        3,
        vec![
            (1, vec![r(e, &all)]),
            (-1, vec![r(b, &all), r(c, &all), r(s, &[2])]),
        ],
    );
    identity(
        &mut rel,
        "public",
        3,
        vec![(1, vec![r(pb, &all)]), (-1, vec![r(p, &all), r(b, &all)])],
    );
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    let mut rng = Rng(2);
    let (bv, cv, sv) = (
        rng.vec(8, Width::signed(4)),
        rng.vec(8, Width::signed(4)),
        rng.vec(2, Width::unsigned(2)),
    );
    f.set(b, bv.clone());
    f.set(c, cv.clone());
    f.set(s, sv.clone());
    f.set(a, (0..8).map(|i| bv[i] * cv[i]).collect());
    f.set(e, (0..8).map(|i| bv[i] * cv[i] * sv[i >> 2]).collect());
    f.set(pb, (0..8).map(|i| coeff[i] * bv[i]).collect());
    f
}

/// Lookups with and without a selector; the unselected lookup disciplines its tuple.
fn lookups() -> Fixture {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/lookup/2", 2));
    let x = rel.add_column("x", g.clone(), Width::signed(4), 2);
    let sq = rel.add_column("sq", g.clone(), Width::unsigned(7), 2);
    let y = rel.add_column("y", g, Width::signed(4), 2);
    let sel = rel.add_column("sel", Kind::Public(vec![1, 0, 1, 1]), Width::unsigned(1), 2);
    range(&mut rel, y, Width::signed(4));
    let squares = rel.add_table(Table {
        name: "squares".into(),
        widths: vec![Width::signed(4), Width::unsigned(7)],
        rows: (-8..8).map(|v| vec![v, v * v]).collect(),
    });
    let allowed = rel.add_table(Table {
        name: "allowed".into(),
        widths: vec![Width::signed(4)],
        rows: vec![vec![4], vec![5], vec![-6]],
    });
    rel.lookups.push(Lookup {
        name: "squares".into(),
        vars: 2,
        selector: None,
        tuple: vec![r(x, &[0, 1]), r(sq, &[0, 1])],
        table: squares,
    });
    // Broadcast domain: y read on the low two of three bits, selector on bits 0 and 2.
    rel.lookups.push(Lookup {
        name: "allowed".into(),
        vars: 3,
        selector: Some(r(sel, &[0, 2])),
        tuple: vec![r(y, &[0, 1])],
        table: allowed,
    });
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    f.set(x, vec![-8, 3, 0, 7]);
    f.set(sq, vec![64, 9, 0, 49]);
    f.set(y, vec![4, 5, -6, 5]);
    f
}

/// Matmuls: witness x weight without shared bits, witness x witness with a shared bit.
fn matmuls() -> Fixture {
    let mut rel = Relation::default();
    let g2 = Kind::Witness(rel.add_group("G/mm/2", 2));
    let g3 = Kind::Witness(rel.add_group("G/mm/3", 3));
    let x = rel.add_column("x", g2.clone(), Width::signed(4), 2);
    let w = rel.add_column("w", Kind::Weight, Width::signed(4), 2);
    let y = rel.add_column("y", g2.clone(), Width::signed(9), 2);
    let p = rel.add_column("p", g3, Width::signed(4), 3);
    let v = rel.add_column("v", g2.clone(), Width::signed(4), 2);
    let o = rel.add_column("o", g2, Width::signed(9), 2);
    for (id, bits) in [(x, 4), (w, 4), (y, 9), (p, 4), (v, 4), (o, 9)] {
        range(&mut rel, id, Width::signed(bits));
    }
    // Bits: 0 = j, 1 = i (free), 2 = k (summed): Y[i,j] = sum_k X[i,k] W[k,j].
    rel.matmuls.push(Matmul {
        name: "xw".into(),
        free: 2,
        summed: 1,
        out: r(y, &[0, 1]),
        lhs: r(x, &[2, 1]),
        rhs: r(w, &[0, 2]),
    });
    // Bits: 0 = i, 1 = h (shared), 2 = k: O[h,i] = sum_k P[h,k,i] V[h,k].
    rel.matmuls.push(Matmul {
        name: "pv".into(),
        free: 2,
        summed: 1,
        out: r(o, &[0, 1]),
        lhs: r(p, &[0, 2, 1]),
        rhs: r(v, &[2, 1]),
    });
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    let mut rng = Rng(3);
    let (xv, wv) = (rng.vec(4, Width::signed(4)), rng.vec(4, Width::signed(4)));
    let (pv, vv) = (rng.vec(8, Width::signed(4)), rng.vec(4, Width::signed(4)));
    let at = |col: &[i64], r: &Ref, z: u64| col[r.index(z)];
    let out = |m: usize, lhs: &[i64], rhs: &[i64]| -> Vec<i64> {
        let mm = f.rel.matmuls[m].clone();
        (0..4u64)
            .map(|xf| {
                (0..2u64)
                    .map(|k| at(lhs, &mm.lhs, xf | k << 2) * at(rhs, &mm.rhs, xf | k << 2))
                    .sum()
            })
            .collect()
    };
    let (yv, ov) = (out(0, &xv, &wv), out(1, &pv, &vv));
    for (id, values) in [(x, xv), (w, wv), (y, yv), (p, pv), (v, vv), (o, ov)] {
        f.set(id, values);
    }
    f
}

/// The two `matmuls()` products, each split once into row blocks (RFC-0026 A6): `xw` on
/// the column bit `j` that `w` reads (fixed in `y` and `w`), `pv` on its shared head bit `h` (fixed in
/// `o`, `p` and `v`). The `y` and `o` columns carry no range of their own: the blocks
/// together discipline them by the matmul-out rule.
fn split_matmuls() -> Fixture {
    let honest = matmuls();
    let mut rel = honest.rel.clone();
    let products = core::mem::take(&mut rel.matmuls);
    rel.ranges
        .retain(|range| range.name != "range2" && range.name != "range5");
    for mm in products {
        rel.add_matmul_within(mm, 2);
    }
    let names: Vec<&str> = rel.matmuls.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["xw/block0", "xw/block1", "pv/block0", "pv/block1"]);
    assert_eq!(rel.matmuls[3].rhs.vars, [1, Ref::FIXED_1]);
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    for id in 0..6 {
        f.set(ColumnId(id), honest.get(ColumnId(id)));
    }
    f
}

#[test]
fn accepts_split_matmuls() {
    let f = split_matmuls();
    assert_eq!(check(&f.rel, &f.values), Ok(()));
    let ledger = run(&f).expect("engine");
    println!("{ledger}");
}

#[test]
fn rejects_out_tamper_in_each_row_block() {
    // y index 1 is (i = 0, j = 1): block 1 of xw; o index 1 is (h = 0, i = 1): block 0 of pv.
    for (column, index, block) in [
        (2, 1, "xw/block1"),
        (2, 2, "xw/block0"),
        (5, 1, "pv/block0"),
        (5, 3, "pv/block1"),
    ] {
        let mut f = split_matmuls();
        let mut v = f.get(ColumnId(column));
        v[index] += 1;
        f.set(ColumnId(column), v);
        assert!(
            matches!(check(&f.rel, &f.values), Err(Violation::Matmul { relation, .. }) if relation == block),
            "{block}"
        );
        assert!(run(&f).is_err(), "{block}: engine");
    }
}

/// A 24-bit column composed from range-checked limbs, and a matmul out disciplined by
/// its worst case alone (RFC-0026 §3.5a, §3.6 item 3).
fn composes() -> Fixture {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/compose/2", 2));
    let lo = rel.add_column("lo", g.clone(), Width::unsigned(12), 2);
    let hi = rel.add_column("hi", g.clone(), Width::signed(12), 2);
    let v = rel.add_column("v", g.clone(), Width::signed(24), 2);
    let x = rel.add_column("x", g.clone(), Width::signed(8), 2);
    let g1 = Kind::Witness(rel.add_group("G/compose/1", 1));
    let y = rel.add_column("y", g1, Width::signed(17), 1);
    range(&mut rel, lo, Width::unsigned(12));
    range(&mut rel, hi, Width::signed(12));
    range(&mut rel, x, Width::signed(8));
    rel.composes.push(Compose {
        name: "v".into(),
        column: v,
        limbs: vec![(lo, 0), (hi, 12)],
    });
    // y[i] = sum_k x[i,k]^2: worst case 2 * 128 * 128 = 2^15 fits signed 17.
    rel.matmuls.push(Matmul {
        name: "xx".into(),
        free: 1,
        summed: 1,
        out: r(y, &[0]),
        lhs: r(x, &[0, 1]),
        rhs: r(x, &[0, 1]),
    });
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    let (lv, hv) = (vec![0, 4095, 17, 2048], vec![-2048, 2047, -1, 0]);
    f.set(v, (0..4).map(|i| lv[i] + (hv[i] << 12)).collect());
    f.set(lo, lv);
    f.set(hi, hv);
    let xv = vec![-128, 127, 5, -3];
    f.set(
        y,
        vec![xv[0] * xv[0] + xv[2] * xv[2], xv[1] * xv[1] + xv[3] * xv[3]],
    );
    f.set(x, xv);
    f
}

#[test]
fn rejects_compose_with_a_wrong_column() {
    let mut f = composes();
    let mut v = f.get(ColumnId(2));
    v[1] += 1;
    f.set(ColumnId(2), v);
    assert!(matches!(
        check(&f.rel, &f.values),
        Err(Violation::Compose { .. })
    ));
    assert!(run(&f).is_err());
}

#[test]
fn accepts_each_relation_kind() {
    for (name, f) in [
        ("ranges", ranges()),
        ("identities", identities()),
        ("lookups", lookups()),
        ("matmuls", matmuls()),
        ("composes", composes()),
    ] {
        assert_eq!(check(&f.rel, &f.values), Ok(()), "{name}: plain checker");
        let ledger = run(&f);
        assert!(ledger.is_ok(), "{name}: engine {ledger:?}");
        let ledger = ledger.expect("checked");
        println!("{name}\n{ledger}");
    }
}

/// Everything at once, sharing groups across kinds.
fn combined() -> Fixture {
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/all/3", 3));
    let g2 = Kind::Witness(rel.add_group("G/all/2", 2));
    let b = rel.add_column("b", g.clone(), Width::signed(4), 3);
    let c = rel.add_column("c", g.clone(), Width::signed(4), 3);
    let a = rel.add_column("a", g.clone(), Width::signed(8), 3);
    let sq = rel.add_column("sq", g.clone(), Width::unsigned(7), 3);
    let x = rel.add_column("x", g2.clone(), Width::signed(4), 2);
    let w = rel.add_column("w", Kind::Weight, Width::signed(4), 2);
    let y = rel.add_column("y", g2, Width::signed(9), 2);
    let sel = rel.add_column(
        "sel",
        Kind::Public(vec![1, 1, 0, 1, 0, 0, 1, 1]),
        Width::unsigned(1),
        3,
    );
    for (id, bits) in [(c, 4), (a, 8), (x, 4), (w, 4), (y, 9)] {
        range(&mut rel, id, Width::signed(bits));
    }
    let squares = rel.add_table(Table {
        name: "squares".into(),
        widths: vec![Width::signed(4), Width::unsigned(7)],
        rows: (-8..8).map(|v| vec![v, v * v]).collect(),
    });
    let nonneg = rel.add_table(Table {
        name: "nonneg".into(),
        widths: vec![Width::signed(4)],
        rows: (0..8).map(|v| vec![v]).collect(),
    });
    let all = [0u8, 1, 2];
    identity(
        &mut rel,
        "product",
        3,
        vec![(1, vec![r(a, &all)]), (-1, vec![r(b, &all), r(c, &all)])],
    );
    identity(
        &mut rel,
        "sq",
        3,
        vec![(1, vec![r(sq, &all)]), (-1, vec![r(b, &all), r(b, &all)])],
    );
    rel.lookups.push(Lookup {
        name: "squares".into(),
        vars: 3,
        selector: None,
        tuple: vec![r(b, &all), r(sq, &all)],
        table: squares,
    });
    rel.lookups.push(Lookup {
        name: "nonneg".into(),
        vars: 3,
        selector: Some(r(sel, &all)),
        tuple: vec![r(c, &all)],
        table: nonneg,
    });
    rel.matmuls.push(Matmul {
        name: "xw".into(),
        free: 2,
        summed: 1,
        out: r(y, &[0, 1]),
        lhs: r(x, &[2, 1]),
        rhs: r(w, &[0, 2]),
    });
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    let mut rng = Rng(4);
    let bv = rng.vec(8, Width::signed(4));
    let cv: Vec<i64> = (0..8)
        .map(|i| {
            if [2, 4, 5].contains(&i) {
                rng.next(-8, 8)
            } else {
                rng.next(0, 8)
            }
        })
        .collect();
    f.set(b, bv.clone());
    f.set(c, cv.clone());
    f.set(a, (0..8).map(|i| bv[i] * cv[i]).collect());
    f.set(sq, bv.iter().map(|v| v * v).collect());
    let (xv, wv) = (rng.vec(4, Width::signed(4)), rng.vec(4, Width::signed(4)));
    let yv = (0..4)
        .map(|z: usize| {
            let (j, i) = (z & 1, z >> 1);
            (0..2).map(|k| xv[k | i << 1] * wv[j | k << 1]).sum()
        })
        .collect();
    f.set(x, xv);
    f.set(w, wv);
    f.set(y, yv);
    f
}

#[test]
fn accepts_combined_relation() {
    let f = combined();
    check(&f.rel, &f.values).expect("honest");
    let ledger = run(&f).expect("engine");
    assert!(ledger.interactive() > 0);
    println!("{ledger}");
}

#[test]
fn accepts_exactly_what_the_checker_accepts() {
    let mut rng = Rng(5);
    for trial in 0..24 {
        let mut f = combined();
        let witness: Vec<ColumnId> = (0..f.rel.columns.len() as u32)
            .map(ColumnId)
            .filter(|id| {
                !matches!(
                    f.rel.columns[id.0 as usize].kind,
                    Kind::Public(_) | Kind::Weight
                )
            })
            .collect();
        let id = witness[rng.next(0, witness.len() as i64) as usize];
        let mut v = f.get(id);
        let i = rng.next(0, v.len() as i64) as usize;
        v[i] += [0, 1, -1, 3, 256][trial % 5];
        f.set(id, v);
        let expected = check(&f.rel, &f.values).is_ok();
        let actual = run(&f);
        assert_eq!(
            actual.is_ok(),
            expected,
            "trial {trial} column {id:?}: {actual:?}"
        );
    }
}

/// Honest proof sections for the combined relation.
fn honest() -> (Fixture, Proof, Vec<Vec<M31>>) {
    let f = combined();
    let (proof, messages) = produce(&f.rel, &f.values).expect("honest proof");
    (f, proof, messages)
}
fn add_one(bytes: &mut [u8]) {
    let mut limb = [0u8; 4];
    limb.copy_from_slice(&bytes[..4]);
    let v = M31::from_le_bytes(limb).expect("canonical") + M31::from_i64(1);
    bytes[..4].copy_from_slice(&v.to_le_bytes());
}
fn k_at(bytes: &[u8]) -> QM31 {
    QM31::from_le_bytes(bytes[..16].try_into().expect("16")).expect("canonical")
}
fn set_k(bytes: &mut [u8], v: QM31) {
    bytes[..16].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn rejects_noncanonical_section_lengths_and_counts() {
    let (f, proof, messages) = honest();
    assert!(check_proof(&f.rel, &messages, &proof).is_ok());
    type Kind = fn(&mut Proof) -> &mut Vec<Vec<u8>>;
    let kinds: [Kind; 6] = [
        |p| &mut p.groups,
        |p| &mut p.multiplicities,
        |p| &mut p.identities,
        |p| &mut p.lookups,
        |p| &mut p.matmuls,
        |p| &mut p.openings,
    ];
    for (k, kind) in kinds.iter().enumerate() {
        let shape = Some(Error::ProofShape);
        let mut long = proof.clone();
        kind(&mut long)[0].push(0);
        assert_eq!(
            check_proof(&f.rel, &messages, &long).err(),
            shape,
            "trailing {k}"
        );
        let mut short = proof.clone();
        kind(&mut short)[0].pop();
        assert_eq!(
            check_proof(&f.rel, &messages, &short).err(),
            shape,
            "short {k}"
        );
        let mut extra = proof.clone();
        kind(&mut extra).push(Vec::new());
        assert_eq!(
            check_proof(&f.rel, &messages, &extra).err(),
            shape,
            "extra {k}"
        );
        let mut missing = proof.clone();
        kind(&mut missing).pop();
        assert_eq!(
            check_proof(&f.rel, &messages, &missing).err(),
            shape,
            "missing {k}"
        );
    }
}

#[test]
fn rejects_changed_plan_and_invalid_relation() {
    let (f, proof, messages) = honest();
    let mut other = f.rel.clone();
    other.identities[0].terms[0].coeff = 2; // NC-1305 analogue: plan differs from the proof's
    assert!(check_proof(&other, &messages, &proof).is_err());
    other.identities[0].terms[0]
        .factors
        .push(r(ColumnId(0), &[0, 1, 2]));
    other.identities[0].terms[0]
        .factors
        .push(r(ColumnId(0), &[0, 1, 2]));
    other.identities[0].terms[0]
        .factors
        .push(r(ColumnId(0), &[0, 1, 2]));
    assert!(matches!(
        check_proof(&other, &messages, &proof),
        Err(Error::StatementMismatch(_))
    ));
}

#[test]
fn rejects_tampered_identity_final_value() {
    // NC-1302 at engine level: a committed value changed under one identity.
    let (f, mut proof, messages) = honest();
    let last = proof.identities[0].len() - 16;
    add_one(&mut proof.identities[0][last..]);
    assert_eq!(
        check_proof(&f.rel, &messages, &proof).err(),
        Some(Error::Sumcheck(
            stele_sumcheck::Error::FinalEvaluationMismatch
        ))
    );
    // A recommitted +1 witness has no honest zerocheck.
    let mut g = combined();
    let mut a = g.get(ColumnId(2));
    a[0] += 1;
    g.set(ColumnId(2), a);
    assert!(run(&g).is_err());
}

#[test]
fn rejects_noncanonical_field_element() {
    // NC-1303: p written for a field element.
    let (f, mut proof, messages) = honest();
    proof.identities[0][..4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    assert_eq!(
        check_proof(&f.rel, &messages, &proof).err(),
        Some(Error::NoncanonicalField)
    );
    // The same limb in a group certificate row (after root and version byte).
    let (f, mut proof, messages) = honest();
    proof.groups[0][33..37].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    assert_eq!(
        check_proof(&f.rel, &messages, &proof).err(),
        Some(Error::Pcs(stele_pcs::Error::NoncanonicalField))
    );
}

#[test]
fn rejects_swapped_stacked_and_multiplicity_roots() {
    // NC-1306 under RFC-0026 A4: the one stacked root, swapped with a multiplicity root.
    let (f, mut proof, messages) = honest();
    proof.groups[0][..32].swap_with_slice(&mut proof.multiplicities[0][..32]);
    assert_eq!(
        check_proof(&f.rel, &messages, &proof).err(),
        Some(Error::Pcs(stele_pcs::Error::Merkle(
            stele_hash::merkle::Error::RootMismatch
        )))
    );
}

#[test]
fn rejects_shifted_matmul_out_round_sum() {
    // +1 on out~(ρ) breaks the first round sum; the out-claim binding (NC-1307) is
    // relation::tests::rejects_matmul_out_claim_on_a_false_commitment.
    let (f, mut proof, messages) = honest();
    add_one(&mut proof.matmuls[0]);
    assert_eq!(
        check_proof(&f.rel, &messages, &proof).err(),
        Some(Error::Sumcheck(stele_sumcheck::Error::RoundSumMismatch))
    );
}

#[test]
fn rejects_tampered_opening_value() {
    // NC-1308 consequence: a group opening whose value is not the committed one.
    let (f, mut proof, messages) = honest();
    add_one(&mut proof.openings[0]);
    assert!(check_proof(&f.rel, &messages, &proof).is_err());
}

#[test]
fn rejects_wrapping_witness_outside_its_width() {
    // 2x = y holds mod p with x = (p+1)/2, y = 1, but x is far outside signed 8.
    let mut rel = Relation::default();
    let g = Kind::Witness(rel.add_group("G/wrap/1", 1));
    let x = rel.add_column("x", g.clone(), Width::signed(8), 1);
    let y = rel.add_column("y", g, Width::unsigned(1), 1);
    range(&mut rel, x, Width::signed(8));
    range(&mut rel, y, Width::unsigned(1));
    identity(
        &mut rel,
        "double",
        1,
        vec![(2, vec![r(x, &[0])]), (-1, vec![r(y, &[0])])],
    );
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    f.set(x, vec![(1 << 30), 0]);
    f.set(y, vec![1, 0]);
    assert!(check(&f.rel, &f.values).is_err());
    assert_eq!(
        run(&f).err(),
        Some(Error::Fraction(stele_lookup::fraction::Error::RootMismatch))
    );
}

/// Matmul section: out, then rounds of `width` values, then finals.
fn finals(section: &mut [u8], rounds: usize, width: usize) -> &mut [u8] {
    &mut section[16 * (1 + rounds * width)..]
}

#[test]
fn rejects_public_matmul_operands_scaled_against_each_other() {
    // All-public matmul: scaling the two operand finals keeps the product and no later
    // message depends on them, so only the verifier's public evaluation can reject.
    let mut rel = Relation::default();
    let lhs = rel.add_column("l", Kind::Public(vec![1, 2, 3, 4]), Width::signed(4), 2);
    let rhs = rel.add_column("r", Kind::Public(vec![2, -1]), Width::signed(4), 1);
    let out = rel.add_column("o", Kind::Public(vec![-1, 0]), Width::signed(8), 1);
    rel.matmuls.push(Matmul {
        name: "pp".into(),
        free: 1,
        summed: 1,
        out: r(out, &[0]),
        lhs: r(lhs, &[0, 1]),
        rhs: r(rhs, &[1]),
    });
    let f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    check(&f.rel, &f.values).expect("honest");
    let (mut proof, messages) = produce(&f.rel, &f.values).expect("proof");
    let two = QM31::from_i64(2);
    let fin = finals(&mut proof.matmuls[0], 1, 3);
    let (l, rr) = (k_at(fin), k_at(&fin[16..]));
    set_k(fin, l * two);
    set_k(&mut fin[16..], rr * two.inverse().expect("unit"));
    assert_eq!(
        check_proof(&f.rel, &messages, &proof).err(),
        Some(Error::PublicMismatch(lhs))
    );
}

#[test]
fn rejects_shared_bit_equality_factor_scaled() {
    let f = matmuls();
    let (mut proof, messages) = produce(&f.rel, &f.values).expect("proof");
    // Matmul "pv": shared bit h and summed k, so two rounds of 4 values (degree 3).
    let two = QM31::from_i64(2);
    let fin = finals(&mut proof.matmuls[1], 2, 4);
    let (eq, l) = (k_at(fin), k_at(&fin[16..]));
    set_k(fin, eq * two);
    set_k(&mut fin[16..], l * two.inverse().expect("unit"));
    assert_eq!(
        check_proof(&f.rel, &messages, &proof).err(),
        Some(Error::EqMismatch)
    );
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn measures_mid_size_relation() {
    for log in [12u8, 14, 16, 18] {
        let mut rel = Relation::default();
        let g = Kind::Witness(rel.add_group("G/bench", log));
        let b = rel.add_column("b", g.clone(), Width::signed(8), log);
        let c = rel.add_column("c", g.clone(), Width::signed(8), log);
        let a = rel.add_column("a", g, Width::signed(16), log);
        for (id, bits) in [(b, 8), (c, 8), (a, 16)] {
            range(&mut rel, id, Width::signed(bits));
        }
        let all: Vec<u8> = (0..log).collect();
        identity(
            &mut rel,
            "product",
            log,
            vec![(1, vec![r(a, &all)]), (-1, vec![r(b, &all), r(c, &all)])],
        );
        let mut f = Fixture {
            values: Values::new(&rel),
            rel,
        };
        let mut rng = Rng(6);
        let n = 1usize << log;
        let (bv, cv) = (rng.vec(n, Width::signed(8)), rng.vec(n, Width::signed(8)));
        f.set(a, (0..n).map(|i| bv[i] * cv[i]).collect());
        f.set(b, bv);
        f.set(c, cv);
        let start = std::time::Instant::now();
        let (proof, messages) = produce(&f.rel, &f.values).expect("proof");
        let proved = start.elapsed();
        let bytes = proof.encode();
        let start = std::time::Instant::now();
        check_proof(&f.rel, &messages, &proof).expect("verify");
        println!(
            "cells=3*2^{log} prove={proved:?} verify={:?} proof_bytes={}",
            start.elapsed(),
            bytes.len()
        );
    }
}

/// Lookup-heavy shape like a model layer: many ranged columns of a few sizes and
/// widths, plus repeated lookups into one two-column table.
fn lookup_heavy() -> Fixture {
    let mut rel = Relation::default();
    let mut rng = Rng(7);
    let mut sets: Vec<(ColumnId, Vec<i64>)> = Vec::new();
    let squares = rel.add_table(Table {
        name: "squares".into(),
        widths: vec![Width::signed(8), Width::unsigned(15)],
        rows: (-128..128).map(|v| vec![v, v * v]).collect(),
    });
    for (log, count) in [(10u8, 24usize), (8, 24), (6, 16)] {
        let g = Kind::Witness(rel.add_group(&format!("G/heavy/{log}"), log));
        let n = 1usize << log;
        for i in 0..count {
            let w = [Width::signed(8), Width::unsigned(8), Width::signed(16)][i % 3];
            let id = rel.add_column(&format!("c{log}/{i}"), g.clone(), w, log);
            range(&mut rel, id, w);
            sets.push((id, rng.vec(n, w)));
        }
        for i in 0..count / 4 {
            let x = rel.add_column(&format!("x{log}/{i}"), g.clone(), Width::signed(8), log);
            let sq = rel.add_column(&format!("s{log}/{i}"), g.clone(), Width::unsigned(15), log);
            let xv = rng.vec(n, Width::signed(8));
            let all: Vec<u8> = (0..log).collect();
            rel.lookups.push(Lookup {
                name: format!("sq{log}/{i}"),
                vars: log,
                selector: None,
                tuple: vec![r(x, &all), r(sq, &all)],
                table: squares,
            });
            sets.push((sq, xv.iter().map(|v| v * v).collect()));
            sets.push((x, xv));
        }
    }
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    for (id, v) in sets {
        f.set(id, v);
    }
    f
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn measures_lookup_heavy_relation() {
    let f = lookup_heavy();
    assert_eq!(check(&f.rel, &f.values), Ok(()));
    let start = std::time::Instant::now();
    let (proof, messages) = produce(&f.rel, &f.values).expect("proof");
    let proved = start.elapsed();
    let start = std::time::Instant::now();
    check_proof(&f.rel, &messages, &proof).expect("verify");
    let verified = start.elapsed();
    let size = |s: &Vec<Vec<u8>>| s.iter().map(Vec::len).sum::<usize>();
    println!(
        "checks={} prove={proved:?} verify={verified:?} total={} groups={} multiplicities={} ({} sources) lookups={} identities={} matmuls={} openings={}",
        f.rel.lookups.len() + f.rel.ranges.len(),
        proof.encode().len(),
        size(&proof.groups),
        size(&proof.multiplicities),
        proof.multiplicities.len(),
        size(&proof.lookups),
        size(&proof.identities),
        size(&proof.matmuls),
        size(&proof.openings),
    );
}

/// Many commitment groups, as one per (layer, module, length) in a model plan.
#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn measures_many_groups_relation() {
    let mut rel = Relation::default();
    let mut rng = Rng(8);
    let mut sets = Vec::new();
    for layer in 0..8 {
        for (module, log) in [(0u8, 6u8), (1, 8), (2, 10), (3, 8), (4, 6)] {
            let g = Kind::Witness(rel.add_group(&format!("L{layer}/m{module}/{log}"), log));
            for i in 0..6 {
                let w = [Width::signed(8), Width::signed(16)][i % 2];
                let id = rel.add_column(&format!("L{layer}/m{module}/c{i}"), g.clone(), w, log);
                range(&mut rel, id, w);
                sets.push((id, rng.vec(1 << log, w)));
            }
        }
    }
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    for (id, v) in sets {
        f.set(id, v);
    }
    let start = std::time::Instant::now();
    let (proof, messages) = produce(&f.rel, &f.values).expect("proof");
    let proved = start.elapsed();
    let start = std::time::Instant::now();
    check_proof(&f.rel, &messages, &proof).expect("verify");
    let verified = start.elapsed();
    let size = |s: &Vec<Vec<u8>>| s.iter().map(Vec::len).sum::<usize>();
    println!(
        "groups={} prove={proved:?} verify={verified:?} total={} group_certs={} ({} sections) multiplicities={} lookups={} openings={} ({} sections)",
        f.rel.groups.len(),
        proof.encode().len(),
        size(&proof.groups),
        proof.groups.len(),
        size(&proof.multiplicities),
        size(&proof.lookups),
        size(&proof.openings),
        proof.openings.len(),
    );
}

/// Many weight matrices (8 layers x 7 roles of 2^10), each read by a projection
/// matmul `Y[i, j] = Σ_k X[i, k] W[k, j]`.
#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn measures_many_weights_relation() {
    let mut rel = Relation::default();
    let mut rng = Rng(9);
    let gx = Kind::Witness(rel.add_group("G/x/6", 6));
    let gy = Kind::Witness(rel.add_group("G/y/8", 8));
    let x = rel.add_column("x", gx, Width::signed(4), 6);
    range(&mut rel, x, Width::signed(4));
    let xv = rng.vec(64, Width::signed(4));
    let mut sets = vec![(x, xv.clone())];
    for i in 0..56 {
        let w = rel.add_column(&format!("w{i}"), Kind::Weight, Width::signed(4), 10);
        range(&mut rel, w, Width::signed(4));
        let y = rel.add_column(&format!("y{i}"), gy.clone(), Width::signed(12), 8);
        // Bits: 0..6 = j, 6..8 = i (free); 8..12 = k (summed).
        rel.matmuls.push(Matmul {
            name: format!("mm{i}"),
            free: 8,
            summed: 4,
            out: r(y, &[0, 1, 2, 3, 4, 5, 6, 7]),
            lhs: r(x, &[8, 9, 10, 11, 6, 7]),
            rhs: r(w, &[0, 1, 2, 3, 4, 5, 8, 9, 10, 11]),
        });
        let wv = rng.vec(1024, Width::signed(4));
        let yv = (0..256usize)
            .map(|z| {
                let (j, ii) = (z & 63, z >> 6);
                (0..16).map(|k| xv[k | ii << 4] * wv[j | k << 6]).sum()
            })
            .collect();
        sets.push((w, wv));
        sets.push((y, yv));
    }
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    for (id, v) in sets {
        f.set(id, v);
    }
    assert_eq!(check(&f.rel, &f.values), Ok(()));
    let start = std::time::Instant::now();
    let (proof, messages) = produce(&f.rel, &f.values).expect("proof");
    let proved = start.elapsed();
    let start = std::time::Instant::now();
    check_proof(&f.rel, &messages, &proof).expect("verify");
    let verified = start.elapsed();
    let size = |s: &Vec<Vec<u8>>| s.iter().map(Vec::len).sum::<usize>();
    println!(
        "weights=56 prove={proved:?} verify={verified:?} total={} openings={} ({} sections) groups={} multiplicities={} lookups={} matmuls={}",
        proof.encode().len(),
        size(&proof.openings),
        proof.openings.len(),
        size(&proof.groups),
        size(&proof.multiplicities),
        size(&proof.lookups),
        size(&proof.matmuls),
    );
}

/// A model-shaped workload: `layers` blocks of T x d = 2^6 x 2^6 activations, each with
/// projection matmuls against 2^6 x 2^6 weights,
/// degree-2/3 identities with broadcast public scales, ranges and a table lookup.
fn model_like(layers: usize) -> Fixture {
    let mut rel = Relation::default();
    let mut rng = Rng(11);
    let mut sets: Vec<(ColumnId, Vec<i64>)> = Vec::new();
    let squares = rel.add_table(Table {
        name: "squares".into(),
        widths: vec![Width::signed(8), Width::unsigned(15)],
        rows: (-128..128).map(|v| vec![v, v * v]).collect(),
    });
    let scale = rel.add_column(
        "scale",
        Kind::Public((0..64).map(|i| i % 4 + 1).collect()),
        Width::unsigned(3),
        6,
    );
    let all12: Vec<u8> = (0..12).collect();
    let g0 = Kind::Witness(rel.add_group("G/in/12", 12));
    let x0 = rel.add_column("x0", g0, Width::signed(4), 12);
    range(&mut rel, x0, Width::signed(4));
    let mut x = (x0, rng.vec(1 << 12, Width::signed(4)));
    sets.push(x.clone());
    for layer in 0..layers {
        let g = Kind::Witness(rel.add_group(&format!("L{layer}/act/12"), 12));
        // Seven projections Y = X W (T=2^6 rows i, d=2^6 cols j, k summed over 2^6).
        let mut outs = Vec::new();
        for role in 0..7 {
            let w = rel.add_column(
                &format!("L{layer}/w{role}"),
                Kind::Weight,
                Width::signed(4),
                12,
            );
            range(&mut rel, w, Width::signed(4));
            let wv = rng.vec(1 << 12, Width::signed(4));
            let y = rel.add_column(
                &format!("L{layer}/y{role}"),
                g.clone(),
                Width::signed(14),
                12,
            );
            // Bits: 0..6 = j, 6..12 = i (free); 12..18 = k (summed).
            rel.matmuls.push(Matmul {
                name: format!("L{layer}/mm{role}"),
                free: 12,
                summed: 6,
                out: r(y, &all12),
                lhs: r(x.0, &[12, 13, 14, 15, 16, 17, 6, 7, 8, 9, 10, 11]),
                rhs: r(w, &[0, 1, 2, 3, 4, 5, 12, 13, 14, 15, 16, 17]),
            });
            let yv: Vec<i64> = (0..1usize << 12)
                .map(|z| {
                    let (j, i) = (z & 63, z >> 6);
                    (0..64).map(|k| x.1[k | i << 6] * wv[j | k << 6]).sum()
                })
                .collect();
            range(&mut rel, y, Width::signed(14));
            sets.push((w, wv));
            sets.push((y, yv.clone()));
            outs.push((y, yv));
        }
        // Identities: z = y0 * y1 (degree 2), u = y2 * scale(i) * y3 (degree 3, broadcast).
        let (y0, y1, y2, y3) = (&outs[2], &outs[3], &outs[4], &outs[5]);
        let small = |v: &[i64]| v.iter().map(|a| a.rem_euclid(16) - 8).collect::<Vec<_>>();
        let a = rel.add_column(&format!("L{layer}/a"), g.clone(), Width::signed(4), 12);
        let b = rel.add_column(&format!("L{layer}/b"), g.clone(), Width::signed(4), 12);
        let c = rel.add_column(&format!("L{layer}/c"), g.clone(), Width::signed(4), 12);
        let z = rel.add_column(&format!("L{layer}/z"), g.clone(), Width::signed(8), 12);
        let u = rel.add_column(&format!("L{layer}/u"), g.clone(), Width::signed(11), 12);
        for (col, w) in [(a, 4), (b, 4), (c, 4), (z, 8), (u, 11)] {
            range(&mut rel, col, Width::signed(w));
        }
        let (av, bv, cv) = (small(&y0.1), small(&y1.1), small(&y2.1));
        let zv: Vec<i64> = av.iter().zip(&bv).map(|(p, q)| p * q).collect();
        let uv: Vec<i64> = (0..1usize << 12)
            .map(|i| av[i] * cv[i] * ((i >> 6) as i64 % 4 + 1))
            .collect();
        identity(
            &mut rel,
            &format!("L{layer}/z"),
            12,
            vec![
                (1, vec![r(z, &all12)]),
                (-1, vec![r(a, &all12), r(b, &all12)]),
            ],
        );
        identity(
            &mut rel,
            &format!("L{layer}/u"),
            12,
            vec![
                (1, vec![r(u, &all12)]),
                (
                    -1,
                    vec![r(a, &all12), r(c, &all12), r(scale, &[6, 7, 8, 9, 10, 11])],
                ),
            ],
        );
        let sq = rel.add_column(&format!("L{layer}/sq"), g.clone(), Width::unsigned(15), 12);
        let xs = rel.add_column(&format!("L{layer}/xs"), g.clone(), Width::signed(8), 12);
        rel.lookups.push(Lookup {
            name: format!("L{layer}/sq"),
            vars: 12,
            selector: None,
            tuple: vec![r(xs, &all12), r(sq, &all12)],
            table: squares,
        });
        let xsv: Vec<i64> = y3.1.iter().map(|v| v.rem_euclid(256) - 128).collect();
        sets.push((sq, xsv.iter().map(|v| v * v).collect()));
        sets.push((xs, xsv));
        sets.extend([(a, av), (b, bv), (c, cv), (z, zv), (u, uv)]);
        // Next layer input: a 4-bit view of y6.
        let nx = rel.add_column(&format!("L{layer}/nx"), g.clone(), Width::signed(4), 12);
        range(&mut rel, nx, Width::signed(4));
        let nv: Vec<i64> = outs[6].1.iter().map(|v| v.rem_euclid(16) - 8).collect();
        sets.push((nx, nv.clone()));
        x = (nx, nv);
    }
    let mut f = Fixture {
        values: Values::new(&rel),
        rel,
    };
    for (id, v) in sets {
        f.set(id, v);
    }
    f
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn measures_model_like_relation() {
    let layers = std::env::var("STELE_LAYERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let f = model_like(layers);
    assert_eq!(check(&f.rel, &f.values), Ok(()));
    let messages = relation::model_messages(&f.rel, &f.values).expect("messages");
    let prepared = prepare(&f.rel, &messages);
    let certificates = certify(&prepared);
    let model: Vec<_> = prepared.iter().zip(&certificates).collect();
    let start = std::time::Instant::now();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let proof = relation::prove(&mut t, &f.rel, &f.values, &model).expect("proof");
    let proved = start.elapsed();
    let start = std::time::Instant::now();
    let mut t = Transcript::new(PUBLIC).expect("transcript");
    let refs: Vec<_> = certificates.iter().collect();
    relation::verify(&mut t, &f.rel, &refs, &proof).expect("verify");
    let verified = start.elapsed();
    let bytes = proof.encode();
    println!(
        "layers={layers} matmuls={} prove={proved:?} verify={verified:?} proof_bytes={} digest={}",
        f.rel.matmuls.len(),
        bytes.len(),
        blake3_hex(&bytes)
    );
}

fn blake3_hex(bytes: &[u8]) -> String {
    // Identity check across prover changes: proof bytes must not move.
    let mut t = Transcript::<QM31>::new(bytes).expect("transcript");
    let k: QM31 = t
        .challenge(stele_hash::ChallengeLabel::Sumcheck)
        .expect("digest");
    k.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
