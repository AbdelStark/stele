//! Greedy argmax tests: executor-equivalent honest rows, near misses, attacker
//! assignments against each removed constraint, static shapes.

use super::*;
use stele_ir::relation::check;

/// The executor's greedy choice (stele-cqis execution/forward.rs `finish`,
/// decoding.rs `choose`) restated: the first index of the maximum.
fn greedy(row: &[i16]) -> usize {
    let maximum = row.iter().max().expect("nonempty");
    row.iter().position(|v| v == maximum).expect("attained")
}

struct Case {
    relation: Relation,
    values: Values,
    module: Argmax,
    rows: Vec<Vec<i16>>,
}

/// Declare the int16 logits column (padding 0, as the head pins it) and the module,
/// and assign both.
fn case(rows: &[Vec<i16>], tokens: &[u32], range: (usize, usize), next: Option<u32>) -> Case {
    let vocabulary = rows[0].len();
    let mut relation = Relation::default();
    let v = log2_ceil(vocabulary);
    let n = log2_ceil(rows.len()) + v;
    let group = relation.add_group("G/projection/test", n);
    let logits = relation.add_column("logits", Kind::Witness(group), Width::signed(16), n);
    relation.ranges.push(Range {
        name: "logits".into(),
        column: logits,
        width: Width::signed(16),
    });
    let mut module = Argmax::new(logits, tokens, range, next, vocabulary).expect("plan");
    module.declare(&mut relation);
    let mut values = Values::new(&relation);
    let mut padded = vec![0; 1 << n];
    for (i, row) in rows.iter().enumerate() {
        for (id, l) in row.iter().enumerate() {
            padded[(i << v) | id] = i64::from(*l);
        }
    }
    values.set(&relation, logits, padded).expect("logits");
    module.assign(&relation, rows, &mut values).expect("assign");
    Case {
        relation,
        values,
        module,
        rows: rows.to_vec(),
    }
}

/// Tokens whose checked choices are the greedy ones; `y` when `e = T`.
fn statement(rows: &[Vec<i16>], (r, e): (usize, usize)) -> (Vec<u32>, Option<u32>) {
    let t = rows.len();
    let mut tokens = vec![0u32; t];
    for i in r..e.min(t - 1) {
        tokens[i + 1] = greedy(&rows[i]) as u32;
    }
    (tokens, (e == t).then(|| greedy(&rows[t - 1]) as u32))
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// Logit rows with ties (small range), all-negative rows and int16 endpoints.
    fn rows(&mut self, t: usize, vocabulary: usize) -> Vec<Vec<i16>> {
        (0..t)
            .map(|i| {
                (0..vocabulary)
                    .map(|_| match (i % 4, self.next() % 8) {
                        (0, _) => (self.next() % 5) as i16 - 2,
                        (1, _) => -1 - (self.next() % 300) as i16,
                        (2, 0) => i16::MAX,
                        (2, 1) => i16::MIN,
                        _ => self.next() as i16,
                    })
                    .collect()
            })
            .collect()
    }
}

#[test]
fn matches_reference_greedy_rows() {
    let mut rng = Rng(0x0e16_0913);
    for (t, vocabulary) in [(4, 8), (4, 5), (3, 1), (8, 33), (2, 40000)] {
        for range in [(0, t), (0, 1), (1, t - 1), (t - 1, t)] {
            if range.0 >= range.1 {
                continue;
            }
            let rows = rng.rows(t, vocabulary);
            let (tokens, next) = statement(&rows, range);
            let case = case(&rows, &tokens, range, next);
            check(&case.relation, &case.values).expect("greedy choices pass");
        }
    }
}

/// Every checked row of `tokens` replaced by `c` at row `i` (as `x_{i+1}` or `y`).
fn claim(tokens: &[u32], next: Option<u32>, i: usize, c: u32) -> (Vec<u32>, Option<u32>) {
    let (mut tokens, mut next) = (tokens.to_vec(), next);
    if i + 1 < tokens.len() {
        tokens[i + 1] = c;
    } else {
        next = Some(c);
    }
    (tokens, next)
}

/// Attacker assignments for a false claim: the honest `sel` with every margin clamped
/// into range, and `sel` raised to the row maximum (blocks consistent) with the margin
/// re-solved.
fn false_claims(case: &Case) -> Vec<(&'static str, Values)> {
    let c = case.module.columns().expect("declared");
    let (_, v, nb) = case.module.bits();
    let vb = v - nb;
    let mut out = Vec::new();
    let honest = |id| {
        case.values
            .get(&case.relation, id)
            .expect("column")
            .to_vec()
    };
    let mut clamped = case.values.clone();
    let margin: Vec<_> = honest(c.margin)
        .iter()
        .map(|m| m.clamp(&0, &65535))
        .copied()
        .collect();
    clamped.set(&case.relation, c.margin, margin).expect("set");
    out.push(("margin", clamped));
    for (raise_blocks, name) in [(true, "select"), (false, "blocks")] {
        if !raise_blocks && c.blocks.is_none() {
            continue;
        }
        let (mut sel, mut blocks, mut margin) =
            (honest(c.selected), c.blocks.map(honest), honest(c.margin));
        for (i, choice) in case.module.choices.iter().enumerate() {
            let Some(choice) = *choice else { continue };
            let row = &case.rows[i];
            let max = i64::from(*row.iter().max().expect("row"));
            sel[i] = max;
            if let (true, Some(blocks)) = (raise_blocks, blocks.as_mut()) {
                blocks[(i << nb) | (choice >> vb)] = max;
            }
            for (id, l) in row.iter().enumerate() {
                margin[(i << v) | id] = max - i64::from(*l) - i64::from(id < choice);
            }
        }
        let mut values = case.values.clone();
        values.set(&case.relation, c.selected, sel).expect("set");
        if let (Some(id), Some(blocks)) = (c.blocks, blocks) {
            values.set(&case.relation, id, blocks).expect("set");
        }
        values.set(&case.relation, c.margin, margin).expect("set");
        out.push((name, values));
    }
    out
}

/// One row of distinct-ish logits, maximum attained only at `late`, and ties at
/// `early < late` for the second-largest value.
fn row(vocabulary: usize, late: usize) -> Vec<i16> {
    let mut row: Vec<i16> = (0..vocabulary).map(|v| -((v % 50) as i16)).collect();
    row[late] = 100;
    row
}

#[test]
fn rejects_non_maximal_token() {
    for vocabulary in [8, 40000] {
        let rows = vec![row(vocabulary, 5), row(vocabulary, 6)];
        let (tokens, next) = statement(&rows, (0, 2));
        for (i, wrong) in [(0, 4u32), (0, 7), (1, 0), (1, 5)] {
            let (tokens, next) = claim(&tokens, next, i, wrong);
            let case = case(&rows, &tokens, (0, 2), next);
            assert!(matches!(
                check(&case.relation, &case.values),
                Err(Violation::Range { .. })
            ));
            for (name, values) in false_claims(&case) {
                assert!(check(&case.relation, &values).is_err(), "{name}");
            }
        }
    }
}

#[test]
fn rejects_later_index_among_ties() {
    // Maximum 7 attained at ids 2, 3 and 6: only 2 is greedy.
    let rows = vec![vec![1, 0, 7, 7, -3, 0, 7, 5]];
    let case_for = |c: u32| case(&rows, &[0], (0, 1), Some(c));
    check(&case_for(2).relation, &case_for(2).values).expect("least id");
    for later in [3, 6] {
        let case = case_for(later);
        assert!(check(&case.relation, &case.values).is_err());
        for (name, values) in false_claims(&case) {
            assert!(check(&case.relation, &values).is_err(), "{name}");
        }
    }
}

/// A padded id is never a choice: the statement is rejected before any relation, and
/// padded logits (0 here, above every real logit) never compete.
#[test]
fn rejects_padded_vocabulary_id() {
    let rows = vec![vec![-5, -1, -9, -2, -4]];
    for padded in [5, 6, 7] {
        assert!(Argmax::new(ColumnId(0), &[0], (0, 1), Some(padded), 5).is_err());
    }
    let case = case(&rows, &[0], (0, 1), Some(1));
    check(&case.relation, &case.values).expect("real greedy id beside larger padding");
}

/// Unchecked rows: a nonzero margin there is rejected, and their tokens are not
/// constrained (outside `[r, e)` the statement claims nothing).
#[test]
fn rejects_unchecked_row_margin() {
    let mut rng = Rng(9);
    let rows = rng.rows(4, 8);
    let (tokens, next) = statement(&rows, (1, 3));
    let case = case(&rows, &tokens, (1, 3), next);
    check(&case.relation, &case.values).expect("honest");
    let margin = case.module.columns().expect("declared").margin;
    for index in [0, 7, 3 << 3, (3 << 3) + 5] {
        let mut values = case.values.clone();
        let mut column = values.get(&case.relation, margin).expect("margin").to_vec();
        column[index] = 1;
        values.set(&case.relation, margin, column).expect("set");
        assert!(check(&case.relation, &values).is_err());
    }
    let (other, _) = claim(&tokens, next, 0, (greedy(&rows[0]) as u32 + 1) % 8);
    let unchecked = self::case(&rows, &other, (1, 3), next);
    check(&unchecked.relation, &unchecked.values).expect("row 0 is not checked");
}

/// The head of every family-1 fixture, from `Executor::capture`: the executor's
/// logits with its recorded greedy choices pass on every checked range; any other
/// claimed token on a checked row is rejected.
#[test]
fn matches_executor_capture_fixtures() {
    for crate::residual::tests::Fixture {
        model,
        capture,
        tokens,
        ..
    } in crate::residual::tests::executor_captures()
    {
        let t = tokens.len();
        let rows: Vec<Vec<i16>> = capture
            .head
            .iter()
            .map(|h| {
                h.logits
                    .output
                    .quotient
                    .iter()
                    .map(|v| i16::try_from(*v).expect("int16 logit"))
                    .collect()
            })
            .collect();
        assert_eq!(rows.len(), t);
        assert_eq!(rows[0].len(), model.shape().vocabulary() as usize);
        for (head, row) in capture.head.iter().zip(&rows) {
            assert_eq!(head.argmax as usize, greedy(row), "executor greedy rule");
        }
        let mut claimed = vec![0u32; t];
        for i in 0..t - 1 {
            claimed[i + 1] = capture.head[i].argmax;
        }
        let next = Some(capture.head[t - 1].argmax);
        let case = case(&rows, &claimed, (0, t), next);
        check(&case.relation, &case.values).expect("executor greedy choices pass");
        for i in 0..t {
            for wrong in 0..rows[0].len() as u32 {
                if wrong == capture.head[i].argmax {
                    continue;
                }
                let (claimed, next) = claim(&claimed, next, i, wrong);
                let case = self::case(&rows, &claimed, (0, t), next);
                assert!(
                    check(&case.relation, &case.values).is_err(),
                    "row {i} id {wrong}"
                );
            }
        }
    }
}

#[test]
fn rejects_bad_statement() {
    let tokens = [1, 2, 3, 4];
    for (range, next) in [
        ((0, 0), None),
        ((2, 1), None),
        ((0, 5), Some(0)),
        ((0, 4), None),
        ((0, 3), Some(1)),
    ] {
        assert!(Argmax::new(ColumnId(0), &tokens, range, next, 8).is_err());
    }
    assert!(Argmax::new(ColumnId(0), &[9, 9], (0, 1), None, 8).is_err());
}

/// Ranges no witness can break alone over Z, and why. Each still disciplines its
/// column (RFC-0026 §3.6 item 3), so the matmul and identity bounds hold in the field.
fn redundant(label: &str) -> Option<&'static str> {
    Some(match label {
        "selected" => {
            "sel = Σ_b sel_b (or the select matmul) of one-hot × int16 rows: exactly one logit or 0"
        }
        "blocks" => "sel_b = Σ O·L over one block: the one-hot row picks at most one int16 logit",
        _ => return None,
    })
}

/// RFC-0026 §5.2 deletion survey: for every identity, matmul and range of the module,
/// an attacker witness of a false claim that `check` rejects and that breaks only that
/// constraint (so `check_except([name])` accepts it), or a reason from [`redundant`].
#[test]
fn rejects_each_constraint_removed() {
    use stele_ir::relation::check_except;
    for vocabulary in [8, 40000] {
        // Row 0 claims an id below the late maximum.
        let rows = vec![row(vocabulary, 6), row(vocabulary, 3)];
        let (tokens, next) = statement(&rows, (0, 2));
        let (tokens, next) = claim(&tokens, next, 0, 4);
        let case = case(&rows, &tokens, (0, 2), next);
        // The honest-formula assignment of the false claim breaks the margin range.
        let mut attacks = vec![("margin", case.values.clone())];
        attacks.extend(false_claims(&case));
        for (name, values) in &attacks {
            assert!(check(&case.relation, values).is_err(), "{name}");
        }
        let names = case
            .relation
            .identities
            .iter()
            .map(|i| &i.name)
            .chain(case.relation.matmuls.iter().map(|m| &m.name))
            .chain(case.relation.ranges.iter().map(|r| &r.name))
            .filter(|n| n.starts_with(NAME));
        for name in names {
            let label = &name[NAME.len() + 1..];
            let alone = attacks
                .iter()
                .any(|(_, values)| check_except(&case.relation, values, &[name]).is_ok());
            assert!(
                alone != redundant(label).is_some(),
                "{name}: witness {alone}, reason {:?}",
                redundant(label)
            );
        }
        // Widen-by-one-bit: a false claim accepted at the wider width, or a reason.
        for (index, range) in case.relation.ranges.iter().enumerate() {
            let Some(label) = range.name.strip_prefix(&format!("{NAME}/")) else {
                continue;
            };
            let widths = if range.width.signed {
                vec![Width::signed(range.width.bits + 1)]
            } else {
                vec![
                    Width::unsigned(range.width.bits + 1),
                    Width::signed(range.width.bits + 1),
                ]
            };
            for width in widths {
                let accepted = attacks.iter().any(|(_, v)| {
                    crate::residual::tests::accepts_widened(&case.relation, v, index, width)
                });
                let reason = widen_reason(label, width);
                assert!(
                    accepted != reason.is_some(),
                    "{label} {width:?}: false claim accepted {accepted}, reason {reason:?}"
                );
            }
        }
    }
}

/// Why widening a range by one bit admits no false claim; `None` when one must.
fn widen_reason(label: &str, width: Width) -> Option<&'static str> {
    Some(match (label, width.signed) {
        ("selected" | "blocks", _) => {
            "an exact matmul of a one-hot row and int16 logits is one logit or 0 at any width"
        }
        ("margin", false) => {
            "Mg = chk·(sel − L) − lt <= 65535 for int16 logits; only Mg >= 0 carries the check"
        }
        _ => return None,
    })
}

/// E16-10 shapes: T = 64 and 128 at a 32000-id vocabulary (one selection matmul), and
/// a 128256-id vocabulary (four blocks of `2^15`).
#[test]
fn accepts_static_validity_realistic_shapes() {
    for (t, vocabulary) in [(64usize, 32000usize), (128, 32000), (8, 128256)] {
        let mut relation = Relation::default();
        let n = log2_ceil(t) + log2_ceil(vocabulary);
        let group = relation.add_group("G/projection/test", n);
        let logits = relation.add_column("logits", Kind::Witness(group), Width::signed(16), n);
        relation.ranges.push(Range {
            name: "logits".into(),
            column: logits,
            width: Width::signed(16),
        });
        let tokens = vec![7u32; t];
        let mut module = Argmax::new(logits, &tokens, (0, t), Some(1), vocabulary).expect("plan");
        module.declare(&mut relation);
        relation.validate().expect("valid");
        assert_eq!(
            relation.matmuls.len(),
            if vocabulary > 1 << 15 { 2 } else { 1 }
        );
    }
}
