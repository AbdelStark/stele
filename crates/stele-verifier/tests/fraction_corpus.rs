//! E8-02e parity: the independent fraction tree and selected-product leaf against
//! `research/logup-characteristic/corpus.jsonl` (162 cases, QM31 and OM31). Every
//! case must give the production decision recorded in `corpus-receipts.jsonl`, which
//! the fraction gate checks against the production output. Accepted cases must also
//! give the same point, claims, layer records and continuation, plus the leaf's point,
//! claims and record.
//!
//! The leaf is also run without the tree's leaf consumer, which would otherwise catch a
//! forged leaf claim first. On every accepted leaf case it gives the same result, and
//! the shifted claim `(p + 1, q + α − 1)`, which leaves the leaf's sum unchanged, is
//! refused by the leaf's own selector check.
use serde_json::{json, Value};
use stele_field::{OM31, QM31};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_verifier::fraction::{
    consume, consume_sources, decode_leaf, root_equation, verify, verify_leaf, Descriptor, Proof,
};

/// How a case is run: as the production adapter does, or with the tree's leaf
/// consumer (and root equation) skipped, optionally with the leaf claim shifted.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Full,
    LeafOnly,
    Shifted,
}

const CORPUS: &str = include_str!("../../../research/logup-characteristic/corpus.jsonl");
const RECEIPTS: &str = include_str!("../../../research/logup-characteristic/corpus-receipts.jsonl");

fn raw(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// One K value; a wrong length or a limb ≥ p is NoncanonicalField (as the adapter).
fn value<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let bytes = raw(v);
    let b = K::Bytes::try_from(bytes.as_slice()).map_err(|_| "NoncanonicalField")?;
    K::from_le_bytes(b).ok_or_else(|| "NoncanonicalField".into())
}

/// Rows of the given counts: the total length first (ProofShape), then the limbs.
fn rows<K: ChallengeField>(v: &Value, counts: &[usize]) -> Result<Vec<Vec<K>>, String>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let bytes = raw(v);
    let width = 4 * K::DEGREE;
    if bytes.len() != width * counts.iter().sum::<usize>() {
        return Err("ProofShape".into());
    }
    let mut out = Vec::new();
    let mut at = 0;
    for count in counts {
        let mut row = Vec::new();
        for _ in 0..*count {
            let b = K::Bytes::try_from(&bytes[at..at + width]).map_err(|_| "ProofShape")?;
            row.push(K::from_le_bytes(b).ok_or("NoncanonicalField")?);
            at += width;
        }
        out.push(row);
    }
    Ok(out)
}

fn hex<K: ChallengeField>(v: &K) -> String {
    v.to_le_bytes()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The innermost variant name of an error's debug form.
fn name(e: impl core::fmt::Debug) -> String {
    let s = format!("{e:?}");
    let inner = s.trim_end_matches(')');
    inner.rsplit('(').next().unwrap_or(inner).to_string()
}

fn record(r: &stele_verifier::sumcheck::ScRecord) -> Value {
    json!({"id": r.id, "m": r.m, "degree": r.degree, "field_degree": r.field_degree, "numerator": r.numerator})
}

fn check<K: ChallengeField + Eq>(c: &Value, mode: Mode) -> Result<Value, String>
where
    K::Bytes: for<'a> TryFrom<&'a [u8]>,
{
    let s = &c["descriptor"];
    let theta = s["theta"]
        .as_array()
        .expect("theta")
        .iter()
        .map(value::<K>)
        .collect::<Result<Vec<_>, _>>()?;
    let d = Descriptor {
        id: s["id"].as_u64().expect("id"),
        m: s["m"].as_u64().expect("m") as u32,
        b: s["b"].as_u64().expect("b") as u32,
        leaves: [
            s["leaves"][0].as_u64().expect("leaf"),
            s["leaves"][1].as_u64().expect("leaf"),
        ],
        theta,
    };
    d.encode().map_err(name)?;
    let leaves = c["leaves"]
        .as_array()
        .expect("leaves")
        .iter()
        .map(|row| Ok([value::<K>(&row[0])?, value::<K>(&row[1])?]))
        .collect::<Result<Vec<_>, String>>()?;
    let m = d.m as usize;
    let mut counts = vec![2];
    for k in 0..m {
        counts.extend(std::iter::repeat_n(4, k));
        counts.push(5);
    }
    rows::<K>(&c["tree"], &counts)?;
    let proof = Proof::decode(&d, &raw(&c["tree"])).map_err(name)?;
    let mut t = Transcript::<K>::new(&raw(&c["public"])).map_err(name)?;
    let mut tree = verify(&mut t, &d, &proof).map_err(name)?;
    if mode == Mode::Full {
        consume(&tree, &leaves).map_err(name)?;
    }
    if let (Some(right), Mode::Full) = (c.get("right"), mode) {
        root_equation(proof.root, [value::<K>(&right[0])?, value::<K>(&right[1])?])
            .map_err(name)?;
    }
    let mut out = json!({"tree": {
        "point": tree.point.iter().map(hex).collect::<Vec<_>>(),
        "claims": [[tree.ids[0], hex(&tree.values[0])], [tree.ids[1], hex(&tree.values[1])]],
        "accounting": {"tree_id": d.id, "field_degree": K::DEGREE, "gamma": m, "fold": m,
                       "layers": tree.layers.iter().map(record).collect::<Vec<_>>()},
        "numerator": 3 * m * m.saturating_sub(1) / 2 + 2 * m,
    }});
    if let Some(leaf) = c.get("leaf") {
        let ids: Vec<u64> = leaf["sources"]
            .as_array()
            .expect("ids")
            .iter()
            .map(|i| i.as_u64().expect("id"))
            .collect();
        let sigma = leaf["sigma"]
            .as_array()
            .expect("sigma")
            .iter()
            .map(value::<K>)
            .collect::<Result<Vec<_>, _>>()?;
        let xs = leaf["xs"]
            .as_array()
            .expect("xs")
            .iter()
            .map(|col| {
                col.as_array()
                    .expect("col")
                    .iter()
                    .map(value::<K>)
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (alpha, beta) = (value::<K>(&leaf["alpha"])?, value::<K>(&leaf["beta"])?);
        let selected = decode_leaf(&d, ids.len(), &raw(&leaf["proof"])).map_err(name)?;
        if mode == Mode::Shifted {
            // (p + δ, q + (α − 1)δ) keeps H = 1 + (α − 1)p − q.
            let one = K::from_i64(1);
            tree.values = [tree.values[0] + one, tree.values[1] + alpha - one];
        }
        let result =
            verify_leaf(&mut t, &d, &tree, &sigma, &ids, &selected, alpha, beta).map_err(name)?;
        consume_sources(&result, &ids, &xs).map_err(name)?;
        out["leaf"] = json!({
            "tree_id": d.id,
            "point": result.point.iter().map(hex).collect::<Vec<_>>(),
            "claims": result.claims.iter().map(|(i, v)| json!([i, hex(v)])).collect::<Vec<_>>(),
            "sc": record(&result.sc),
        });
    }
    out["continuation"] = json!(hex(&t.challenge(ChallengeLabel::Sumcheck).map_err(name)?));
    Ok(out)
}

fn run(c: &Value, mode: Mode) -> Result<Value, String> {
    match c["degree"].as_u64() {
        Some(4) => check::<QM31>(c, mode),
        Some(8) => check::<OM31>(c, mode),
        _ => Err("Field".into()),
    }
}

/// The leaf without the tree's consumer: the same result on every accepted leaf case,
/// and SelectorMismatch for the shifted claim.
#[test]
fn rejects_shifted_leaf_claims_without_the_leaf_consumer() {
    let mut checked = 0;
    for line in CORPUS.lines() {
        let c: Value = serde_json::from_str(line).expect("case");
        if c.get("leaf").is_none() || c["expected"] != "accept" {
            continue;
        }
        assert_eq!(
            run(&c, Mode::LeafOnly),
            run(&c, Mode::Full),
            "case {}",
            c["name"]
        );
        assert_eq!(
            run(&c, Mode::Shifted),
            Err("SelectorMismatch".into()),
            "case {}",
            c["name"]
        );
        checked += 1;
    }
    assert!(checked > 0);
    println!("{checked} accepted leaf cases");
}

#[test]
fn matches_reference_fraction_corpus_decisions_and_receipts() {
    let (cases, recorded): (Vec<&str>, Vec<&str>) =
        (CORPUS.lines().collect(), RECEIPTS.lines().collect());
    assert_eq!((cases.len(), recorded.len()), (162, 162));
    let mut accepted = 0;
    for (line, expected) in cases.iter().zip(&recorded) {
        let c: Value = serde_json::from_str(line).expect("case");
        let expected: Value = serde_json::from_str(expected).expect("receipt");
        let result = run(&c, Mode::Full);
        let mut output = result.unwrap_or_else(|error| json!({ "error": error }));
        output["name"] = c["name"].clone();
        assert_eq!(output, expected, "case {}", c["name"]);
        let decision = output
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("accept");
        assert_eq!(decision, c["expected"].as_str().expect("expected"));
        accepted += usize::from(decision == "accept");
    }
    assert_eq!(accepted, 28);
}
