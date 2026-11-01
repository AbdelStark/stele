//! RFC-0006 A4: fixture adapter for actual native public proofs, never a core parser.
use serde_json::{json, Value};
use std::io::{self, BufRead};
use stele_field::{M31, OM31, QM31};
use stele_gkr::{
    public_mle::{Axis, Kind},
    stacked::{self, Claim, Limits, Order, Prepared, Statement},
};
use stele_hash::{ChallengeField, ChallengeLabel, Transcript};
use stele_sumcheck::{Proof, Term};

fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or("InvalidStacked".into())
}
fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or("InvalidStacked".into())
}
fn field<K: ChallengeField>(v: &Value) -> Result<K, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let mut bytes = Vec::new();
    for limb in array(v)? {
        let n = u32::try_from(number(limb)?).map_err(|_| "NoncanonicalField")?;
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    K::from_le_bytes(bytes.try_into().map_err(|_| "NoncanonicalField")?)
        .ok_or("NoncanonicalField".into())
}
fn fields<K: ChallengeField>(v: &Value) -> Result<Vec<K>, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    array(v)?.iter().map(field::<K>).collect()
}
fn axes(v: &Value) -> Result<Vec<Axis>, String> {
    array(v)?
        .iter()
        .map(|a| {
            Ok(Axis {
                bits: number(&a[0])?.try_into().map_err(|_| "InvalidStacked")?,
                real: number(&a[1])?,
            })
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn wire<K: ChallengeField>(p: &Proof<K>, id: u64, count: usize) -> Vec<String> {
    let mut result: Vec<_> = p
        .rounds
        .iter()
        .enumerate()
        .map(|(r, row)| hex(&stele_sumcheck::message_bytes(id, r as u32, row).expect("round")))
        .collect();
    result.push(hex(&stele_sumcheck::message_bytes(
        id,
        count as u32,
        &p.final_values,
    )
    .expect("final")));
    result
}
fn check<K: ChallengeField + Eq + core::fmt::Debug>(case: &Value) -> Result<Value, String>
where
    K::Bytes: TryFrom<Vec<u8>>,
{
    let s = &case["statement"];
    let c = &s["coefficient"];
    let o = &s["output"];
    let layout = axes(&s["layout"])?;
    let output_layout = axes(&o["layout"])?;
    let output_point = fields::<K>(&o["point"])?;
    let inputs: Vec<_> = array(&s["inputs"])?
        .iter()
        .map(number)
        .collect::<Result<_, _>>()?;
    let terms: Vec<_> = array(&s["terms"])?
        .iter()
        .map(|t| {
            Ok(Term {
                coefficient: field::<K>(&t[0])?,
                factors: array(&t[1])?
                    .iter()
                    .map(|v| number(v)?.try_into().map_err(|_| "InvalidStacked".into()))
                    .collect::<Result<_, String>>()?,
            })
        })
        .collect::<Result<_, String>>()?;
    let selector_values: Vec<Option<Vec<K>>> = array(&c["selectors"])?
        .iter()
        .map(|v| {
            if v.is_null() {
                Ok(None)
            } else {
                fields(v).map(Some)
            }
        })
        .collect::<Result<_, _>>()?;
    let selectors: Vec<_> = selector_values.iter().map(|v| v.as_deref()).collect();
    let chosen: Vec<usize> = array(&c["axes"])?
        .iter()
        .map(|v| number(v)?.try_into().map_err(|_| "InvalidStacked".into()))
        .collect::<Result<_, String>>()?;
    let values: Vec<_> = array(&c["values"])?
        .iter()
        .map(number)
        .collect::<Result<_, _>>()?;
    let base_values: Vec<_> = if number(&c["kind"])? == 5 {
        values
            .iter()
            .map(|v| {
                u32::try_from(*v)
                    .ok()
                    .and_then(M31::from_canonical)
                    .ok_or("NoncanonicalField".into())
            })
            .collect::<Result<_, String>>()?
    } else {
        vec![]
    };
    let pair = || -> Result<(usize, usize), String> {
        if chosen.len() != 2 {
            Err("InvalidStacked".into())
        } else {
            Ok((chosen[0], chosen[1]))
        }
    };
    let kind = match number(&c["kind"])? {
        0 => Kind::Eq,
        1 => {
            let (row, column) = pair()?;
            Kind::CausalMask { row, column }
        }
        2 => {
            let (row, column) = pair()?;
            Kind::WindowMask {
                row,
                column,
                width: number(&c["width"])?,
            }
        }
        3 => {
            let (row, column) = pair()?;
            Kind::OnehotSparse {
                row,
                column,
                indices: &values,
            }
        }
        4 => {
            let (head, group) = pair()?;
            Kind::GqaBroadcast { head, group }
        }
        5 => Kind::RopeTables {
            axes: &chosen,
            values: &base_values,
        },
        _ => return Err("InvalidStacked".into()),
    };
    let statement = Statement {
        id: number(&s["id"])?,
        axes: &layout,
        order: match number(&s["order"])? {
            0 => Order::LayerFirst,
            1 => Order::LayerLast,
            _ => return Err("InvalidStacked".into()),
        },
        output: Claim {
            id: number(&o["id"])?,
            axes: &output_layout,
            point: &output_point,
            value: field(&o["value"])?,
        },
        coefficient_id: number(&s["coefficient_id"])?,
        inputs: &inputs,
        terms: &terms,
        selectors: &selectors,
        kind,
        source_id: if c["source_id"].is_null() {
            None
        } else {
            Some(number(&c["source_id"])?)
        },
    };
    let owned: Vec<Vec<K>> = array(&case["tables"])?
        .iter()
        .map(fields::<K>)
        .collect::<Result<_, _>>()?;
    let tables: Vec<_> = owned.iter().map(Vec::as_slice).collect();
    let proof = Proof {
        rounds: array(&case["proof"]["rounds"])?
            .iter()
            .map(fields::<K>)
            .collect::<Result<_, _>>()?,
        final_values: fields(&case["proof"]["final"])?,
    };
    let limits = Limits {
        descriptor_bytes: 1 << 20,
        proof_bytes: 1 << 20,
        prepared_entries: 1 << 16,
        partial_entries: 1 << 12,
        axis_entries: 1 << 12,
    };
    let mut verifier = Transcript::new(b"stacked wire oracle").expect("public input");
    let (record, usage) =
        match stacked::verify_public(&mut verifier, &statement, &proof, &tables, limits) {
            Ok(value) => value,
            Err(failure) => return Ok(json!({"decision":format!("{:?}",failure.cause)})),
        };
    let mut prover = Transcript::new(b"stacked wire oracle").expect("public input");
    let native = stacked::prove_public(&mut prover, &statement, &tables, limits)
        .map_err(|e| format!("native producer: {e:?}"))?;
    assert_eq!(native, proof);
    assert_eq!(prover.usage(), usage);
    let next = verifier
        .challenge(ChallengeLabel::Sumcheck)
        .expect("continuation");
    assert_eq!(
        next,
        prover
            .challenge(ChallengeLabel::Sumcheck)
            .expect("continuation")
    );
    let prepared = Prepared::new(&statement, limits).map_err(|e| format!("{e:?}"))?;
    let sc = record.sc();
    Ok(
        json!({"decision":"accept","stack":hex(prepared.bytes()),"sources":hex(&prepared.source_bytes(&tables).expect("public sources")),"instance":hex(&prepared.instance().encode().expect("A1 descriptor")),
        "proof":wire(&native,statement.id,inputs.len()+1),"point":record.point().iter().map(|x|hex(x.to_le_bytes().as_ref())).collect::<Vec<_>>(),
        "claims":record.claims().iter().map(|(id,x)|json!([id,hex(x.to_le_bytes().as_ref())])).collect::<Vec<_>>(),
        "sc":{"id":sc.id,"m":sc.m,"degree":sc.degree,"field_degree":sc.field_degree,"numerator":sc.numerator},"continuation":hex(next.to_le_bytes().as_ref())}),
    )
}
fn main() {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line.expect("line")).expect("fixture JSON");
        let result = match value["statement"]["field"].as_u64() {
            Some(4) => check::<QM31>(&value),
            Some(8) => check::<OM31>(&value),
            _ => Err("InvalidStacked".into()),
        };
        println!("{}", result.expect("valid corpus adapter"));
    }
}
