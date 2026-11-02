//! RFC-0024 §5: serialize actual closed obligations for independent comparison.
use crate::records::{self, fields, opening, sc};
use serde_json::{json, Value};
use stele_hash::ChallengeField;
use stele_reductions::integer_linear as linear;

pub(crate) fn record<K: ChallengeField>(record: &linear::Record<'_, K>) -> Value {
    let zero = record.zerocheck();
    let zero_sc: Vec<_> = zero
        .sc
        .iter()
        .enumerate()
        .map(|(phase, r)| {
            let mut v = sc(r);
            v["phase"] = json!(phase);
            v
        })
        .collect();
    let output = record.output();
    let equality = record.point_equality();
    let mm = record.matmul();
    json!({"lookup":records::lookup(record.lookup()),
        "zero":{"claims":zero.claims.iter().map(|c|json!([c.tensor,fields(&c.point),fields(&[c.value])[0]])).collect::<Vec<_>>(),"sc":zero_sc},
        "output":{"point":fields(&output.point),"claims":output.claims.iter().map(|(id,v)|json!([id,fields(&[*v])[0]])).collect::<Vec<_>>(),"sc":sc(&output.sc)},
        "groups":record.groups().iter().map(|g|json!({"point":fields(g.point()),"claims":g.claims().iter().map(|(r,id,v)|json!([r,id,fields(&[*v])[0]])).collect::<Vec<_>>(),"opening":opening(g.opening())})).collect::<Vec<_>>(),
        "rlc":record.rlc().iter().map(|r|json!({"stage":r.stage(),"phase":r.phase(),"field_degree":r.field_degree(),"count":r.weights().len(),"numerator":r.numerator(),"weights":fields(r.weights())})).collect::<Vec<_>>(),
        "equality":{"stage":equality.stage(),"aggregate_id":equality.aggregate_id(),"point":fields(equality.point()),"field_degree":equality.field_degree(),"numerator":equality.numerator(),"family":format!("{:?}",equality.family())},
        "matmul":{"sc":sc(mm.sc()),"openings":mm.openings().iter().map(opening).collect::<Vec<_>>(),"points":mm.points().map(fields),"values":fields(mm.values())}})
}
