//! Canonical relation encoding and statement digest (RFC-0026 §4 step 1).
//!
//! Every field of the relation is written in declaration order with fixed-width
//! little-endian integers and u32 length prefixes, so the bytes are a function of
//! the plan alone. The digest is BLAKE3 of these bytes.
use alloc::vec::Vec;
use stele_ir::relation::{Def, Kind, Ref, Relation, Width};

const MAGIC: &[u8] = b"stele/v0.1/relation/encoding/v1";
const MAGIC_V2: &[u8] = b"stele/v0.1/relation/encoding/v2";
/// RFC-0026 A31: closes the encoding of a relation whose weight widths its passport carries.
const PASSPORT_WEIGHTS: &[u8] = b"stele/v0.1/relation/passport-weights";

fn u32_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_le_bytes());
}
fn name(out: &mut Vec<u8>, name: &str) {
    u32_len(out, name.len());
    out.extend_from_slice(name.as_bytes());
}
fn width(out: &mut Vec<u8>, w: Width) {
    out.extend_from_slice(&[u8::from(w.signed), w.bits]);
}
fn reference(out: &mut Vec<u8>, r: &Ref) {
    out.extend_from_slice(&r.column.0.to_le_bytes());
    out.push(r.vars.len() as u8);
    out.extend_from_slice(&r.vars);
}

/// Canonical bytes of a relation; prover and verifier derive them from the plan.
/// Unsegmented relations without virtual columns keep `stele/v0.1/relation/encoding/v1`
/// unchanged; segmented or virtual relations emit `stele/v0.1/relation/encoding/v2`
/// (RFC-0026 A27 §2, RFC-0028 §2.1).
pub fn encode(relation: &Relation) -> Vec<u8> {
    let v2 = relation.is_segmented() || relation.has_virtual();
    let mut out = Vec::new();
    out.extend_from_slice(if v2 { MAGIC_V2 } else { MAGIC });
    u32_len(&mut out, relation.groups.len());
    for group in &relation.groups {
        name(&mut out, &group.name);
        out.push(group.log_len);
        if v2 {
            out.extend_from_slice(&group.segment.to_le_bytes());
        }
    }
    u32_len(&mut out, relation.columns.len());
    for column in &relation.columns {
        name(&mut out, &column.name);
        match &column.kind {
            Kind::Witness(group) => {
                out.push(0);
                out.extend_from_slice(&group.0.to_le_bytes());
            }
            Kind::Weight => out.push(1),
            Kind::Public(values) => {
                out.push(2);
                u32_len(&mut out, values.len());
                for v in values {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
            Kind::Virtual(def) => {
                out.push(3);
                match def {
                    Def::Linear { constant, terms } => {
                        out.push(0);
                        out.extend_from_slice(&constant.to_le_bytes());
                        u32_len(&mut out, terms.len());
                        for (coeff, r) in terms {
                            out.extend_from_slice(&coeff.to_le_bytes());
                            reference(&mut out, r);
                        }
                    }
                    Def::Pointwise { terms } => {
                        out.push(1);
                        u32_len(&mut out, terms.len());
                        for term in terms {
                            out.extend_from_slice(&term.coeff.to_le_bytes());
                            out.push(term.factors.len() as u8);
                            for factor in &term.factors {
                                reference(&mut out, factor);
                            }
                        }
                    }
                    Def::Contraction {
                        free,
                        summed,
                        lhs,
                        rhs,
                    } => {
                        out.push(2);
                        out.extend_from_slice(&[*free, *summed]);
                        reference(&mut out, lhs);
                        reference(&mut out, rhs);
                    }
                }
                match column.segment {
                    None => out.push(0),
                    Some(seg) => {
                        out.push(1);
                        out.extend_from_slice(&seg.to_le_bytes());
                    }
                }
            }
        }
        width(&mut out, column.width);
        out.push(column.log_len);
        if v2 {
            out.push(u8::from(column.carried));
        }
    }
    u32_len(&mut out, relation.tables.len());
    for table in &relation.tables {
        name(&mut out, &table.name);
        u32_len(&mut out, table.widths.len());
        for w in &table.widths {
            width(&mut out, *w);
        }
        u32_len(&mut out, table.rows.len());
        for row in &table.rows {
            u32_len(&mut out, row.len());
            for v in row {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    u32_len(&mut out, relation.identities.len());
    for identity in &relation.identities {
        name(&mut out, &identity.name);
        out.push(identity.vars);
        u32_len(&mut out, identity.terms.len());
        for term in &identity.terms {
            out.extend_from_slice(&term.coeff.to_le_bytes());
            out.push(term.factors.len() as u8);
            for factor in &term.factors {
                reference(&mut out, factor);
            }
        }
    }
    u32_len(&mut out, relation.lookups.len());
    for lookup in &relation.lookups {
        name(&mut out, &lookup.name);
        out.push(lookup.vars);
        match &lookup.selector {
            None => out.push(0),
            Some(selector) => {
                out.push(1);
                reference(&mut out, selector);
            }
        }
        u32_len(&mut out, lookup.tuple.len());
        for r in &lookup.tuple {
            reference(&mut out, r);
        }
        out.extend_from_slice(&lookup.table.0.to_le_bytes());
    }
    u32_len(&mut out, relation.ranges.len());
    for range in &relation.ranges {
        name(&mut out, &range.name);
        out.extend_from_slice(&range.column.0.to_le_bytes());
        width(&mut out, range.width);
    }
    u32_len(&mut out, relation.matmuls.len());
    for matmul in &relation.matmuls {
        name(&mut out, &matmul.name);
        out.extend_from_slice(&[matmul.free, matmul.summed]);
        for r in [&matmul.out, &matmul.lhs, &matmul.rhs] {
            reference(&mut out, r);
        }
    }
    u32_len(&mut out, relation.composes.len());
    for compose in &relation.composes {
        name(&mut out, &compose.name);
        out.extend_from_slice(&compose.column.0.to_le_bytes());
        u32_len(&mut out, compose.limbs.len());
        for (limb, shift) in &compose.limbs {
            out.extend_from_slice(&limb.0.to_le_bytes());
            out.push(*shift);
        }
    }
    // Every other relation ends with its compositions, so its bytes are unchanged.
    if relation.passport_weights {
        out.extend_from_slice(PASSPORT_WEIGHTS);
    }
    out
}

/// The `relation/statement` digest: BLAKE3 of [`encode`].
pub fn digest(relation: &Relation) -> [u8; 32] {
    *blake3::hash(&encode(relation)).as_bytes()
}
