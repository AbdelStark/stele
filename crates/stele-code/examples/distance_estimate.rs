//! RFC-0010 A4 — sampled nonzero codeword weights give upper bounds only.
use stele_code::{Code, CodeId};
use stele_field::{Field, M31};
fn row(n: usize, kind: usize, index: usize) -> Vec<M31> {
    let mut out = vec![M31::ZERO; n];
    match kind {
        0 => out[index] = M31::ONE,
        1 => {
            out[index] = M31::ONE;
            out[index + 1] = -M31::ONE;
        }
        _ => {
            let mut state = index as u64 + 1;
            for x in &mut out {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *x = M31::from_i64((state >> 32) as i64);
            }
            out[0] = M31::ONE;
        }
    }
    out
}
fn main() -> Result<(), String> {
    for j in [3u8, 4] {
        for seed in [0u8, 1] {
            let mut raw = b"stele/expander-seed/v2".to_vec();
            raw.push(j);
            raw.extend([seed; 32]);
            let id = CodeId::parse(&raw).map_err(|e| format!("{e:?}"))?;
            let code = id.prepare(1 << 20).map_err(|e| format!("{e:?}"))?;
            let n = code.parameters().message_len;
            let mut best = (2 * n + 1, 0, 0);
            let mut samples = 0;
            for (kind, count) in [(0, n), (1, n - 1), (2, 32)] {
                for index in 0..count {
                    let input = row(n, kind, index);
                    let encoded = code.encode(&input).map_err(|e| format!("{e:?}"))?;
                    let weight = encoded.iter().filter(|x| **x != M31::ZERO).count();
                    if weight == 0 {
                        return Err("nonzero input encoded to zero".into());
                    }
                    if weight < best.0 {
                        best = (weight, kind, index);
                    }
                    samples += 1;
                }
            }
            println!("{{\"j\":{j},\"seed\":{seed},\"samples\":{samples},\"distance_upper_bound\":{},\"witness_kind\":{},\"witness_index\":{}}}",best.0,best.1,best.2);
        }
    }
    Ok(())
}
