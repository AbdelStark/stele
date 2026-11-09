//! Embedding attackers for the mutation survey (see `mutation.rs`), on two instances:
//! the rounding branch (`s = −4`, with a tie: `m = 8` and odd codes) and the exact
//! branch (`s = 2`, with a token whose multiplier reaches the `2^16` cap). Both use
//! one-row gather blocks, so the block assembly identity is present.

use super::mutation::*;
use super::*;
use alloc::format;
use alloc::string::String;

const SCOPE: &str = "G/embedding";

fn instance(exponent: i16, mantissas: Vec<u16>, zero_row: Option<usize>) -> Gather {
    let mut rng = Rng(0x05ee_de16);
    let mut gather = Gather::new(&mut rng, 4, exponent, 8);
    gather.plan.tokens = vec![0, 1, 2, 3];
    gather.plan.mantissas = mantissas;
    for (i, w) in gather.weights.iter_mut().enumerate() {
        if zero_row == Some(i / 6) {
            *w = 0;
        } else if i % 6 == 0 {
            *w |= 1; // odd codes at feature 0 give ties at m = 8
        }
    }
    gather
}

struct EmbeddingAttack<'a> {
    r: &'a Relation,
    honest: &'a Values,
    shift: i32,
    mantissas: Vec<i64>,
    blocks: bool,
}

impl EmbeddingAttack<'_> {
    fn col(&self, name: &str) -> ColumnId {
        column(self.r, &format!("{SCOPE}/{name}")).expect("declared column")
    }

    fn r0(&self, v: &Values) -> Vec<i64> {
        v.get(self.r, self.col("R0")).expect("R0").to_vec()
    }

    /// Set `R0` and `ρ` at cell `i` to satisfy the rounding (or exact) identity for the
    /// current `G` and sign: the attacker's own solve of the module's identity.
    fn settle(&self, v: &mut Values, i: usize) {
        let r = self.r;
        let t = i >> 3;
        let g = get(r, v, self.col("G"), i);
        let p = g * i128::from(self.mantissas[t]) * i128::from(i % 8 < 6);
        if self.shift >= 0 {
            let mm = if self.shift >= 17 {
                1 << 16
            } else {
                (i128::from(self.mantissas[t]) << self.shift).min(1 << 16)
            };
            set(r, v, self.col("R0"), i, g * mm * i128::from(i % 8 < 6));
            return;
        }
        let h = -self.shift;
        let sigma = get(r, v, self.col("sigma"), i);
        // ρ = 2^h·R0 − P + σ + 2^(h−1) − 1 ∈ [0, 2^h) gives R0 = floor((P − σ + 2^(h−1)) / 2^h).
        let y = (p - sigma + (1 << (h - 1))).div_euclid(1 << h);
        set(r, v, self.col("R0"), i, y);
        let rho = (y << h) - p + sigma + (1 << (h - 1)) - 1;
        set(r, v, self.col("rho0"), i, rho);
    }

    fn pool(&self) -> Vec<Attack> {
        let r = self.r;
        let base = self.r0(self.honest);
        let mut out = Vec::new();
        let mut emit = |how: String, v: Values| {
            let output = self.r0(&v) != base;
            out.push(Attack {
                how,
                values: v,
                output,
            });
        };
        for i in 0..32 {
            let t = i >> 3;
            let g = get(r, self.honest, self.col("G"), i);
            for delta in [1i128, -1] {
                let ng = g + delta;
                if !(-128..128).contains(&ng) || (ng < 0) != (g < 0) {
                    continue;
                }
                // G off the gathered row, the block (and its matmul) kept.
                let mut v = self.honest.clone();
                set(r, &mut v, self.col("G"), i, ng);
                self.settle(&mut v, i);
                emit(format!("G[{i}] {delta:+} with R0 settled"), v.clone());
                // The block follows G: only the gather matmul of that row is violated.
                if self.blocks {
                    set(r, &mut v, self.col(&format!("G{t}")), i & 7, ng);
                    emit(
                        format!("G[{i}] and G{t}[{}] {delta:+} with R0 settled", i & 7),
                        v,
                    );
                }
            }
            // The sign flipped (a tie then rounds toward zero).
            let mut v = self.honest.clone();
            let sigma = get(r, &v, self.col("sigma"), i);
            set(r, &mut v, self.col("sigma"), i, 1 - sigma);
            self.settle(&mut v, i);
            emit(format!("sigma[{i}] flipped, R0 settled"), v);
            // R0 ± 1 alone, against its (rounding or exact) identity.
            for delta in [1i128, -1] {
                let mut v = self.honest.clone();
                let y = get(r, &v, self.col("R0"), i);
                set(r, &mut v, self.col("R0"), i, y + delta);
                emit(format!("R0[{i}] {delta:+} alone"), v);
            }
            if self.shift < 0 {
                // R0 ± 1 with ρ moved by ∓2^h.
                for delta in [1i128, -1] {
                    let mut v = self.honest.clone();
                    let y = get(r, &v, self.col("R0"), i);
                    let rho = get(r, &v, self.col("rho0"), i);
                    set(r, &mut v, self.col("R0"), i, y + delta);
                    set(r, &mut v, self.col("rho0"), i, rho + (delta << -self.shift));
                    emit(
                        format!("R0[{i}] {delta:+}, rho0 {:+}", delta << -self.shift),
                        v,
                    );
                }
            }
            // Token 3 has a zero row and a large multiplier: one nonzero code (a different
            // model) makes the true R0 leave int16, which the executor rejects.
            if t == 3 && i % 8 < 6 {
                let code = if self.shift < 0 { 127 } else { 1 };
                let mut v = self.honest.clone();
                let k = i & 7;
                set(r, &mut v, self.col("E"), (3 << 3) + k, code);
                set(r, &mut v, self.col("G"), i, code);
                if self.blocks {
                    set(r, &mut v, self.col("G3"), k, code);
                }
                self.settle(&mut v, i);
                emit(format!("E[3,{k}] = {code}: true R0 outside int16"), v);
            }
            // A weight entry outside int8 on a row no token gathers.
            let mut v = self.honest.clone();
            set(r, &mut v, self.col("E"), 8 * 8 + (i & 7), 200);
            emit("E[8, k] = 200 on an ungathered row".into(), v);
            // A gather block entry outside int8 that G does not follow.
            if self.blocks {
                let mut v = self.honest.clone();
                let block = self.col(&format!("G{t}"));
                let old = get(r, &v, block, i & 7);
                set(r, &mut v, block, i & 7, old + 256);
                emit(format!("G{t}[{}] +256", i & 7), v);
            }
        }
        out
    }
}

fn embedding_survey(gather: &Gather, expected: &str) {
    let shift = i32::from(gather.plan.exponent) + i32::from(gather.plan.fraction);
    let capture = gather.capture().expect("in range");
    // One-row gather blocks (domain limit ld + lv) exercise the block assembly.
    let (r, honest) = gather.assigned(&capture, 3 + 4).expect("assign");
    let attack = EmbeddingAttack {
        r: &r,
        honest: &honest,
        shift,
        mantissas: gather
            .plan
            .tokens
            .iter()
            .map(|&x| i64::from(gather.plan.mantissas[x as usize]))
            .collect(),
        blocks: true,
    };
    let pool = attack.pool();
    let rows = survey(&r, &honest, &pool, &|_, _| {}, Some(expected));
    golden("embedding", &rows, expected);
}

#[test]
fn rejects_every_embedding_constraint_alone_rounding() {
    let mut mantissas = vec![8, 3, 1000, 65535];
    mantissas.extend([5; 7]);
    embedding_survey(
        &instance(-10, mantissas, Some(3)),
        include_str!("embedding-round-mutation.txt"),
    );
}

#[test]
fn rejects_every_embedding_constraint_alone_exact() {
    let mut mantissas = vec![8, 3, 60, 16384];
    mantissas.extend([5; 7]);
    embedding_survey(
        &instance(-4, mantissas, Some(3)),
        include_str!("embedding-exact-mutation.txt"),
    );
}

#[test]
fn accepts_embedding_row_blocks() {
    // Values pass through the block path (one-row blocks) at both branches.
    for exponent in [-10i16, -4] {
        let mut mantissas = vec![8, 3, 60, 16384];
        mantissas.extend([5; 7]);
        let gather = instance(exponent, mantissas, Some(3));
        let capture = gather.capture().expect("in range");
        let (r, values) = gather.assigned(&capture, 3 + 4).expect("assign");
        assert!(r.matmuls.len() == 4 && r.identities.iter().any(|d| d.name.ends_with("/blocks")));
        check(&r, &values).expect("honest values pass through row blocks");
    }
}
