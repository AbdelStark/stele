//! RFC-0023 §§2.1-2.2: closed ordered terms, with O(J+E) static metadata work.
//! This compiler does not bind sources, sample weights or accept a proof.
use super::{buffer, Block, Error, Role, Schema};
use alloc::vec::Vec;
use stele_hash::ChallengeField;
use stele_sumcheck::Term;

/// Ordered arithmetic equations over one shared sigma/U/advice ordinal space.
#[derive(Debug)]
pub struct Constraints<K> {
    input_count: usize,
    equations: Vec<Vec<Term<K>>>,
}
impl<K> Constraints<K> {
    /// Sigma, four input byte planes, then all R advice planes.
    pub fn input_count(&self) -> usize {
        self.input_count
    }
    /// Complete ordered terms, including zeros and repeated factors.
    pub fn equations(&self) -> &[Vec<Term<K>>] {
        &self.equations
    }
}

#[derive(Clone, Copy)]
enum Operand {
    Input,
    TwiceSign,
    Value(usize),
    Constant(u64),
}

impl Schema {
    /// Compile the fixed relation from this generated schema, without proof data.
    pub fn constraints<K: ChallengeField>(&self) -> Result<Constraints<K>, Error> {
        let input_count = self
            .rows()
            .checked_add(5)
            .filter(|v| u32::try_from(*v).is_ok())
            .ok_or(Error::Capacity)?;
        let mut count = self.rows().checked_add(13).ok_or(Error::Capacity)?;
        for b in self.values().iter().chain(
            self.roles()
                .iter()
                .flat_map(|r| r.result_cap().into_iter().chain(r.carries())),
        ) {
            count = b
                .value
                .len()
                .checked_mul(2)
                .and_then(|v| v.checked_sub(1))
                .and_then(|v| count.checked_add(v))
                .ok_or(Error::Capacity)?;
        }
        for r in self.roles() {
            count = count
                .checked_add(usize::from(r.widths[2]))
                .ok_or(Error::Capacity)?;
        }
        if count >= 1 << 20 {
            return Err(Error::Capacity);
        }
        let p = self.layout.params;
        let mantissa = u64::from(u16::from_le_bytes([p[0], p[1]]));
        let d = 1u64.checked_shl(u32::from(p[2])).ok_or(Error::Encoding)?;
        let h = if p[2] == 0 { 0 } else { d / 2 };
        use Operand::{Constant as C, Input, TwiceSign, Value as V};
        let pairs: [&[(Operand, Operand)]; 6] = [
            &[(Input, C(1)), (V(0), TwiceSign)],
            &[(C(1 << 31), C(1)), (V(0), C(1))],
            &[(V(0), C(mantissa))],
            &[(V(1), C(1)), (C(h), C(1))],
            &[(V(2), C(d))],
            &[(V(3), C(1)), (V(4), C(1))],
        ];
        // The actual operand caps must fit the generated common bounds (§2.1).
        for (role, pairs) in self.roles().iter().zip(pairs) {
            if role.count as usize != pairs.len() {
                return Err(Error::Encoding);
            }
            for (left, right) in pairs {
                if operand_cap(self, *left)? > role.bounds[0]
                    || operand_cap(self, *right)? > role.bounds[1]
                {
                    return Err(Error::Encoding);
                }
            }
        }
        let mut equations = buffer(count)?;
        boolean(&mut equations, 0)?;
        for b in self.values() {
            cap(&mut equations, b)?;
        }
        for ((role, pairs), target) in self.roles().iter().zip(pairs).zip([6, 6, 1, 5, 3, 5]) {
            if let Some(b) = role.result_cap() {
                cap(&mut equations, b)?;
            }
            for b in role.carries() {
                cap(&mut equations, b)?;
            }
            for k in 0..usize::from(role.widths[2]) {
                let mut terms = buffer(0)?;
                for (left, right) in pairs {
                    for i in 0..usize::from(role.widths[0]) {
                        if let Some(j) = k
                            .checked_sub(i)
                            .filter(|j| *j < usize::from(role.widths[1]))
                        {
                            let mut a = digit::<K>(self, *left, i)?;
                            let b = digit::<K>(self, *right, j)?;
                            // Digits have at most one factor; the reserved third slot is sigma.
                            a.coefficient = a.coefficient * b.coefficient;
                            a.factors.extend_from_slice(&b.factors);
                            append(&mut terms, a)?;
                        }
                    }
                }
                carry(&mut terms, role, k, 1)?;
                let mut result = digit::<K>(self, V(target), k)?;
                result.coefficient = -result.coefficient;
                append(&mut terms, result)?;
                carry(&mut terms, role, k + 1, -256)?;
                real(&mut equations, terms)?;
            }
        }
        for k in 0..4 {
            let mut terms = buffer(5)?;
            terms.push(digit::<K>(self, V(7), k)?);
            terms.push(if k == 0 { advice(0)? } else { term(0, &[])? });
            terms.push(if k == 0 {
                term(0, &[])?
            } else {
                advice(self.layout.u_carries.start + k - 1)?
            });
            let mut v = digit::<K>(self, V(0), k)?;
            v.coefficient = -v.coefficient;
            terms.push(v);
            terms.push(if k == 3 {
                term(0, &[])?
            } else {
                scaled_advice(self.layout.u_carries.start + k, -256)?
            });
            real(&mut equations, terms)?;
        }
        for row in self.u_carries() {
            boolean(&mut equations, row)?;
        }
        let mut target = buffer(0)?;
        whole(&mut target, &self.values()[2], 1)?;
        whole(&mut target, &self.values()[8], 1)?;
        let h = i64::try_from(self.values()[8].cap).map_err(|_| Error::Encoding)?;
        append(&mut target, term(1 - h, &[])?)?;
        append(&mut target, scaled_advice(0, -1)?)?;
        real(&mut equations, target)?;
        for ordinal in (1..5).chain(5..5 + self.allocated_rows()) {
            let mut terms = buffer(2)?;
            terms.push(term(1, &[ordinal as u32])?);
            terms.push(term(-1, &[0, ordinal as u32])?);
            append(&mut equations, terms)?;
        }
        for row in self.allocated_rows()..self.rows() {
            let mut terms = buffer(1)?;
            terms.push(advice(row)?);
            append(&mut equations, terms)?;
        }
        if equations.len() != count
            || equations.iter().any(|e| {
                e.is_empty()
                    || u32::try_from(e.len()).is_err()
                    || e.iter().any(|t| {
                        t.factors.len() > 3 || t.factors.iter().any(|f| *f as usize >= input_count)
                    })
            })
        {
            return Err(Error::Encoding);
        }
        Ok(Constraints {
            input_count,
            equations,
        })
    }
}

fn append<T>(out: &mut Vec<T>, value: T) -> Result<(), Error> {
    out.try_reserve(1).map_err(|_| Error::Capacity)?;
    out.push(value);
    Ok(())
}

fn term<K: ChallengeField>(coefficient: i64, factors: &[u32]) -> Result<Term<K>, Error> {
    if factors.len() > 3 {
        return Err(Error::Encoding);
    }
    let mut out = buffer(3)?; // Bounded slack permits products and sigma without reallocating.
    out.extend_from_slice(factors);
    Ok(Term {
        coefficient: K::from_i64(coefficient),
        factors: out,
    })
}

fn scaled_advice<K: ChallengeField>(row: usize, coefficient: i64) -> Result<Term<K>, Error> {
    let ordinal = row
        .checked_add(5)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(Error::Capacity)?;
    term(coefficient, &[ordinal])
}
fn advice<K: ChallengeField>(row: usize) -> Result<Term<K>, Error> {
    scaled_advice(row, 1)
}

fn real<K: ChallengeField>(
    out: &mut Vec<Vec<Term<K>>>,
    mut terms: Vec<Term<K>>,
) -> Result<(), Error> {
    for t in &mut terms {
        if t.factors.len() >= 3 {
            return Err(Error::Encoding);
        }
        // All terms originate in term(), with three fallibly reserved factor slots.
        t.factors.insert(0, 0);
    }
    append(out, terms)
}

fn boolean<K: ChallengeField>(out: &mut Vec<Vec<Term<K>>>, row: usize) -> Result<(), Error> {
    let mut t = advice::<K>(row)?;
    t.factors.push(t.factors[0]);
    let mut terms = buffer(2)?;
    terms.push(t);
    terms.push(scaled_advice(row, -1)?);
    real(out, terms)
}

fn cap<K: ChallengeField>(out: &mut Vec<Vec<Term<K>>>, b: &Block) -> Result<(), Error> {
    for (k, row) in b.value().enumerate() {
        let mut terms = buffer(5)?;
        terms.push(advice(row)?);
        terms.push(advice(b.slack.start + k)?);
        terms.push(if k == 0 {
            term(0, &[])?
        } else {
            advice(b.carry.start + k - 1)?
        });
        terms.push(term(
            -i64::from(b.cap.to_le_bytes().get(k).copied().unwrap_or(0)),
            &[],
        )?);
        terms.push(if k + 1 == b.value.len() {
            term(0, &[])?
        } else {
            scaled_advice(b.carry.start + k, -256)?
        });
        real(out, terms)?;
    }
    for row in b.carry() {
        boolean(out, row)?;
    }
    Ok(())
}

fn whole<K: ChallengeField>(out: &mut Vec<Term<K>>, b: &Block, scale: i64) -> Result<(), Error> {
    let mut power = K::from_i64(scale);
    for row in b.value() {
        let mut t = advice(row)?;
        t.coefficient = power;
        append(out, t)?;
        power = power * K::from_i64(256);
    }
    Ok(())
}

fn carry<K: ChallengeField>(
    out: &mut Vec<Term<K>>,
    role: &Role,
    k: usize,
    scale: i64,
) -> Result<(), Error> {
    if let Some(b) = k.checked_sub(1).and_then(|k| role.carries().get(k)) {
        whole(out, b, scale)
    } else {
        append(out, term(0, &[])?)
    }
}

fn operand_cap(schema: &Schema, operand: Operand) -> Result<u64, Error> {
    Ok(match operand {
        Operand::Input => (1 << 32) - 1,
        Operand::TwiceSign => 2,
        Operand::Constant(v) => v,
        Operand::Value(i) => schema.values().get(i).ok_or(Error::Encoding)?.cap,
    })
}

fn digit<K: ChallengeField>(schema: &Schema, operand: Operand, k: usize) -> Result<Term<K>, Error> {
    match operand {
        Operand::Input if k < 4 => term(1, &[1 + k as u32]),
        Operand::TwiceSign if k == 0 => scaled_advice(0, 2),
        Operand::Constant(v) => term(i64::from(v.to_le_bytes().get(k).copied().unwrap_or(0)), &[]),
        Operand::Value(i) => {
            let b = schema.values().get(i).ok_or(Error::Encoding)?;
            if let Some(row) = b.value.start.checked_add(k).filter(|r| *r < b.value.end) {
                advice(row)
            } else {
                term(0, &[])
            }
        }
        _ => term(0, &[]),
    }
}

#[cfg(test)]
#[path = "requant_constraint_tests.rs"]
mod tests;
