//! stele-cli — governed by RFC-0020. No behaviour exists here that is not specified there (INV-1).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

use stele_prover::development::{Ledger, Round, RoundError};
use stele_verifier::accounting::{self, Bound, Family, Reject, STANDARD};

/// `2^-x.y` for a security of `bits/1024`, rounded down to a tenth.
fn tenths(bits: u64) -> String {
    let t = bits * 10 / 1024;
    format!("2^-{}.{}", t / 10, t % 10)
}

/// A round's family; an unknown line is `None`, never a non-grinding default, so a
/// renamed PCS line cannot lose its grinding rule.
fn family(line: &str) -> Option<Family> {
    Some(match line {
        "SC" => Family::Sumcheck,
        "RLC" => Family::Rlc,
        "SZ" => Family::Sz,
        "LU" => Family::Lookup,
        "MASK" => Family::Mask,
        "PCS tensor" => Family::PcsTensor,
        "PCS column" => Family::PcsColumn,
        _ => return None,
    })
}

fn round(r: &Round) -> Option<accounting::Round> {
    let error = match r.error {
        RoundError::Field(n) => Bound {
            numerator: u128::from(n),
            field_degree: 4,
            log2_denominator: 0,
        },
        RoundError::Pow2(c) => Bound {
            numerator: 1,
            field_degree: 0,
            log2_denominator: c,
        },
    };
    Some(accounting::Round {
        family: family(r.line)?,
        error,
        grind_bits: u32::from(r.grind),
    })
}

/// E8-05c: the RFC-0012 A17 item 4 verdict for a development proof's enumerated
/// rounds under the standard profile (λ = 100, g = 8, `Q_cap = 2^80`). Informational
/// only: the development tier claims no level (RFC-0026 §1.2).
///
/// `Q_V` is taken as `2^64 − 1`, an upper bound on any verification's hash calls;
/// (C3) holds there for the standard profile.
pub fn admission(ledger: &Ledger) -> String {
    let rounds = ledger.rounds();
    let Some(checked) = rounds.iter().map(round).collect::<Option<Vec<_>>>() else {
        return "admission\tFAIL: a round of an unknown line".to_string();
    };
    let verdict = verdict(&rounds, &checked, admit(ledger, &checked));
    // Policy 1 column rounds carry no k_q nonce; RFC-0010 A14 admits only Policy 2.
    let policy1 = checked
        .iter()
        .any(|r| r.family == Family::PcsColumn && r.grind_bits == 0);
    let worst = ledger.worst().map_or_else(String::new, |(r, bits)| {
        format!(
            "worst round\t{} {}\t{} after {} grinding bits\n",
            r.line,
            r.name,
            tenths(bits),
            r.grind
        )
    });
    let note = if policy1 {
        "note\tPolicy 1 sources are not a standard configuration (no k_q column grinding, \
         RFC-0010 A14): they always fail (C4)\n"
    } else {
        ""
    };
    format!(
        "admission\tstandard (lambda 100, g 8, Q_cap 2^80), RFC-0012 A17 item 4; \
         informational, development claims no level\n\
         rounds\t{}\n{worst}floor\t{}{}\n{note}\
         verdict\t{verdict}",
        rounds.len(),
        tenths(ledger.floor_bits()),
        if ledger.setup {
            " plus the A7 setup term"
        } else {
            ""
        },
    )
}

/// `admit` under `STANDARD` on the ledger's rounds, with the A7 setup term when a v2
/// J ≥ 4 source is present and `Q_V = 2^64 − 1`.
fn admit(ledger: &Ledger, checked: &[accounting::Round]) -> Result<(), Reject> {
    let setup = ledger.setup.then_some(Bound {
        numerator: 200_431_782,
        field_degree: 0,
        log2_denominator: 160,
    });
    accounting::admit(&STANDARD, checked, setup, u64::MAX)
}

fn verdict(rounds: &[Round], checked: &[accounting::Round], result: Result<(), Reject>) -> String {
    let name = |i: usize| {
        rounds
            .get(i)
            .map_or_else(String::new, |r| format!("{} {}", r.line, r.name))
    };
    match result {
        Ok(()) => "PASS (C1)-(C4)".to_string(),
        Err(Reject::Round(i)) => format!(
            "FAIL (C1): round {i} ({}) exceeds 2^-108 at every grinding its family allows",
            name(i)
        ),
        Err(Reject::Grinding(i)) => format!(
            "FAIL (C4): round {i} ({}) grinds {} bits, not the bits the rule requires",
            name(i),
            checked[i].grind_bits
        ),
        Err(Reject::Floor) => "FAIL (C2): floor above 2^-100".to_string(),
        Err(Reject::Hash) => "FAIL (C3): an H* endpoint fails".to_string(),
        Err(Reject::Overflow) => "FAIL: exact arithmetic overflow".to_string(),
    }
}

/// Why [`gate`] refused a proof.
#[derive(Debug, PartialEq)]
pub enum Refusal<E> {
    /// RFC-0016 §2 step 3: the replay rejected.
    Verify(E),
    /// RFC-0016 §2 step 2: the replay accepted, but the configuration's rounds fail
    /// RFC-0012 A17 (C1)–(C4) (or carry an unknown line); the verdict text says which.
    Admission(String),
}

/// E8-05f (RFC-0016 A5, Draft): RFC-0016 §2 steps 2–4 for a development proof. It is
/// accepted only if the replay accepts **and** `admit` passes on the replay's
/// plan-derived rounds. This is the conjunction a standard entry point makes; it is
/// not one. The development tier still claims no level (RFC-0026 §1.2): no proof is
/// `proven: true`, and `standard-unproven` stays (ADR-126).
pub fn gate<E>(verified: Result<Ledger, E>) -> Result<Ledger, Refusal<E>> {
    let ledger = verified.map_err(Refusal::Verify)?;
    let rounds = ledger.rounds();
    let Some(checked) = rounds.iter().map(round).collect::<Option<Vec<_>>>() else {
        return Err(Refusal::Admission("a round of an unknown line".to_string()));
    };
    match admit(&ledger, &checked) {
        Ok(()) => Ok(ledger),
        Err(reject) => Err(Refusal::Admission(verdict(&rounds, &checked, Err(reject)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stele_prover::development::{Entry, Line};

    /// A ledger of one LU round of `numerator`.
    fn ledger(numerator: u64) -> Ledger {
        let mut l = Ledger::default();
        l.entries.push(Entry {
            line: Line::Lu,
            name: "check".into(),
            numerator,
            round: numerator,
            grind: 0,
        });
        l
    }

    /// E8-05f: the gate accepts only replay-accepted proofs whose rounds pass `admit`.
    /// Mutation check: with `gate` returning the replay's result alone, the second
    /// assertion fails (an ungrinded LU round above the cap would be accepted).
    #[test]
    fn gate_requires_both_the_replay_and_admission() {
        assert_eq!(gate::<()>(Ok(ledger(65_535))).map(|_| ()), Ok(()));
        assert_eq!(
            gate::<()>(Ok(ledger(65_536))).map(|_| ()),
            Err(Refusal::Admission(
                "FAIL (C4): round 0 (LU check) grinds 0 bits, not the bits the rule requires"
                    .to_string()
            ))
        );
        assert_eq!(
            gate(Err::<Ledger, _>("replay")).map(|_| ()),
            Err(Refusal::Verify("replay"))
        );
    }

    #[test]
    fn reports_c4_for_an_ungrinded_lu_round_above_the_cap_and_passes_below() {
        // ⌊p^4/2^108⌋ = 65535: one LU round of that numerator passes unaided.
        let pass = admission(&ledger(65_535));
        assert!(pass.ends_with("verdict\tPASS (C1)-(C4)"), "{pass}");
        let fail = admission(&ledger(65_536));
        assert!(
            fail.ends_with("verdict\tFAIL (C4): round 0 (LU check) grinds 0 bits, not the bits the rule requires"),
            "{fail}"
        );
        assert!(
            fail.contains("worst round\tLU check\t2^-107.9 after 0 grinding bits"),
            "{fail}"
        );
    }

    /// Cross-check with `research/fs-pcs/study.py` (PARAMETERS.md §4, Policy 1): its
    /// recorded stories42M ledger, each record one round as the study reads it, gives
    /// the study's worst round 2^-97.0 (LU range_8; 2^-96.9 rounded toward the larger
    /// error) and floor 2^-95.6. The study's
    /// PCS rounds (Σ ≈ 2^-105.6) do not move the floor's tenth, so they are omitted.
    #[test]
    fn matches_reference_study_worst_round_and_floor_and_fails() {
        let mut l = Ledger::default();
        for row in include_str!("../../../research/fs-pcs/stories42m-ledger.tsv").lines() {
            let mut cells = row.split('\t');
            let line = match cells.next() {
                Some("Lu") => Line::Lu,
                Some("Rlc") => Line::Rlc,
                Some("Sz") => Line::Sz,
                _ => Line::Sc,
            };
            let name = cells.next().unwrap_or_default().to_string();
            let numerator: u64 = cells
                .next()
                .and_then(|t| t.strip_suffix("/|K|"))
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            l.entries.push(Entry {
                line,
                name,
                numerator,
                round: numerator,
                grind: 0,
            });
        }
        assert_eq!(l.entries.len(), 1792);
        let out = admission(&l);
        // 134,217,983/p^4 = 2^-96.99999: the study prints 2^-97.0 (nearest); the
        // ledger rounds toward the larger error.
        assert!(
            out.contains("worst round\tLU range_8\t2^-96.9 after 0 grinding bits"),
            "{out}"
        );
        assert!(out.contains("floor\t2^-95.6\n"), "{out}");
        assert!(out.contains("verdict\tFAIL (C4)"), "{out}");
    }
}
