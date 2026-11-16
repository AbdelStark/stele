//! RFC-0026 §4, §9: NC-1303/1307 on L0 and L1, source profiles 3 and 5.
use crate::{check_proof_control, development::span_of, ProverHook};
use stele_prover::development::{
    self, container::Container, Error, Layout, PlanData, Public, Statement,
};
use stele_reductions::relation;
use stele_reductions::stele_cqis::model::{Model, Scales};
use stele_reductions::stele_pcs::{Error as PcsError, ProofKind};

fn err(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}

struct Fixture {
    public: Public,
    statement: Statement,
    proof: Container,
    row_at: usize,
    profile: u8,
}

fn fixtures() -> Result<Vec<Fixture>, String> {
    let mut out = Vec::new();
    for (case, length) in [("one-layer", 16), ("eight-layer", 64)] {
        for profile in [development::CIRCLE_ALL_PROFILE, development::GRIND_PROFILE] {
            let span = |key| span_of(case, key);
            let (public, statement, proof) = development::prove_window_development(
                span("model")?,
                span("preparation")?,
                span("scales")?,
                span("artifact")?,
                Statement {
                    tokens: vec![1],
                    start: 0,
                    end: 1,
                    next: None,
                },
                length,
                profile,
            )
            .map_err(err)?;
            let proof = development::container::decode(&proof).map_err(err)?;
            let model = Model::decode(&public.model).map_err(err)?;
            let scales = Scales::decode(&model, &public.scales).map_err(err)?;
            let layout = Layout::declare(
                &PlanData {
                    model: &model,
                    scales: &scales,
                    vectors: &public.vectors,
                    zk: false,
                },
                &statement,
            )
            .map_err(err)?;
            let group = proof.groups.first().ok_or("no stacked certificate")?;
            let root = group
                .get(..32)
                .ok_or("stacked root")?
                .try_into()
                .map_err(err)?;
            let source = relation::stack_source(&layout.relation, public.sources, root)
                .map_err(err)?
                .ok_or("no stacked source")?;
            // RFC-0010 A14: root || u8(1) || [tensor nonce] || canonical QM31 row.
            let (tensor, _) = source.grind_bits(ProofKind::Certificate);
            let row_at = 32 + 1 + 8 * usize::from(tensor > 0);
            let parsed = source
                .parse(ProofKind::Certificate, &group[32..])
                .map_err(err)?;
            assert_eq!(
                &group[row_at..row_at + parsed.row_bytes().len()],
                parsed.row_bytes()
            );
            out.push(Fixture {
                public,
                statement,
                proof,
                row_at,
                profile,
            });
        }
    }
    Ok(out)
}

struct Change {
    id: u16,
    row_at: usize,
}
impl Change {
    fn word<'a>(&self, proof: &'a mut Container) -> &'a mut [u8] {
        match self.id {
            1303 => &mut proof.groups[0][self.row_at..self.row_at + 4],
            1307 => &mut proof.matmuls[0][..4],
            _ => unreachable!("fixed message control inventory"),
        }
    }
}
impl ProverHook<Container> for Change {
    fn tamper(&self, proof: &mut Container) {
        let before = proof.clone();
        let word = self.word(proof);
        let old: [u8; 4] = word.try_into().expect("one base-field limb");
        let value = u32::from_le_bytes(old);
        const P: u32 = (1 << 31) - 1;
        assert!(value < P, "honest limb must be canonical");
        let replacement = if self.id == 1303 { P } else { (value + 1) % P };
        word.copy_from_slice(&replacement.to_le_bytes());
        assert_ne!(word, old);
        let mut restored = proof.clone();
        self.word(&mut restored).copy_from_slice(&old);
        assert!(restored == before, "only the declared limb may change");
    }
}

/// Run one composed control; cache only its real, freshly proved fixture inputs.
pub fn run(id: u16) -> Result<(), String> {
    let expected = match id {
        1303 => Error::Engine(relation::Error::Pcs(PcsError::NoncanonicalField)),
        1307 => Error::Engine(relation::Error::Sumcheck(
            stele_sumcheck::Error::RoundSumMismatch,
        )),
        _ => return Err(format!("unknown message control {id}")),
    };
    static FIXTURES: std::sync::OnceLock<Result<Vec<Fixture>, String>> = std::sync::OnceLock::new();
    for f in FIXTURES
        .get_or_init(fixtures)
        .as_ref()
        .map_err(Clone::clone)?
    {
        check_proof_control(
            || Ok::<_, Error>(f.proof.clone()),
            &Change {
                id,
                row_at: f.row_at,
            },
            |proof| development::verify(&f.public, &f.statement, &proof.encode()).map(|_| ()),
            expected.clone(),
        )
        .map_err(err)?;
        eprintln!(
            "NC-{id}: T={} profile={} honest accepted, exact {expected:?}",
            f.statement.tokens.len(),
            f.profile
        );
    }
    Ok(())
}
