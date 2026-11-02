//! RFC-0024 §6: export the actual control packets for independent consumption.
use stele_hash::{ChallengeField, Transcript};
use stele_pcs::{CodeField, Source, Usage};
use stele_reductions::integer_linear as linear;

#[derive(Clone, Copy)]
pub struct Original<'a, K: ChallengeField + CodeField> {
    pub source: Source<K>,
    pub certificate: &'a [u8],
    pub range: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct Context<'a, K: ChallengeField + CodeField> {
    pub id: u16,
    pub bits: [u8; 4],
    pub repetitions: usize,
    pub side: Option<usize>,
    pub point: &'a [K],
    pub value: K,
    pub originals: [Original<'a, K>; 2],
}

/// Untrusted wire and observed result, never an imported verification receipt.
pub struct Attempt<'a, K: ChallengeField + CodeField> {
    pub context: &'a Context<'a, K>,
    pub variant: &'a str,
    pub wire: &'a [u8],
    pub following: Vec<u8>,
    pub result: Result<Usage, linear::Failure>,
}

pub(super) type Observer<'a, K> = Option<&'a dyn Fn(Attempt<'_, K>)>;

impl<K: ChallengeField + CodeField + Eq> Context<'_, K> {
    pub(super) fn emit(
        &self,
        observer: Observer<'_, K>,
        variant: &str,
        wire: &[u8],
        t: &mut Transcript<K>,
        result: &Result<(linear::Record<'_, K>, Usage), linear::Failure>,
    ) {
        let Some(observer) = observer else { return };
        let result = result.as_ref().map(|(_, u)| *u).map_err(|f| *f);
        let mut following = Vec::new();
        if result.is_ok() {
            let instance = super::next::<K>();
            let proof = stele_sumcheck::prove(
                &instance,
                stele_sumcheck::Dense::new(&instance, vec![vec![K::from_i64(1), K::from_i64(2)]])
                    .expect("following public table"),
                t,
            )
            .expect("actual following producer after the accepted control");
            for value in proof.rounds.iter().flatten().chain(&proof.final_values) {
                following.extend_from_slice(value.to_le_bytes().as_ref());
            }
        }
        observer(Attempt {
            context: self,
            variant,
            wire,
            following,
            result,
        });
    }
}
