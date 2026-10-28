//! RFC-0006 A6: A1 engine with caller-owned proof and absorb buffers.
use crate::{
    finish_payload, message_bytes_into, message_size, round_payload, Error, Instance, Proof,
    Summand,
};
use stele_hash::{AbsorbLabel, ChallengeField, Transcript};

/// Fill preallocated A1 proof rows/finals without allocating engine buffers.
///
/// Shapes and the largest absorb buffer are checked before transcript mutation.
/// Strategy allocations are separate: the default `Summand::*_into` methods allocate,
/// while Dense and bounded strategies override them. Count all retained caller/source
/// capacities; this function does not certify a total process-memory budget.
/// On any error discard the partial proof and the entire transcript attempt.
pub fn prove_into<K: ChallengeField + Eq>(
    i: &Instance<K>,
    summand: &mut impl Summand<K>,
    proof: &mut Proof<K>,
    bytes: &mut [u8],
    transcript: &mut Transcript<K>,
) -> Result<(), Error> {
    let degree = i.validate()?;
    summand.validate_instance(i)?;
    if proof.rounds.len() != i.num_vars as usize
        || proof.rounds.iter().any(|row| row.len() != degree + 1)
        || proof.final_values.len() != i.inputs.len()
    {
        return Err(Error::ProofShape);
    }
    let required = i
        .encoded_len()?
        .max(message_size::<K>((degree + 1).max(i.inputs.len()))?);
    if bytes.len() < required {
        return Err(Error::Capacity);
    }
    let size = i.encode_into(bytes)?;
    transcript.absorb(AbsorbLabel::Instance, &bytes[..size])?;
    let mut running = i.claimed_sum;
    for (index, values) in proof.rounds.iter_mut().enumerate() {
        summand.round_into(i, values)?;
        let size = message_bytes_into(i.id, index as u32, values, bytes)?;
        let (challenge, next) = round_payload(values, running, &bytes[..size], transcript)?;
        summand.fold(challenge)?;
        if summand.shape() != (i.num_vars - index as u32 - 1, i.inputs.len()) {
            return Err(Error::PublicShape);
        }
        running = next;
    }
    summand.final_values_into(&mut proof.final_values)?;
    let size = message_bytes_into(i.id, i.inputs.len() as u32, &proof.final_values, bytes)?;
    finish_payload(i, &proof.final_values, running, &bytes[..size], transcript)
}
