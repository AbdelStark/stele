//! RFC-0013 A5 item 5. Borrow every ordinary claim before production weight_table.
extern crate std;
use super::Claim;
use alloc::vec::Vec;
use std::{any::Any, sync::OnceLock, time::Instant};
use stele_field::{M31, QM31};
use stele_hash::ChallengeField;
use stele_pcs::PreparedSource;

type Sample = fn(u64, &[u8], &[M31], &[Claim<QM31>], &[QM31]);
pub static OBSERVER: OnceLock<Sample> = OnceLock::new();

pub(super) fn batch<K: ChallengeField>(
    id: u64,
    source: &PreparedSource<'_, K>,
    claims: &Vec<Claim<K>>,
    gammas: &Vec<K>,
) {
    let start = Instant::now();
    let descriptor = source.source().bytes();
    let ns = start.elapsed().as_nanos();
    std::eprintln!("host_source id={id} encode_ns={ns}");
    OBSERVER.get().expect("required CPU observer")(
        id,
        &descriptor,
        source.message(),
        (claims as &dyn Any)
            .downcast_ref::<Vec<Claim<QM31>>>()
            .expect("QM31 claims"),
        (gammas as &dyn Any)
            .downcast_ref::<Vec<QM31>>()
            .expect("QM31 coefficients"),
    );
}
