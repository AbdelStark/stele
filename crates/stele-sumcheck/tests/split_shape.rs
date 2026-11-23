//! The assertion the three-thread runs of `kernel_parity.rs` and `large_trees` rely on
//! (E20-03 slice 1 review, second pass, F9): a pool of three threads must hand out a range
//! that is not a whole number of blocks, or those runs test no tail.
#![cfg(feature = "std")]
use std::sync::Mutex;
use stele_field::{Field, QM31};
use stele_sumcheck::parallel;

#[test]
fn rejects_a_three_thread_split_made_of_whole_blocks() {
    let lengths = Mutex::new(Vec::new());
    parallel::with_threads(3, || {
        let mut out = [QM31::from_i64(0); 1];
        parallel::sum_ranges(1 << 12, &mut out, |range, _| {
            lengths.lock().expect("lock").push(range.len());
            Ok(())
        })
        .expect("sum");
    });
    let lengths = lengths.into_inner().expect("lock");
    assert!(lengths.iter().any(|n| n % 64 != 0), "{lengths:?}");
}
