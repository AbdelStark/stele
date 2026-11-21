//! RFC-0006 A1 (task E20-24): `parallel::for_each_block` hands out exactly the listed
//! blocks, on any pool, and refuses a list that overlaps or leaves the data.
#![cfg(feature = "std")]
use stele_sumcheck::{parallel, Error};

#[test]
fn matches_reference_fill_of_disjoint_blocks_and_rejects_overlap() {
    let blocks = [(0usize, 3usize), (3, 1), (8, 0), (9, 5), (20, 4)];
    let fill = |data: &mut [u32]| {
        parallel::for_each_block(data, &blocks, |i, block| {
            for (j, slot) in block.iter_mut().enumerate() {
                *slot += 100 * (i as u32 + 1) + j as u32;
            }
            Ok(())
        })
    };
    let mut expected = vec![0u32; 24];
    for (i, &(begin, len)) in blocks.iter().enumerate() {
        for j in 0..len {
            expected[begin + j] = 100 * (i as u32 + 1) + j as u32;
        }
    }
    let mut data = vec![0u32; 24];
    assert_eq!(fill(&mut data), Ok(()));
    assert_eq!(data, expected);
    let mut pooled = vec![0u32; 24];
    assert_eq!(parallel::with_threads(3, || fill(&mut pooled)), Ok(()));
    assert_eq!(pooled, expected);
    // Overlap, descending order and a block past the end are refused before any write.
    for bad in [
        vec![(0usize, 4usize), (3, 2)],
        vec![(5, 1), (2, 1)],
        vec![(20, 5)],
        vec![(25, 0)],
    ] {
        let mut data = vec![0u32; 24];
        let result = parallel::for_each_block(&mut data, &bad, |_, block| {
            block.fill(1);
            Ok(())
        });
        assert_eq!(result, Err(Error::PublicShape), "{bad:?}");
        assert!(data.iter().all(|v| *v == 0));
    }
    // The first error in block order is returned.
    let mut data = vec![0u32; 24];
    let result = parallel::for_each_block(&mut data, &blocks, |i, _| match i {
        1 => Err(Error::Capacity),
        3 => Err(Error::PublicShape),
        _ => Ok(()),
    });
    assert_eq!(result, Err(Error::Capacity));
}
