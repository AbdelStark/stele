//! RFC-0013 A5. Columns span data rows, with mask halves excluded.
use super::Column;

#[test]
fn matches_reference_physical_data_run_across_rows() {
    let column = Column::new(9, 1, 8, 8, 3, 11, 8, 1).unwrap();
    let physical: Vec<_> = (0..8).map(|i| column.physical(i).unwrap()).collect();
    assert_eq!(physical, [3, 8, 9, 10, 11, 16, 17, 18]);
    assert_eq!(column.physical(8), None);
}

#[test]
fn rejects_block_overlap_wrong_limb_count_and_bad_geometry() {
    assert!(Column::new(0, 1, 8, 8, 3, 10, 8, 1).is_none());
    assert!(Column::new(0, 1, 8, 8, 3, 11, 8, 4).is_none());
    assert!(Column::new(0, 1, 8, 7, 3, 11, 8, 1).is_none());
    assert!(Column::new(0, 1, 8, 8, 12, 20, 8, 1).is_none());
    let a = Column::new(0, 0, 8, 8, 0, 4, 4, 1).unwrap();
    let b = Column::new(1, 1, 8, 8, 0, 4, 4, 1).unwrap();
    assert_ne!(a, b); // Identical all-zero witnesses would still have distinct origins.
}
