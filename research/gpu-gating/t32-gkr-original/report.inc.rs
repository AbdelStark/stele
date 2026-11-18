// Every explicit H2D copy is attributed; offsets and strides passed by value are launch arguments.
assert_eq!(work.input_bytes, work.equality_bytes+work.block_challenge_bytes+work.block_mask_bytes+
    work.column_bytes+work.mask_bytes+work.layer_upload_bytes+work.public_challenge_bytes+
    work.public_table_bytes+work.selector_bytes);
assert_eq!(work.descriptor_bytes,work.coordinate_bytes+work.term_bytes);
eprintln!("gkr_inputs step={} lookup={} leaf={} original_views={} addressable_bytes={} equality={} block_challenge={} block_mask={} column={} mask={} layer={} table_challenge={} table={} selector={} coordinates={} terms={} inputs={} descriptors={}",
    step.step,step.lookup,usize::from(step.leaf),work.original_views,work.original_bytes,work.equality_bytes,
    work.block_challenge_bytes,work.block_mask_bytes,work.column_bytes,work.mask_bytes,work.layer_upload_bytes,
    work.public_challenge_bytes,work.public_table_bytes,work.selector_bytes,work.coordinate_bytes,
    work.term_bytes,work.input_bytes,work.descriptor_bytes);
