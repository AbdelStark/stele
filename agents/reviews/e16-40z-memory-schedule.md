# E16-40z independent memory-schedule review

The independent lane-Z reviewer checked the research allocation schedule at source `025cd299` and the final frozen candidate `888ccdd8`. Construction allocates the destination, then one span's uploaded data and shifts. Descriptor and round scratch allocations follow all span uploads. First-fold M31 promotion keeps the old buffer live until the new QM31 buffer is populated. A vanishing mask at coordinate zero survives through the combined fold then drops. Surviving QM31 tables fold in place.

The final-child path checks the device, lookup identity and bottom width. The tree owns every borrowed child through all construction kernels and their synchronization. The consuming path drops and synchronizes the owner before checking space for the first fold. A budget rejection on this path consumes the owner and invalidates the qualification. The T32 success criterion checks every step and all 21 releases.

The reviewer accepted this ownership boundary for a bounded H100 campaign and requested an explicit positive bound for both memory phases in the receipt. The post-capture parser checks both bounds and the ordering of current and high-water CUDA pool counters. The scheduled job source and its independently archived receipts are frozen.

Reviewed by codex-source-visits, lane Z, and codex-root.
