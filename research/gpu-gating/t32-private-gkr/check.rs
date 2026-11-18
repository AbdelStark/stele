//! RFC-0013 A5. Compare every original window to the independently built CPU mask.
use crate::{K, M31};
use stele_reductions::zk::claims::bench::{GkrCase, GkrConstruction, GkrFactor};

pub fn check(step: &GkrCase<'_, K>, input: &GkrConstruction<'_, K>) -> (usize, usize) {
    assert_eq!(input.factors.len(), input.private_windows.len());
    let (mut count, mut bytes) = (0, 0);
    for (factor, origins) in input.factors.iter().zip(&input.private_windows) {
        let expected: Vec<(usize, &[M31])> = match factor {
            GkrFactor::Block { values, .. } => vec![(0, values)],
            GkrFactor::Column { mask, .. } | GkrFactor::Layer { mask, .. } => {
                vec![(0, &mask.values)]
            }
            GkrFactor::Combined { members, .. } => members
                .iter()
                .map(|m| (m.range.start, m.mask.as_slice()))
                .collect(),
            _ => vec![],
        };
        assert_eq!(expected.len(), origins.len());
        for ((start, values), &[begin, id, rows, cols, at, len]) in
            expected.into_iter().zip(origins)
        {
            let message = (step.private_message)(id).expect("actual certified original");
            assert_eq!(
                (begin, len, rows.checked_mul(cols)),
                (start, values.len(), Some(message.len()))
            );
            assert!(
                rows >= 2
                    && cols >= 2
                    && at
                        .checked_add(len)
                        .is_some_and(|end| end <= message.len() / 4)
            );
            for (i, v) in values.iter().enumerate() {
                let p = at + i;
                assert_eq!(
                    *v,
                    message[p / (cols / 2) * cols + p % (cols / 2)],
                    "private GKR source window"
                );
            }
            count += 1;
            bytes += 4 * len;
        }
    }
    (count, bytes)
}
