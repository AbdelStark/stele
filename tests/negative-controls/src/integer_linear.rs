//! RFC-0024 §6: complete accepted baseline, one encoded K value, actual rejection.
use crate::{check_control, check_proof_control, ProverHook};
use stele_field::{Field, M31, OM31, QM31};
use stele_gkr::stacked;
use stele_hash::{ChallengeField, HashUsage, Transcript};
use stele_pcs::{verify_certificate, CodeField, PreparedSource, ProofKind};
use stele_reductions::{
    byte_range, integer_linear as linear, lookup, matmul,
    requant::{EmbeddedSchema, Format},
};

const LIMITS: lookup::Limits = lookup::Limits {
    positions: 1 << 16,
    public_bytes: 64 << 20,
    proof_bytes: 64 << 20,
};
const MATMUL: stacked::Limits = stacked::Limits {
    descriptor_bytes: 1 << 20,
    proof_bytes: 1 << 20,
    prepared_entries: 1 << 16,
    partial_entries: 1 << 16,
    axis_entries: 0,
};
#[path = "integer_linear_composer.rs"]
mod composer;
#[path = "integer_linear_replay.rs"]
pub mod replay;
struct Cell {
    at: usize,
    value: Vec<u8>,
}
impl ProverHook<Vec<u8>> for Cell {
    fn tamper(&self, wire: &mut Vec<u8>) {
        let before = wire.clone();
        let end = self.at + self.value.len();
        assert_ne!(&before[self.at..end], &self.value);
        wire[self.at..end].copy_from_slice(&self.value);
        assert_eq!(&wire[..self.at], &before[..self.at]);
        assert_eq!(&wire[end..], &before[end..]);
        assert_eq!(wire.len(), before.len());
    }
}
/// Execute the specified new binding in both fields and both repetition counts.
pub fn run(id: u16) -> Result<(), String> {
    run_field::<QM31>(id, None)?;
    run_field::<OM31>(id, None)
}
/// Observe the same control execution; every request must be verified again by its consumer.
pub fn run_observed<K: ChallengeField + CodeField + lookup::TableField + Eq + core::fmt::Debug>(
    id: u16,
    observer: &dyn Fn(replay::Attempt<'_, K>),
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    run_field::<K>(id, Some(observer))
}
fn run_field<K: ChallengeField + CodeField + lookup::TableField + Eq + core::fmt::Debug>(
    id: u16,
    observer: replay::Observer<'_, K>,
) -> Result<(), String>
where
    for<'b> K::Bytes: TryFrom<&'b [u8]>,
{
    for repetitions in 1..=2 {
        let cases = match id {
            606 => vec![([0; 4], Some(0)), ([0; 4], Some(1))],
            306 | 611 => vec![([0, 1, 0, 1], Some(0)), ([0, 1, 0, 1], Some(1))],
            307 => vec![
                ([0, 1, 0, 1], Some(0)),
                ([0, 1, 0, 1], Some(1)),
                ([1; 4], Some(0)),
                ([1; 4], Some(1)),
            ],
            802 => vec![([0; 4], None), ([1; 4], None)],
            605 => vec![([0; 4], None), ([1; 4], None)],
            _ => vec![([0; 4], None)],
        };
        for (bits, side) in cases {
            let [h, a, b, c] = bits;
            let columns = 1usize << (h + b);
            let messages: [Vec<M31>; 2] = core::array::from_fn(|source| {
                (0..columns * (1 << if source == 0 { a } else { c }))
                    .map(|i| {
                        let value = if let Some(changed) = side {
                            if changed != source {
                                128
                            } else {
                                let row = i / columns;
                                let layer = (i % columns) >> b;
                                let inner = i & ((1 << b) - 1);
                                128 + row * 13 + layer * 5 + inner * 7 + layer * inner * 3
                            }
                        } else if source == 0 {
                            125 + i % 7
                        } else {
                            126 + i % 5
                        };
                        M31::from_i64(value as i64)
                    })
                    .collect()
            });
            let [x, w] = messages.each_ref();
            let px = PreparedSource::<K>::new(101, a, h + b, 1, x, &mut HashUsage::default())
                .expect("valid fixed fixture");
            let pw = PreparedSource::<K>::new(102, c, h + b, 2, w, &mut HashUsage::default())
                .expect("valid fixed fixture");
            let xp = px.certificate().expect("valid fixed fixture").0;
            let wp = pw.certificate().expect("valid fixed fixture").0;
            let cx = verify_certificate(*px.source(), &xp)
                .expect("valid fixed fixture")
                .0;
            let cw = verify_certificate(*pw.source(), &wp)
                .expect("valid fixed fixture")
                .0;
            let dx = byte_range::Descriptor::new(&cx, 9, &[111, 112][..repetitions], LIMITS)
                .expect("valid fixed fixture");
            let dw = byte_range::Descriptor::new(&cw, 10, &[121, 122][..repetitions], LIMITS)
                .expect("valid fixed fixture");
            let range = |d: &byte_range::Descriptor<'_, K>, p: &PreparedSource<'_, K>| {
                d.prove(
                    p,
                    lookup::ProducerLimits {
                        public_bytes: d.producer_public_bytes().expect("valid fixed fixture"),
                        dense_elements: d.producer_dense_elements().expect("valid fixed fixture"),
                    },
                )
                .expect("valid fixed fixture")
                .0
            };
            let rx = range(&dx, &px);
            let rw = range(&dw, &pw);
            let mx = dx
                .register_multiplicities(&rx, usize::MAX)
                .expect("valid fixed fixture")
                .0;
            let mw = dw
                .register_multiplicities(&rw, usize::MAX)
                .expect("valid fixed fixture")
                .0;
            let mxr: Vec<_> = mx.iter().collect();
            let mwr: Vec<_> = mw.iter().collect();
            let xr = dx.verify(&mxr, &rx).expect("valid fixed fixture");
            let wr = dw.verify(&mwr, &rw).expect("valid fixed fixture");
            let schema = EmbeddedSchema::new(b, 1, 1, Format::Int8).expect("valid fixed fixture");
            // Fixture capture is separate setup, never evidence of an online proof pass.
            let mut captured = Vec::new();
            for layer in 0..1usize << h {
                for i in 0..1usize << a {
                    for j in 0..1usize << c {
                        captured.push(
                            (0..1usize << b)
                                .map(|k| {
                                    (i64::from(x[i * columns + (layer << b) + k].as_u32()) - 128)
                                        * (i64::from(w[j * columns + (layer << b) + k].as_u32())
                                            - 128)
                                })
                                .sum::<i64>() as i32,
                        );
                    }
                }
            }
            let point: Vec<_> = (0..h + a + c)
                .map(|i| K::from_i64(2 + i64::from(i)))
                .collect();
            let value = stele_poly::eq_table(&point)
                .expect("fixture point")
                .iter()
                .zip(&captured)
                .fold(K::from_i64(0), |sum, (weight, value)| {
                    sum + *weight * K::from_i64(i64::from(value.signum() * ((value.abs() + 1) / 2)))
                });
            let witness = schema
                .witness(&captured, 1 << 16)
                .expect("valid fixed fixture");
            let pa = PreparedSource::<K>::new(
                (31u64 << 40) + 2,
                schema.rows().ilog2() as u8,
                h + a + c,
                1,
                witness.advice(),
                &mut HashUsage::default(),
            )
            .expect("valid fixed fixture");
            let certificate = pa.certificate().expect("valid fixed fixture").0;
            let ca = verify_certificate(*pa.source(), &certificate)
                .expect("valid fixed fixture")
                .0;
            let expected = linear::Statement {
                stage: 31,
                bits,
                mantissa: 1,
                shift: 1,
                format: Format::Int8,
                repetitions: repetitions as u8,
                advice_blowup: 1,
                point: &point,
                value,
                originals: [&xr, &wr],
            };
            let replay = replay::Context {
                id,
                bits,
                repetitions,
                side,
                point: &point,
                value,
                originals: [
                    replay::Original {
                        source: *px.source(),
                        certificate: &xp,
                        range: &rx,
                    },
                    replay::Original {
                        source: *pw.source(),
                        certificate: &wp,
                        range: &rw,
                    },
                ],
            };
            let d = linear::Descriptor::new(expected, &ca, LIMITS, MATMUL)
                .expect("valid fixed fixture");
            let transcript = || {
                Transcript::<K>::new(b"RFC0024/complete-control/v1").expect("valid fixed fixture")
            };
            let produce = || {
                d.prove(
                    &mut transcript(),
                    [&px, &pw],
                    &pa,
                    &certificate,
                    linear::ProducerLimits {
                        public_bytes: d.producer_public_bytes().expect("valid fixed fixture"),
                        dense_elements: d.producer_dense_elements().expect("valid fixed fixture"),
                        retained_row_entries: d.retained_row_entries(),
                    },
                )
            };
            let (honest, producer_usage) =
                produce().map_err(|f| format!("honest producer:{f:?}"))?;
            let mu = d
                .register_multiplicities(&honest, usize::MAX)
                .expect("valid fixed fixture")
                .0;
            let refs: Vec<_> = mu.iter().collect();
            if id == 605 {
                // RFC-0007 A1 item 7 NC-0605(b): honest centered sumcheck; the W opening
                // serializes the centered B instead of the raw retained row B + 128.
                let packet = composer::compose(
                    &d,
                    &expected,
                    &schema,
                    [&px, &pw],
                    &pa,
                    &ca,
                    &certificate,
                    b"RFC0024/complete-control/v1",
                    composer::Attack::Honest,
                    None,
                    None,
                );
                assert_eq!(packet.wire, honest);
                let encode = |row: &[K]| -> Vec<u8> {
                    row.iter()
                        .flat_map(|v| v.to_le_bytes().as_ref().to_vec())
                        .collect()
                };
                let raw = encode(&packet.rows[1]);
                let at: Vec<_> = (0..=honest.len() - raw.len())
                    .filter(|i| honest[*i..*i + raw.len()] == raw[..])
                    .collect();
                assert_eq!(at.len(), 1, "one raw W row in the wire");
                let shift = K::from_i64(128)
                    * stele_poly::eq_table(&packet.join_point[usize::from(h + a)..])
                        .expect("fixture point")
                        .iter()
                        .fold(K::from_i64(0), |sum, e| sum + *e);
                let centered: Vec<K> = packet.rows[1].iter().map(|u| *u - shift).collect();
                let rejected =
                    linear::Error::Matmul(matmul::Error::Pcs(stele_pcs::Error::ValueMismatch));
                check_proof_control(
                    || Ok::<_, String>(honest.clone()),
                    &Cell {
                        at: at[0],
                        value: encode(&centered),
                    },
                    |wire| {
                        let mut t = transcript();
                        let result = d.verify(&mut t, &refs, wire);
                        result.map(|_| ()).map_err(|failure| {
                            // No W column draw and no W path: only frame and row absorbs.
                            let mut prefix = packet.original_prefix[1][0];
                            prefix.hash_evaluations += 2;
                            prefix.state_updates += 2;
                            assert_eq!(failure.usage.transcript, prefix);
                            let source = pw.source();
                            assert_eq!(
                                failure.usage.non_transcript.hash_evaluations,
                                d.max_local_hashes()
                                    - u64::from(source.queries(ProofKind::Opening))
                                        * (1 + source.path_height() as u64)
                            );
                            failure.cause
                        })
                    },
                    rejected,
                )
                .map_err(|e| {
                    format!(
                        "NC-0605(b) K{}, r{repetitions}, {bits:?}: {e:?}",
                        <K as CodeField>::DEGREE
                    )
                })?;
                continue;
            }
            if id == 606 {
                let side = side.expect("one original source context");
                let changed = [M31::from_i64(129)];
                let replacement = PreparedSource::<K>::new(
                    101 + side as u64,
                    0,
                    0,
                    1 + side as u8,
                    &changed,
                    &mut HashUsage::default(),
                )
                .expect("genuine replacement source");
                let replacement_packet = replacement.certificate().expect("genuine packet").0;
                let owner = verify_certificate(*replacement.source(), &replacement_packet)
                    .expect("genuine replacement owner")
                    .0;
                let ids = if side == 0 { [111, 112] } else { [121, 122] };
                let range_descriptor = byte_range::Descriptor::new(
                    &owner,
                    9 + side as u64,
                    &ids[..repetitions],
                    LIMITS,
                )
                .expect("same fixed whole-source range policy");
                let range_proof = range(&range_descriptor, &replacement);
                let range_mu = range_descriptor
                    .register_multiplicities(&range_proof, usize::MAX)
                    .expect("genuine replacement range imports")
                    .0;
                let range_refs: Vec<_> = range_mu.iter().collect();
                let replacement_range = range_descriptor
                    .verify(&range_refs, &range_proof)
                    .expect("actual replacement byte-range event");
                let baseline = RangeWitness { ranges: [&xr, &wr] };
                check_control(
                    &baseline,
                    &ChangeRange {
                        side,
                        replacement: &replacement_range,
                    },
                    |changed: &RangeWitness<'_, K>| -> Result<_, String> {
                        let statement = linear::Statement {
                            originals: changed.ranges,
                            ..expected
                        };
                        let descriptor = linear::Descriptor::new(statement, &ca, LIMITS, MATMUL)
                            .expect("genuine range context");
                        // Only the original range handle changes. The affected response owner
                        // remains the original prepared source; every dependent message is rebuilt.
                        let packet = composer::compose(
                            &descriptor,
                            &statement,
                            &schema,
                            [&px, &pw],
                            &pa,
                            &ca,
                            &certificate,
                            b"RFC0024/complete-control/v1",
                            composer::Attack::Honest,
                            None,
                            None,
                        );
                        assert!(packet.rows.iter().flatten().all(|v| *v == K::from_i64(128)));
                        assert!(packet.matmul.final_values[..2]
                            .iter()
                            .all(|v| *v == K::from_i64(0)));
                        if changed == &baseline {
                            assert_eq!(packet.wire, honest);
                        }
                        Ok((*changed, packet))
                    },
                    |(changed, packet)| {
                        let statement = linear::Statement {
                            originals: changed.ranges,
                            ..expected
                        };
                        let descriptor = linear::Descriptor::new(statement, &ca, LIMITS, MATMUL)
                            .expect("expected genuine source context");
                        let owners = descriptor
                            .register_multiplicities(&packet.wire, usize::MAX)
                            .expect("actual advice multiplicity imports")
                            .0;
                        let refs: Vec<_> = owners.iter().collect();
                        let mut t = transcript();
                        let result = descriptor.verify(&mut t, &refs, &packet.wire);
                        let mut context = replay;
                        if changed != &baseline {
                            context.originals[side] = replay::Original {
                                source: *replacement.source(),
                                certificate: &replacement_packet,
                                range: &range_proof,
                            };
                        }
                        context.emit(observer, "range-context", &packet.wire, &mut t, &result);
                        result.map(|_| ()).map_err(|failure| {
                            assert_eq!(failure.usage.transcript, t.usage());
                            assert_eq!(failure.usage.transcript, packet.original_prefix[side][1]);
                            let mut hashes = descriptor.max_local_hashes();
                            for range in &changed.ranges[side..] {
                                let source = range.original().record().source();
                                hashes -= u64::from(source.queries(ProofKind::Opening))
                                    * (1 + source.path_height() as u64);
                            }
                            hashes += 1 + changed.ranges[side]
                                .original()
                                .record()
                                .source()
                                .path_height() as u64;
                            assert_eq!(failure.usage.non_transcript.hash_evaluations, hashes);
                            failure.cause
                        })
                    },
                    linear::Error::Matmul(matmul::Error::Pcs(stele_pcs::Error::Merkle(
                        stele_hash::merkle::Error::RootMismatch,
                    ))),
                )
                .map_err(|e| {
                    format!(
                        "NC-0606 K{}, r{repetitions}, source {side}: {e:?}",
                        <K as CodeField>::DEGREE
                    )
                })?;
                continue;
            }
            if matches!(id, 306 | 307 | 312 | 611 | 802 | 610) {
                use composer::Attack;
                let compose = |attack: Attack,
                               template: Option<&composer::Packet<K>>,
                               view: Option<composer::View<'_, K>>| {
                    composer::compose(
                        &d,
                        &expected,
                        &schema,
                        [&px, &pw],
                        &pa,
                        &ca,
                        &certificate,
                        b"RFC0024/complete-control/v1",
                        attack,
                        template,
                        view,
                    )
                };
                let mut baseline = compose(Attack::Honest, None, None);
                assert_eq!(
                    baseline.wire, honest,
                    "composer must match the complete actual producer"
                );
                assert_eq!(baseline.transcript.usage(), producer_usage.transcript);
                if let Some(side) = side {
                    use crate::matmul::{ChangeFinal, ChangeRow, RowWitness};
                    use composer::View;
                    let originals = [&px, &pw];
                    assert_eq!(baseline.rows[1 - side], vec![K::from_i64(128); columns]);
                    let error = if id == 307 {
                        stele_pcs::Error::ValueMismatch
                    } else {
                        stele_pcs::Error::ColumnMismatch
                    };
                    let rejected = linear::Error::Matmul(matmul::Error::Pcs(error));
                    let checked = |packet: &composer::Packet<K>| {
                        let mut t = transcript();
                        let result = d.verify(&mut t, &refs, &packet.wire);
                        replay.emit(observer, "original", &packet.wire, &mut t, &result);
                        result.map(|_| ()).map_err(|failure| {
                            assert_eq!(failure.cause, rejected, "actual original consumer");
                            assert_eq!(failure.usage.transcript, t.usage());
                            let mut hashes = d.max_local_hashes();
                            for source in &originals[side..] {
                                hashes -= u64::from(source.source().queries(ProofKind::Opening))
                                    * (1 + source.source().path_height() as u64);
                            }
                            let exact = if id == 307 {
                                let mut prefix = packet.original_prefix[side][0];
                                prefix.hash_evaluations += 2;
                                prefix.state_updates += 2;
                                prefix
                            } else {
                                hashes += 1 + originals[side].source().path_height() as u64;
                                packet.original_prefix[side][1]
                            };
                            assert_eq!(
                                failure.usage.transcript, exact,
                                "actual first-query or no-query prefix"
                            );
                            assert_eq!(failure.usage.non_transcript.hash_evaluations, hashes);
                            failure.cause
                        })
                    };
                    if id == 307 {
                        let replacement = if h + b == 0 {
                            baseline.matmul.final_values[side] + K::from_i64(1)
                        } else {
                            assert_eq!(baseline.matmul_point.len(), 2);
                            assert!(baseline
                                .matmul_point
                                .iter()
                                .all(|q| *q != K::from_i64(0) && *q != K::from_i64(1)));
                            let mut full = if side == 0 {
                                baseline.join_point[usize::from(h)..usize::from(h + a)].to_vec()
                            } else {
                                baseline.join_point[usize::from(h + a)..].to_vec()
                            };
                            full.extend_from_slice(&baseline.matmul_point);
                            let raw =
                                crate::matmul::composer::original_value(originals[side], &full);
                            assert_eq!(raw - K::from_i64(128), baseline.matmul.final_values[side]);
                            let end = full.len();
                            full.swap(end - 2, end - 1);
                            crate::matmul::composer::original_value(originals[side], &full)
                                - K::from_i64(128)
                        };
                        assert_ne!(replacement, baseline.matmul.final_values[side]);
                        check_control(
                            &baseline.matmul,
                            &ChangeFinal {
                                index: side,
                                value: replacement,
                            },
                            |proof| -> Result<_, String> {
                                let packet =
                                    compose(Attack::Honest, None, Some(View::Proof(proof)));
                                assert_eq!(
                                    packet.rows, baseline.rows,
                                    "retained raw rows do not change"
                                );
                                assert_eq!(packet.matmul_point, baseline.matmul_point);
                                if proof == &baseline.matmul {
                                    assert_eq!(packet.wire, honest);
                                }
                                Ok(packet)
                            },
                            checked,
                            rejected,
                        )
                        .map_err(|e| {
                            format!(
                                "NC-0307 K{}, r{repetitions}, {bits:?}, source {side}: {e:?}",
                                <K as CodeField>::DEGREE
                            )
                        })?;
                    } else {
                        let view = RowWitness {
                            point: baseline.join_point.clone(),
                            rows: baseline.rows.clone(),
                        };
                        check_control(
                            &view,
                            &ChangeRow {
                                id,
                                side,
                                coordinate: usize::from(if side == 0 { h } else { h + a }),
                            },
                            |changed| -> Result<_, String> {
                                let override_ = if id == 306 {
                                    View::Point(&changed.point)
                                } else {
                                    View::Rows(&changed.rows)
                                };
                                let packet = compose(Attack::Honest, None, Some(override_));
                                assert_eq!(packet.rows[1 - side], baseline.rows[1 - side]);
                                assert_eq!(
                                    packet.join_point, baseline.join_point,
                                    "actual A3 join remains fixed"
                                );
                                if changed == &view {
                                    assert_eq!(packet.wire, honest);
                                } else {
                                    assert_ne!(packet.rows[side], baseline.rows[side]);
                                }
                                Ok(packet)
                            },
                            checked,
                            rejected,
                        )
                        .map_err(|e| {
                            format!(
                                "NC-{id:04} K{}, r{repetitions}, source {side}: {e:?}",
                                <K as CodeField>::DEGREE
                            )
                        })?;
                    }
                    continue;
                }
                if id == 610 || id == 312 {
                    let width = core::mem::size_of::<K>();
                    let opening_hashes = |s: &stele_pcs::Source<K>| {
                        u64::from(s.queries(ProofKind::Opening)) * (1 + s.path_height() as u64)
                    };
                    let variants = if id == 312 {
                        vec![(2, Attack::WrongPlane)]
                    } else {
                        (0u8..4)
                            .flat_map(|phase| {
                                [Attack::SwapWeights(phase), Attack::OmitWeight(phase)]
                                    .map(|attack| (usize::from(phase.max(1) - 1), attack))
                            })
                            .collect()
                    };
                    for (group, attack) in variants {
                        let other = compose(attack, None, None);
                        let at = baseline.group_offsets[group] + 1;
                        let replacement = other.group_offsets[group] + 1;
                        check_proof_control(
                            || Ok::<_, String>(honest.clone()),
                            &Cell {
                                at,
                                value: other.wire[replacement..replacement + width].to_vec(),
                            },
                            |proof| {
                                let mut t = transcript();
                                let result = d.verify(&mut t, &refs, proof);
                                replay.emit(
                                    observer,
                                    &format!("{attack:?}"),
                                    proof,
                                    &mut t,
                                    &result,
                                );
                                result.map(|_| ()).map_err(|failure| {
                                    assert_eq!(failure.usage.transcript, t.usage());
                                    let mut exact = baseline.group_prefix[group];
                                    exact.hash_evaluations += 2;
                                    exact.state_updates += 2;
                                    assert_eq!(
                                        failure.usage.transcript, exact,
                                        "no affected-group query"
                                    );
                                    assert_eq!(
                                        failure.usage.non_transcript.hash_evaluations,
                                        d.max_local_hashes()
                                            - (3 - group as u64) * opening_hashes(pa.source())
                                            - opening_hashes(px.source())
                                            - opening_hashes(pw.source())
                                    );
                                    failure.cause
                                })
                            },
                            linear::Error::Pcs(stele_pcs::Error::ValueMismatch),
                        )
                        .map_err(|e| {
                            format!(
                                "NC-{id:04} K{}, r{repetitions}, {attack:?}: {e:?}",
                                <K as CodeField>::DEGREE
                            )
                        })?;
                    }
                    continue;
                }
                let next = next::<K>();
                let following = |t: &mut Transcript<K>| {
                    stele_sumcheck::prove(
                        &next,
                        stele_sumcheck::Dense::new(
                            &next,
                            vec![vec![K::from_i64(1), K::from_i64(2)]],
                        )
                        .expect("following table"),
                        t,
                    )
                    .expect("actual following A1 producer")
                };
                let accepted = following(&mut baseline.transcript);
                let mut replay = compose(Attack::ReplayResponses, Some(&baseline), None);
                assert_eq!(
                    replay.wire, honest,
                    "actual response replay matches complete proof"
                );
                assert_eq!(following(&mut replay.transcript), accepted);
                assert_eq!(replay.transcript.usage(), baseline.transcript.usage());
                for frame in 0..7 {
                    let mut other = compose(Attack::OmitFrame(frame), Some(&baseline), None);
                    let wrong = following(&mut other.transcript);
                    assert_eq!(wrong.rounds, accepted.rounds);
                    check_proof_control(
                        || Ok::<_, String>(accepted.clone()),
                        &Final(wrong.final_values[0]),
                        |proof| {
                            let mut t = transcript();
                            let (_, usage) = d
                                .verify(&mut t, &refs, &honest)
                                .map_err(|f| ChainError::Linear(f.cause))?;
                            assert_eq!(usage.transcript, t.usage());
                            let result = stele_sumcheck::verify_public(
                                &next,
                                proof,
                                &[vec![K::from_i64(1), K::from_i64(2)]],
                                &mut t,
                            );
                            let mut expected = baseline.transcript.usage();
                            if result.is_err() {
                                // A1 checks the final before absorbing it; all prior work remains.
                                expected.hash_evaluations -= 1;
                                expected.state_updates -= 1;
                            }
                            assert_eq!(t.usage(), expected, "exact following-A1 prefix");
                            result.map(|_| ()).map_err(ChainError::Sumcheck)
                        },
                        ChainError::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
                    )
                    .map_err(|e| {
                        format!(
                            "NC-0802 K{}, r{repetitions}, frame {frame}: {e:?}",
                            <K as CodeField>::DEGREE
                        )
                    })?;
                }
                continue;
            }
            let width = core::mem::size_of::<K>();
            let suffix = 1
                + 3 * width
                + px.source()
                    .proof_size(ProofKind::Opening)
                    .expect("valid fixed fixture")
                + pw.source()
                    .proof_size(ProofKind::Opening)
                    .expect("valid fixed fixture");
            let start = honest.len() - suffix;
            let (at, value, expected) = match id {
                314 | 316 => {
                    let q = schema.semantic().values()[2].value().len();
                    let zero_end = start
                        - 3 * pa
                            .source()
                            .proof_size(ProofKind::Opening)
                            .expect("valid fixed fixture")
                        - width * (q + 2);
                    let zero_start = zero_end - width * (schema.rows() + 1);
                    let ordinal = if id == 314 {
                        assert!(schema.rows() > schema.allocated_rows());
                        schema.rows()
                    } else {
                        1 + schema.semantic().allocated_rows() + 7
                    };
                    assert_eq!(
                        &honest[zero_start + ordinal * width..zero_start + (ordinal + 1) * width],
                        K::from_i64(0).to_le_bytes().as_ref()
                    );
                    if id == 314 {
                        let mut values: Vec<K> = honest[zero_start..zero_end]
                            .chunks_exact(width)
                            .map(|raw| {
                                K::from_le_bytes(K::Bytes::try_from(raw).ok().expect("field width"))
                                    .expect("canonical finals")
                            })
                            .collect();
                        values[ordinal] = K::from_i64(1);
                        let constraints = schema
                            .constraints::<K>()
                            .expect("actual embedded equations");
                        let failed: Vec<_> = constraints
                            .equations()
                            .iter()
                            .filter(|equation| {
                                equation.iter().fold(K::from_i64(0), |sum, term| {
                                    sum + term
                                        .factors
                                        .iter()
                                        .fold(term.coefficient, |product, factor| {
                                            product * values[*factor as usize]
                                        })
                                }) != K::from_i64(0)
                            })
                            .collect();
                        assert_eq!(
                            failed.len(),
                            1,
                            "only the physical reserved-plane equation fails"
                        );
                        assert_eq!(failed[0].len(), 1);
                        assert_eq!(failed[0][0].coefficient, K::from_i64(1));
                        assert_eq!(failed[0][0].factors, vec![ordinal as u32]);
                    }
                    (
                        zero_start + ordinal * width,
                        K::from_i64(1),
                        linear::Error::Sumcheck(stele_sumcheck::Error::FinalEvaluationMismatch),
                    )
                }
                317 => (
                    start + 1,
                    K::from_i64(-2),
                    linear::Error::Matmul(matmul::Error::Stacked(stacked::Error::Sumcheck(
                        stele_sumcheck::Error::FinalEvaluationMismatch,
                    ))),
                ),
                318 => (
                    start + 1 + 3 * width + 1,
                    K::from_i64(-3),
                    linear::Error::Matmul(matmul::Error::Pcs(stele_pcs::Error::ValueMismatch)),
                ),
                _ => return Err(format!("unknown integer-linear control {id}")),
            };
            check_proof_control(
                // The actual producer already ran above so its mu packets could be imported.
                || Ok::<_, core::convert::Infallible>(honest.clone()),
                &Cell {
                    at,
                    value: value.to_le_bytes().as_ref().to_vec(),
                },
                |proof| {
                    let mut t = transcript();
                    let result = d.verify(&mut t, &refs, proof);
                    replay.emit(observer, "proof-value", proof, &mut t, &result);
                    result.map(|_| ()).map_err(|f| {
                        assert_eq!(f.usage.transcript, t.usage());
                        if id == 314 || id == 316 {
                            let opening_hashes = |s: &stele_pcs::Source<K>| {
                                u64::from(s.queries(ProofKind::Opening))
                                    * (1 + s.path_height() as u64)
                            };
                            assert_eq!(
                                f.usage.non_transcript.hash_evaluations,
                                d.max_local_hashes()
                                    - 3 * opening_hashes(pa.source())
                                    - opening_hashes(px.source())
                                    - opening_hashes(pw.source())
                            );
                        }
                        if id == 318 {
                            let original_hashes: u64 = [px.source(), pw.source()]
                                .iter()
                                .map(|s| {
                                    u64::from(s.queries(ProofKind::Opening))
                                        * (1 + s.path_height() as u64)
                                })
                                .sum();
                            assert_eq!(
                                f.usage.non_transcript.hash_evaluations,
                                d.max_local_hashes() - original_hashes
                            );
                        }
                        f.cause
                    })
                },
                expected,
            )
            .map_err(|e| {
                format!(
                    "NC-{id:04}, K{}, r{repetitions}: {e:?}",
                    <K as CodeField>::DEGREE
                )
            })?;
        }
    }
    Ok(())
}

fn next<K: ChallengeField>() -> stele_sumcheck::Instance<K> {
    let base = 31u64 << 40;
    stele_sumcheck::Instance {
        id: base + (1 << 29),
        num_vars: 1,
        inputs: vec![base + (1 << 29) + 1],
        terms: vec![stele_sumcheck::Term {
            coefficient: K::from_i64(1),
            factors: vec![0],
        }],
        claimed_sum: K::from_i64(3),
    }
}
struct Final<K>(K);
impl<K: ChallengeField + Eq + core::fmt::Debug> ProverHook<stele_sumcheck::Proof<K>> for Final<K> {
    fn tamper(&self, proof: &mut stele_sumcheck::Proof<K>) {
        let before = proof.clone();
        assert_eq!(proof.final_values.len(), 1);
        assert_ne!(proof.final_values[0], self.0);
        proof.final_values[0] = self.0;
        assert_eq!(proof.rounds, before.rounds);
    }
}
#[derive(Debug, Eq, PartialEq)]
enum ChainError {
    Linear(linear::Error),
    Sumcheck(stele_sumcheck::Error),
}

#[derive(Clone, Copy)]
struct RangeWitness<'a, K: ChallengeField> {
    ranges: [&'a byte_range::ByteRange<'a, K>; 2],
}
impl<K: ChallengeField> PartialEq for RangeWitness<'_, K> {
    fn eq(&self, other: &Self) -> bool {
        self.ranges
            .iter()
            .zip(other.ranges)
            .all(|(a, b)| core::ptr::eq(*a, b))
    }
}
struct ChangeRange<'a, K: ChallengeField> {
    side: usize,
    replacement: &'a byte_range::ByteRange<'a, K>,
}
impl<'a, K: ChallengeField> ProverHook<RangeWitness<'a, K>> for ChangeRange<'a, K> {
    fn tamper(&self, witness: &mut RangeWitness<'a, K>) {
        let before = witness.ranges;
        let old = before[self.side].original().record().source();
        let new = self.replacement.original().record().source();
        assert_eq!(old.descriptor().id, new.descriptor().id);
        assert_eq!(
            (old.rows(), old.columns(), old.code_id()),
            (new.rows(), new.columns(), new.code_id())
        );
        assert_eq!(
            before[self.side].lookup().parameters().id,
            self.replacement.lookup().parameters().id
        );
        assert_ne!(old.root(), new.root());
        witness.ranges[self.side] = self.replacement;
        assert_eq!(
            before
                .iter()
                .zip(witness.ranges)
                .filter(|(a, b)| !core::ptr::eq(**a, *b))
                .count(),
            1
        );
    }
}
