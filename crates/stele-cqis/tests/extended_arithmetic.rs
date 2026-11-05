//! RFC-0025 schemas7–13/15–19: full-domain static metadata, not proof admission.
use serde_json::Value;
use stele_cqis::{bounds::arithmetic::*, model::Shape};

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let raw = self.0[..N].try_into().expect("fixture bytes");
        self.0 = &self.0[N..];
        raw
    }
    fn byte(&mut self) -> u8 {
        self.take::<1>()[0]
    }
    fn short(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }
    fn uint(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }
    fn shape(&mut self) -> AttentionShape {
        AttentionShape {
            heads: self.short(),
            groups: self.short(),
            width: self.short(),
            context: self.uint(),
        }
    }
    fn exp(&mut self, count: u32) -> Exponential {
        let (domain_bits, source_fraction, output_fraction, mode) =
            (self.byte(), self.byte(), self.byte(), self.byte());
        Exponential {
            count,
            domain_bits,
            source_fraction,
            output_fraction,
            mode,
            split: if mode == 0 { 0 } else { self.byte() },
        }
    }
    fn weighted(&mut self) -> Weighted {
        Weighted {
            shape: self.shape(),
            value_fraction: self.byte(),
            exp_fraction: self.byte(),
            policy: (self.byte(), self.short()),
            mode: self.byte(),
            drop: self.byte(),
        }
    }
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn derive(schema: u64, raw: &[u8]) -> Result<(Record, Option<u32>), Error> {
    let mut r = Reader(raw);
    if schema == 8 {
        let p = Score {
            shape: r.shape(),
            query_fraction: r.byte(),
            key_fraction: r.byte(),
            exp_fraction: r.byte(),
            query_policy: (r.byte(), r.short()),
            key_policy: (r.byte(), r.short()),
            multiplier: r.short(),
            exponent: r.byte() as i8,
        };
        assert!(r.0.is_empty());
        return Record::score(p).map(|(record, bound)| (record, Some(bound)));
    }
    let record = match schema {
        7 => Record::rotary(Rotary {
            heads: r.short(),
            width: r.short(),
            rotary_width: r.short(),
            context: r.uint(),
            layout: r.byte(),
            fraction: r.byte(),
        }),
        9 => Record::maximum(Maximum {
            context: r.uint(),
            score_bound: r.uint(),
            domain_bits: r.byte(),
            fraction: r.byte(),
        }),
        10 => {
            let n = r.uint();
            Record::exponential(r.exp(n))
        }
        11 => {
            let (dimension, kind, source_fraction, output_fraction) =
                (r.short(), r.byte(), r.byte(), r.byte());
            let (cap_m, cap_f) = if kind == 2 {
                (r.short(), r.byte())
            } else {
                (0, 0)
            };
            Record::activation(Activation {
                dimension,
                kind,
                source_fraction,
                output_fraction,
                cap_m,
                cap_f,
            })
        }
        12 => Record::weighted(r.weighted()),
        13 => Record::normalize(Normalize {
            source: r.weighted(),
            output_fraction: r.byte(),
        }),
        15 => Record::logits(Logits {
            vocabulary: r.uint(),
            fraction: r.byte(),
        }),
        16 => {
            let (n, logits_fraction, temperature) = (r.uint(), r.byte(), (r.uint(), r.uint()));
            Record::temperature(Temperature {
                logits_fraction,
                temperature,
                exp: r.exp(n),
            })
        }
        17 => Record::sampling(Sampling {
            vocabulary: r.uint(),
            exp_fraction: r.byte(),
            top_p: (r.uint(), r.uint()),
        }),
        18 => Record::request(Request {
            vocabulary: r.uint(),
            context: r.uint(),
            mode: r.byte(),
        }),
        19 => {
            let shape = Shape::decode(&r.take::<21>()).map_err(|_| Error::Parameters)?;
            let ordinal = r.short();
            let rank = r.byte();
            let dims: Vec<_> = (0..rank).map(|_| r.uint()).collect();
            assert_eq!(
                shape.physical(ordinal).expect("physical").dimensions(),
                dims
            );
            Record::physical(shape, ordinal, r.byte(), r.byte())
        }
        _ => unreachable!("fixture schema"),
    }?;
    assert!(r.0.is_empty());
    Ok((record, None))
}
fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/extended-arithmetic.json"))
        .expect("qualified pure reference")
}

#[test]
fn matches_reference_all_remaining_schemas_and_complete_boundary_bytes() {
    let data = fixtures();
    let mut complete = include_bytes!("fixtures/extended-arithmetic.bin").as_slice();
    let mut counts = [0usize; 20];
    for case in data["cases"].as_array().expect("cases") {
        let schema = case["schema"].as_u64().expect("schema");
        counts[schema as usize] += 1;
        let params = hex(case["parameters"].as_str().expect("parameters"));
        let (record, score_bound) = derive(schema, &params).expect("record");
        let raw = record.as_bytes();
        assert_eq!(raw.len() as u64, case["length"].as_u64().expect("length"));
        assert_eq!(
            blake3::hash(raw).to_hex().as_str(),
            case["digest"].as_str().expect("digest")
        );
        assert_eq!(score_bound.map(u64::from), case["score_bound"].as_u64());
        if case["complete"] == true {
            let n = u32::from_le_bytes(complete[..4].try_into().expect("length")) as usize;
            assert_eq!(raw, &complete[4..4 + n]);
            complete = &complete[4 + n..];
            let mut changed = raw.to_vec();
            for i in 0..raw.len() {
                changed[i] ^= 1;
                assert_eq!(record.validate_encoding(&changed), Err(Error::Encoding));
                changed[i] ^= 1;
                assert_eq!(record.validate_encoding(&raw[..i]), Err(Error::Encoding));
            }
            changed.push(0);
            assert_eq!(record.validate_encoding(&changed), Err(Error::Encoding));
            assert_eq!(record.validate_encoding(raw), Ok(()));
        }
    }
    assert!(complete.is_empty());
    for schema in [7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19] {
        assert!(counts[schema] >= 60, "schema{schema}");
    }
}

#[test]
fn rejects_static_score_and_full_block_failures_before_any_witness() {
    let data = fixtures();
    let cases = data["rejected"].as_array().expect("rejections");
    assert!(cases.len() > 40);
    for case in cases {
        let error = match case["error"].as_str().expect("error") {
            "ScoreBound" => Error::ScoreBound,
            "BlockBound" => Error::BlockBound,
            _ => unreachable!("error"),
        };
        let params = hex(case["parameters"].as_str().expect("parameters"));
        assert_eq!(
            derive(case["schema"].as_u64().expect("schema"), &params),
            Err(error)
        );
    }
    let shape = AttentionShape {
        heads: 1,
        groups: 1,
        width: 1,
        context: 1,
    };
    let p = Weighted {
        shape,
        value_fraction: 0,
        exp_fraction: 0,
        policy: (1, 32768),
        mode: 1,
        drop: 10,
    };
    assert_eq!(Record::weighted(p), Err(Error::BlockBound));
    assert_eq!(
        Record::normalize(Normalize {
            source: p,
            output_fraction: 0
        }),
        Err(Error::BlockBound)
    );
    assert!(Record::weighted(Weighted {
        policy: (1, 32767),
        ..p
    })
    .is_ok());
}

#[test]
fn rejects_parameter_domains_inactive_fields_and_noncanonical_rationals() {
    let data = fixtures();
    for case in data["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|c| c["complete"] == true)
    {
        let schema = case["schema"].as_u64().expect("schema");
        let mut params = hex(case["parameters"].as_str().expect("parameters"));
        let (at, len) = if schema == 19 {
            (3, 2)
        } else if [7, 8, 11, 12, 13].contains(&schema) {
            (0, 2)
        } else {
            (0, 4)
        };
        params[at..at + len].fill(0);
        assert_eq!(derive(schema, &params), Err(Error::Parameters));
        if schema == 19 {
            let original = hex(case["parameters"].as_str().expect("parameters"));
            let shape = Shape::decode(&original[..21]).expect("shape");
            let ordinal = u16::from_le_bytes([original[21], original[22]]);
            let matrix = original[23] == 2;
            assert_eq!(
                Record::physical(shape, ordinal, if matrix { 16 } else { 8 }, 0),
                Err(Error::Parameters)
            );
            assert_eq!(
                Record::physical(
                    shape,
                    ordinal,
                    if matrix { 8 } else { 16 },
                    if matrix { 1 } else { 31 }
                ),
                Err(Error::Parameters)
            );
            assert_eq!(
                Record::physical(shape, shape.record_count(), 8, 0),
                Err(Error::Parameters)
            );
        }
    }
    let exp = Exponential {
        count: 1,
        domain_bits: 7,
        source_fraction: 0,
        output_fraction: 0,
        mode: 0,
        split: 0,
    };
    for p in [
        Exponential { split: 1, ..exp },
        Exponential {
            domain_bits: 16,
            ..exp
        },
        Exponential {
            mode: 2,
            domain_bits: 16,
            split: 1,
            ..exp
        },
        Exponential {
            mode: 1,
            split: 0,
            ..exp
        },
        Exponential {
            mode: 1,
            split: 8,
            ..exp
        },
        Exponential { mode: 3, ..exp },
        Exponential {
            source_fraction: 31,
            ..exp
        },
        Exponential {
            output_fraction: 15,
            ..exp
        },
    ] {
        assert_eq!(Record::exponential(p), Err(Error::Parameters));
    }
    for temperature in [(0, 1), (1, 0), (2, 2)] {
        assert_eq!(
            Record::temperature(Temperature {
                logits_fraction: 0,
                temperature,
                exp
            }),
            Err(Error::Parameters)
        );
    }
    for top_p in [(0, 1), (1, 0), (2, 2), (2, 1)] {
        assert_eq!(
            Record::sampling(Sampling {
                vocabulary: 1,
                exp_fraction: 0,
                top_p
            }),
            Err(Error::Parameters)
        );
    }
    let activation = Activation {
        dimension: 1,
        kind: 2,
        source_fraction: 0,
        output_fraction: 0,
        cap_m: 2,
        cap_f: 1,
    };
    assert_eq!(Record::activation(activation), Err(Error::Parameters));
    assert_eq!(
        Record::activation(Activation {
            kind: 0,
            cap_m: 1,
            cap_f: 0,
            ..activation
        }),
        Err(Error::Parameters)
    );
    assert_eq!(
        Record::maximum(Maximum {
            context: 1,
            score_bound: 1 << 31,
            domain_bits: 31,
            fraction: 0
        }),
        Err(Error::Parameters)
    );
    assert_eq!(
        Record::request(Request {
            vocabulary: 1,
            context: 1,
            mode: 2
        }),
        Err(Error::Parameters)
    );
    let shape = AttentionShape {
        heads: 2,
        groups: 1,
        width: 2,
        context: 1,
    };
    let score = Score {
        shape,
        query_fraction: 30,
        key_fraction: 30,
        exp_fraction: 0,
        query_policy: (0, 0),
        key_policy: (0, 0),
        multiplier: 1,
        exponent: 0,
    };
    for bad in [
        Score {
            shape: AttentionShape { groups: 0, ..shape },
            ..score
        },
        Score {
            shape: AttentionShape {
                heads: 3,
                groups: 2,
                ..shape
            },
            ..score
        },
        Score {
            shape: AttentionShape {
                width: 8193,
                ..shape
            },
            ..score
        },
        Score {
            shape: AttentionShape {
                context: (1 << 20) + 1,
                ..shape
            },
            ..score
        },
        Score {
            query_fraction: 31,
            ..score
        },
        Score {
            key_fraction: 31,
            ..score
        },
        Score {
            exp_fraction: 31,
            ..score
        },
        Score {
            query_policy: (0, 1),
            ..score
        },
        Score {
            key_policy: (1, 0),
            ..score
        },
        Score {
            query_policy: (2, 1),
            ..score
        },
        Score {
            multiplier: 0,
            ..score
        },
        Score {
            exponent: -63,
            ..score
        },
        Score {
            exponent: 31,
            ..score
        },
    ] {
        assert_eq!(Record::score(bad), Err(Error::Parameters));
    }
    let weighted = Weighted {
        shape,
        value_fraction: 0,
        exp_fraction: 0,
        policy: (0, 0),
        mode: 0,
        drop: 0,
    };
    for bad in [
        Weighted {
            value_fraction: 31,
            ..weighted
        },
        Weighted {
            exp_fraction: 15,
            ..weighted
        },
        Weighted {
            mode: 2,
            ..weighted
        },
        Weighted {
            drop: 1,
            ..weighted
        },
        Weighted {
            mode: 1,
            drop: 63,
            ..weighted
        },
        Weighted {
            policy: (1, 0),
            ..weighted
        },
    ] {
        assert_eq!(Record::weighted(bad), Err(Error::Parameters));
        assert_eq!(
            Record::normalize(Normalize {
                source: bad,
                output_fraction: 0
            }),
            Err(Error::Parameters)
        );
    }
    assert_eq!(
        Record::normalize(Normalize {
            source: weighted,
            output_fraction: 31
        }),
        Err(Error::Parameters)
    );
    let rotary = Rotary {
        heads: 1,
        width: 4,
        rotary_width: 2,
        context: 1,
        layout: 0,
        fraction: 0,
    };
    for bad in [
        Rotary {
            rotary_width: 0,
            ..rotary
        },
        Rotary {
            rotary_width: 3,
            ..rotary
        },
        Rotary {
            rotary_width: 6,
            ..rotary
        },
        Rotary {
            layout: 2,
            ..rotary
        },
        Rotary {
            fraction: 31,
            ..rotary
        },
    ] {
        assert_eq!(Record::rotary(bad), Err(Error::Parameters));
    }
    assert_eq!(
        Record::logits(Logits {
            vocabulary: 1,
            fraction: 31
        }),
        Err(Error::Parameters)
    );
    assert_eq!(
        Record::temperature(Temperature {
            logits_fraction: 31,
            temperature: (1, 1),
            exp
        }),
        Err(Error::Parameters)
    );
    assert_eq!(
        Record::sampling(Sampling {
            vocabulary: 1,
            exp_fraction: 15,
            top_p: (1, 1)
        }),
        Err(Error::Parameters)
    );
}
