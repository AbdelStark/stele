//! RFC-0023 §2.1: full independent layout fixtures and private reader failures.
use super::*;
use alloc::{format, string::String, vec};

#[test]
fn matches_reference_complete_schema() {
    let lines: Vec<_> = include_str!("../tests/fixtures/requant-schema.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 18 * 3);
    for case in lines.chunks_exact(3) {
        let p: Vec<u32> = case[0]
            .split_whitespace()
            .map(|v| v.parse().expect("valid schema fixture"))
            .collect();
        let format = if p[2] == 8 {
            Format::Int8
        } else {
            Format::Int16
        };
        let schema = Schema::new(p[0], p[1], format).expect("valid schema fixture");
        let hex: String = schema
            .bounds()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, case[1], "parameters {}", case[0]);
        let mut out = vec![schema.allocated_rows() as u64, schema.rows() as u64];
        out.extend(schema.u_carries().map(|v| v as u64));
        fn block(out: &mut Vec<u64>, b: &Block) {
            out.push(b.cap());
            for range in [b.value(), b.slack(), b.carry()] {
                out.push(range.len() as u64);
                out.extend(range.map(|v| v as u64));
            }
        }
        for b in schema.values() {
            block(&mut out, b);
        }
        for role in schema.roles() {
            out.push(u64::from(role.count()));
            out.extend(role.bounds());
            out.extend(role.widths().map(u64::from));
            out.push(u64::from(role.result_cap().is_some()));
            if let Some(b) = role.result_cap() {
                block(&mut out, b);
            }
            out.push(role.carries().len() as u64);
            for b in role.carries() {
                block(&mut out, b);
            }
        }
        let expected: Vec<u64> = case[2]
            .split_whitespace()
            .map(|v| v.parse().expect("valid schema fixture"))
            .collect();
        assert_eq!(out, expected, "parameters {}", case[0]);
        // Every allocated row has one owner; a result cap shares only its value.
        let mut owners = vec![0; schema.rows()];
        owners[0] = 1;
        let mut own = |r: Range<usize>| {
            for i in r {
                owners[i] += 1;
            }
        };
        for b in schema
            .values()
            .iter()
            .chain(schema.roles().iter().flat_map(Role::carries))
        {
            own(b.value());
            own(b.slack());
            own(b.carry());
        }
        for b in schema.roles().iter().filter_map(Role::result_cap) {
            own(b.slack());
            own(b.carry());
        }
        own(schema.u_carries());
        assert!(owners[..schema.allocated_rows()].iter().all(|v| *v == 1));
        assert!(owners[schema.allocated_rows()..].iter().all(|v| *v == 0));
    }
}

#[test]
fn accepts_shared_tail_and_zero_caps() {
    let s = Schema::new(1, 0, Format::Int8).expect("valid schema fixture");
    assert_eq!((s.allocated_rows(), s.rows()), (109, 128));
    let cap = s.roles()[5].result_cap().expect("valid schema fixture");
    assert_eq!((cap.cap(), cap.value()), (256, s.values()[5].value()));
    assert_eq!((cap.value().len(), s.roles()[5].widths()[2]), (4, 2));
    let s = Schema::new(1, 62, Format::Int16).expect("valid schema fixture");
    assert_eq!((s.allocated_rows(), s.rows()), (170, 256));
    assert_eq!((s.values()[2].cap(), s.values()[2].value().len()), (0, 1));
    assert_eq!(
        (s.roles()[4].widths()[2], s.roles()[4].carries().len()),
        (8, 7)
    );
    assert!(s.roles()[4]
        .carries()
        .iter()
        .all(|b| b.cap() == 0 && b.value().len() == 1));
}

#[test]
fn rejects_parameters_reader_and_capacity() {
    assert_eq!(buffer::<u64>(usize::MAX), Err(Error::Capacity));
    assert_eq!(
        Schema::new(0, 0, Format::Int8).expect_err("invalid expected parameters"),
        Error::Parameters(stele_cqis::Error::Scale)
    );
    assert_eq!(
        Schema::new(65536, 0, Format::Int8).expect_err("mantissa above u16"),
        Error::Parameters(stele_cqis::Error::Scale)
    );
    assert_eq!(
        Schema::new(1, 63, Format::Int8).expect_err("invalid expected parameters"),
        Error::Parameters(stele_cqis::Error::Shift)
    );
    let mut at = 2046;
    assert_eq!(allocate(&mut at, 2), Err(Error::Capacity));
    assert_eq!(at, 2046);
    let mut at = usize::MAX;
    assert_eq!(allocate(&mut at, 1), Err(Error::Capacity));
    let mut raw = [0; 20];
    raw[8] = 1;
    assert_eq!(Reader(&raw).wide(), Err(Error::Encoding));
    assert_eq!(Reader(&[0; 19]).wide(), Err(Error::Encoding));
    let record = stele_cqis::bounds::Record::requant(
        Requant::new(1, 0).expect("valid schema fixture"),
        Format::Int8,
    )
    .expect("valid schema fixture");
    // Header ends at 181; first role widths are at 246, carry endpoints at 259/279.
    for offset in [0, 25, 27, 36, 177, 179, 180, 181, 182, 244, 246, 259, 279] {
        let mut raw = record.as_bytes().to_vec();
        raw[offset] ^= 128;
        assert!(
            matches!(read_layout(&raw), Err(Error::Encoding)),
            "offset {offset}"
        );
    }
    assert!(read_layout(&record.as_bytes()[..record.as_bytes().len() - 1]).is_err());
    let mut raw = record.as_bytes().to_vec();
    raw.push(0);
    assert!(read_layout(&raw).is_err());
}
