//! RFC-0024 §6: fixed complete parameter and signed-boundary fixtures.
use stele_reductions::requant::Format;

pub(super) struct Case {
    pub(super) bits: [u8; 4],
    pub(super) mantissa: u32,
    pub(super) shift: u32,
    pub(super) format: Format,
    pub(super) rates: [u8; 3],
    pub(super) messages: [Vec<u8>; 2],
    pub(super) base_point: bool,
}
pub(super) fn case(name: &str) -> Result<Case, &'static str> {
    let (bits, mantissa, shift, format) = match name {
        "scalar" => ([0; 4], 1, 1, Format::Int8),
        "stacked" => ([1; 4], 1, 1, Format::Int8),
        "ties" => ([0, 0, 0, 2], 1, 1, Format::Int8),
        "zero_x" => ([1, 1, 1, 0], 32767, 62, Format::Int16),
        "zero_w" => ([0, 1, 1, 1], 1, 0, Format::Int8),
        "wide" => ([1, 1, 0, 1], 32767, 15, Format::Int16),
        "shift62" => ([0, 1, 1, 1], 32767, 62, Format::Int16),
        "int16_min" | "int16_max" => ([0, 0, 2, 0], 1, 0, Format::Int16),
        "int8_min" | "int8_max" => ([0; 4], 1, 0, Format::Int8),
        "cap" => ([0; 4], 1, 8, Format::Int8),
        _ => return Err("unknown fixture"),
    };
    let [h, a, b, c] = bits;
    let mut x: Vec<_> = (0..1usize << (h + a + b))
        .map(|i| 125 + (i % 7) as u8)
        .collect();
    let mut w: Vec<_> = (0..1usize << (h + c + b))
        .map(|i| 126 + (i % 5) as u8)
        .collect();
    match name {
        "ties" => {
            x = vec![127];
            w = vec![127, 129, 125, 131];
        }
        "zero_x" => x.fill(128),
        "zero_w" => w.fill(128),
        "wide" => {
            x = vec![0, 255, 129, 127];
            w = vec![255, 0, 127, 129];
        }
        "int16_min" => {
            x.fill(0);
            w.fill(192);
        }
        "int16_max" => {
            x = vec![255, 255, 255, 129];
            w = vec![255, 255, 132, 129];
        }
        "int8_min" => {
            x = vec![0];
            w = vec![129];
        }
        "int8_max" => {
            x = vec![255];
            w = vec![129];
        }
        "cap" => {
            x = vec![0];
            w = vec![0];
        }
        _ => (),
    }
    let base_point = matches!(name, "scalar" | "stacked");
    Ok(Case {
        bits,
        mantissa,
        shift,
        format,
        rates: if base_point { [1, 2, 1] } else { [2, 1, 2] },
        messages: [x, w],
        base_point,
    })
}
