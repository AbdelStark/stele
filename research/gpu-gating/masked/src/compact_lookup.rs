//! RFC-0008 A7 items 2–3. Compact base-field inputs for an actual lookup tree.
use crate::{lookup::words, Field, K, M31};
use std::collections::BTreeMap;
use stele_reductions::zk::claims::bench::{GkrMember, GkrSelector};

/// Borrowed projections from the CPU's original lookup plan and base columns.
pub struct Input<'a> {
    pub variables: usize,
    pub top_variables: usize,
    pub tuples: &'a [Vec<GkrMember<'a, M31>>],
    pub selectors: &'a [GkrSelector<'a>],
    pub multiplicity: &'a [M31],
    pub table: &'a [Vec<i64>],
    pub valid: usize,
    pub beta: K,
    pub alpha: K,
}

pub(crate) struct Packed {
    pub n: usize,
    pub leaves: usize,
    pub top: usize,
    pub tree_words: usize,
    pub width: u32,
    pub members: u32,
    pub valid: u32,
    pub mults: u32,
    pub fields: Vec<u32>,
    pub descriptors: Vec<u32>,
    pub shifts: Vec<u32>,
}

type Checked<T> = Result<T, &'static str>;

fn word(n: usize) -> Checked<u32> {
    u32::try_from(n).map_err(|_| "compact lookup word offset")
}

enum Column<'a> {
    Base(&'a [M31]),
    Selector(&'a [i64]),
}

struct Columns<'a> {
    // Comparing addresses only deduplicates an identical borrowed source. No
    // pointer is dereferenced here or encoded in the device input.
    offsets: BTreeMap<(bool, usize, usize), u32>,
    sources: Vec<Column<'a>>,
    end: u32,
}

impl<'a> Columns<'a> {
    fn add(&mut self, col: Column<'a>) -> Checked<u32> {
        let key = match col {
            Column::Base(v) => (false, v.as_ptr() as usize, v.len()),
            Column::Selector(v) => (true, v.as_ptr() as usize, v.len()),
        };
        if let Some(&start) = self.offsets.get(&key) {
            return Ok(start);
        }
        if let Column::Selector(values) = &col {
            if values.iter().any(|v| !matches!(v, 0 | 1)) {
                return Err("compact lookup selector");
            }
        }
        let start = self.end;
        self.end = start
            .checked_add(word(key.2)?)
            .ok_or("compact lookup field count")?;
        self.offsets.insert(key, start);
        self.sources.push(col);
        Ok(start)
    }
}

fn coordinates(
    shifts: &mut Vec<u32>,
    coords: &[usize],
    entries: usize,
    vars: usize,
) -> Checked<[u32; 2]> {
    if coords.len() > 30 || entries != (1usize << coords.len()) || coords.iter().any(|&q| q >= vars)
    {
        return Err("compact lookup gather");
    }
    let start = word(shifts.len())?;
    let len = word(coords.len())?;
    start
        .checked_add(len)
        .ok_or("compact lookup coordinate count")?;
    shifts.extend(coords.iter().map(|&c| (vars - 1 - c) as u32));
    Ok([start, len])
}

impl Packed {
    pub(crate) fn new(input: &Input<'_>) -> Checked<Self> {
        let vars = input.variables;
        if vars > 30 || input.top_variables > vars + 1 {
            return Err("compact lookup domain");
        }
        let n = 1usize << vars;
        let width = input.tuples.len();
        let members = input.selectors.len();
        if width == 0
            || members == 0
            || input.tuples.iter().any(|reads| reads.len() != members)
            || !input.table.len().is_power_of_two()
            || input.table.len() > n
            || input.multiplicity.len() != input.table.len()
            || input.valid > input.table.len()
            || input.table.iter().any(|row| row.len() != width)
        {
            return Err("compact lookup shape");
        }
        let header = width
            .checked_add(1)
            .and_then(|size| size.checked_mul(4))
            .and_then(|size| size.checked_add(input.valid.checked_mul(width)?))
            .ok_or("compact lookup header")?;
        let mut columns = Columns {
            offsets: BTreeMap::new(),
            sources: Vec::new(),
            end: word(header)?,
        };
        columns.add(Column::Base(input.multiplicity))?;
        let stride = width
            .checked_mul(4)
            .and_then(|v| v.checked_add(5))
            .ok_or("compact lookup stride")?;
        let desc_words = word(
            stride
                .checked_mul(members)
                .ok_or("compact lookup descriptors")?,
        )?;
        let mut descriptors = Vec::with_capacity(desc_words as usize);
        let mut shifts = vec![0]; // A valid device buffer even for all-constant gathers.
        let mut end = 0;
        for (i, selector) in input.selectors.iter().enumerate() {
            let range = &selector.range;
            if range.start < end || range.end <= range.start || range.end > n {
                return Err("compact lookup member range");
            }
            end = range.end;
            descriptors.extend([word(range.start)?, word(range.end)?]);
            if let Some((values, axes)) = selector.values {
                let offset = columns.add(Column::Selector(values))?;
                let [s, c] = coordinates(&mut shifts, axes, values.len(), vars)?;
                descriptors.extend([offset, s, c]);
            } else {
                descriptors.extend([u32::MAX, 0, 0]);
            }
            for reads in input.tuples {
                let r = &reads[i];
                if r.range != *range || !r.mask.is_empty() {
                    return Err("compact lookup tuple range or mask");
                }
                let offset = columns.add(Column::Base(r.values))?;
                let [s, c] = coordinates(&mut shifts, r.coordinates, r.values.len(), vars)?;
                descriptors.extend([offset, s, c, M31::from_i64(r.shift).as_u32()]);
            }
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(columns.end as usize)
            .map_err(|_| "compact lookup allocation")?;
        fields.extend(words(input.alpha));
        let mut power = K::ONE;
        for _ in 0..width {
            fields.extend(words(power));
            power = power * input.beta;
        }
        for row in &input.table[..input.valid] {
            fields.extend(row.iter().map(|&v| M31::from_i64(v).as_u32()));
        }
        for col in columns.sources {
            match col {
                Column::Base(v) => fields.extend(v.iter().map(|x| x.as_u32())),
                Column::Selector(v) => fields.extend(v.iter().map(|&x| x as u32)),
            }
        }
        assert_eq!(fields.len(), columns.end as usize);
        let leaves = n * 2;
        Ok(Self {
            n,
            leaves,
            top: 1usize << input.top_variables,
            tree_words: (2 * leaves - 1) * 8,
            width: word(width)?,
            members: word(members)?,
            valid: word(input.valid)?,
            mults: word(input.multiplicity.len())?,
            fields,
            descriptors,
            shifts,
        })
    }

    pub(crate) fn upload_bytes(&self) -> usize {
        4 * (self.fields.len() + self.descriptors.len() + self.shifts.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_borrowed_base_inputs_and_rejects_bad_projection() {
        let col = [M31::ZERO, M31::ONE];
        let coords = [0];
        let read = || GkrMember {
            range: 0..4,
            values: col.as_slice(),
            coordinates: coords.as_slice(),
            shift: -1,
            mask: Vec::new(),
        };
        let tuples = [vec![read()], vec![read()]];
        let mut selectors = [GkrSelector {
            range: 0..4,
            values: Some((&[1, 0], &coords)),
        }];
        let rows = [vec![3, -1], vec![0, 0]];
        {
            let input = Input {
                variables: 2,
                top_variables: 1,
                tuples: &tuples,
                selectors: &selectors,
                multiplicity: &col,
                table: &rows,
                valid: 1,
                beta: K::ONE,
                alpha: K::ONE,
            };
            let p = Packed::new(&input).unwrap();
            // 3 challenges, 2 multiplicities, 2 table entries and 2 selector values.
            // Both tuple reads share the original multiplicity buffer.
            assert_eq!(p.fields.len(), 18);
            assert_eq!(p.descriptors.len(), 5 + 2 * 4);
            assert_eq!(p.leaves, 8);
            assert_eq!(p.tree_words, 8 * 15);
            assert_eq!(
                (p.n, p.top, p.width, p.members, p.valid, p.mults),
                (4, 2, 2, 1, 1, 2)
            );
            assert_eq!(p.shifts, [0, 1, 1, 1]);
            assert_eq!(p.upload_bytes(), 4 * (18 + 13 + 4));
        }
        selectors[0].range = 1..4;
        let input = Input {
            variables: 2,
            top_variables: 1,
            tuples: &tuples,
            selectors: &selectors,
            multiplicity: &col,
            table: &rows,
            valid: 1,
            beta: K::ONE,
            alpha: K::ONE,
        };
        assert!(Packed::new(&input).is_err());
    }
}
