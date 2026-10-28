//! RFC-0006 A5 reference: recompute original MLEs, without prefix grids or folded tables.
use stele_hash::ChallengeField;
use stele_sumcheck::{Error, Instance, Summand};

pub struct Reference<'a, K> {
    pub instance: &'a Instance<K>,
    pub tables: &'a [Vec<K>],
    pub point: Vec<K>,
}
impl<K: ChallengeField> Reference<'_, K> {
    fn values(&self, point: &[K]) -> Vec<K> {
        let weights = stele_poly::eq_table(point).expect("small reference shape");
        self.tables
            .iter()
            .map(|table| {
                assert_eq!(table.len(), weights.len());
                table
                    .iter()
                    .zip(&weights)
                    .fold(K::from_i64(0), |sum, (v, w)| sum + *v * *w)
            })
            .collect()
    }
}
impl<K: ChallengeField + Eq> Summand<K> for Reference<'_, K> {
    fn shape(&self) -> (u32, usize) {
        (
            self.instance.num_vars - self.point.len() as u32,
            self.tables.len(),
        )
    }
    fn round(&self, i: &Instance<K>) -> Result<Vec<K>, Error> {
        assert!(i == self.instance);
        let degree = i
            .terms
            .iter()
            .map(|term| term.factors.len())
            .max()
            .unwrap_or(0);
        let rest = i.num_vars as usize - self.point.len() - 1;
        Ok((0..=degree)
            .map(|node| {
                (0..1usize << rest).fold(K::from_i64(0), |sum, vertex| {
                    let mut point = self.point.clone();
                    point.push(K::from_i64(node as i64));
                    point.extend(
                        (0..rest)
                            .rev()
                            .map(|bit| K::from_i64(((vertex >> bit) & 1) as i64)),
                    );
                    let values = self.values(&point);
                    sum + i.terms.iter().fold(K::from_i64(0), |total, term| {
                        total
                            + term
                                .factors
                                .iter()
                                .fold(term.coefficient, |p, f| p * values[*f as usize])
                    })
                })
            })
            .collect())
    }
    fn fold(&mut self, value: K) -> Result<(), Error> {
        self.point.push(value);
        Ok(())
    }
    fn final_values(&self) -> Result<Vec<K>, Error> {
        assert_eq!(self.point.len(), self.instance.num_vars as usize);
        Ok(self.values(&self.point))
    }
}
