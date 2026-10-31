//! RFC-0010 A9 §1: expose all native finite counts for independent exact checking.
use stele_field::QM31;
use stele_pcs::Source;

fn main() -> Result<(), stele_pcs::Error> {
    for blowup in 1..=2 {
        for m in 0..=30 - blowup {
            let p = Source::<QM31>::new(0, 0, m, blowup, [0; 32])?.parameters();
            println!(
                "{m} {blowup} {} {} {} {} {}",
                p.length, p.distance, p.radius, p.certificate_queries, p.opening_queries
            );
        }
    }
    Ok(())
}
