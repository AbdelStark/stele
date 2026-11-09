//! RFC-0010 A3 item 4: expose native v2 geometry and Policy 1 for independent checking.
use stele_field::QM31;
use stele_pcs::Source;

fn main() -> Result<(), stele_pcs::Error> {
    for j in 3..=14u8 {
        let mut code = b"stele/expander-seed/v2".to_vec();
        code.push(j);
        code.extend_from_slice(&[0; 32]);
        let p = Source::<QM31>::from_code_id(0, 0, &code, [0; 32])?.parameters();
        println!(
            "{j} {} {} {} {} {} {}",
            p.length,
            p.distance,
            p.radius,
            p.certificate_queries,
            p.opening_queries,
            u8::from(p.setup_term)
        );
    }
    Ok(())
}
