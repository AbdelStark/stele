//! stele-verifier — governed by RFC-0016. No behaviour exists here that is not specified there (INV-1).
#![forbid(unsafe_code)]
#![no_std]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {}
}
