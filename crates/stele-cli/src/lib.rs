//! stele-cli — governed by RFC-0020. No behaviour exists here that is not specified there (INV-1).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {}
}
