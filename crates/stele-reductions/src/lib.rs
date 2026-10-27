//! stele-reductions — governed by RFC-0007 RFC-0008 RFC-0009 RFC-0017. No behaviour exists here that is not specified there (INV-1).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {}
}
