//! stele-gpu — governed by RFC-0014. No behaviour exists here that is not specified there (INV-1).
// unsafe allowed in this crate: every block carries a // SAFETY: comment (agents/guardrails/code.md)
#![cfg_attr(not(test), deny(clippy::float_arithmetic))]

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {}
}
