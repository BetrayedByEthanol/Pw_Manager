//! Dependency-isolated compilation of the same V02 code as the root crate.
#![forbid(unsafe_code)]
#[path = "../../../src/v02/mod.rs"]
pub mod v02;
