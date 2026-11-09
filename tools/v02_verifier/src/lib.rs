//! Dependency-isolated compilation of the same V02 code as the root crate.
#![forbid(unsafe_code)]
#[path = "../../../src/v02/mod.rs"]
pub mod v02;
#[path = "../../../src/v03.rs"]
pub mod v03;
#[path = "../../../src/v03a.rs"]
pub mod v03a;
#[path = "../../../src/v03c.rs"]
pub mod v03c;
