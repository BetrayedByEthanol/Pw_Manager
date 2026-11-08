//! Vaulty candidate cryptographic infrastructure, isolated from the disabled
//! legacy application executable. No user-facing unlock/write path is enabled.
//! OPEN-01/OPEN-15 independent reviews and canonical format acceptance pending.
#![forbid(unsafe_code)]
pub mod v02;
// Review-gated model; no production unlock/authenticator adapters activated.
pub mod v03;
