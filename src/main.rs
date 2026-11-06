mod cli;
mod crypto;
mod fsutil;
mod io;
mod security;
mod util;
mod vault;
mod x11_keysyms;
mod fido2;
mod obfuscate;

// V01 safety gate: do not auto-open legacy vaults or display test credentials.
fn main() {
    eprintln!("Vaulty is an unsafe development prototype. The interactive legacy vault is disabled pending the v0.4.5 runtime and recovery implementation. Do not store real credentials.");
}
