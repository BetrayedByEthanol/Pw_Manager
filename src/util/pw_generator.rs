use argon2::password_hash::rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use std::error::Error;

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharSet(u8);
impl CharSet {
    pub const UPPERCASE: Self = Self(0b0001);
    pub const LOWERCASE: Self = Self(0b0010);
    pub const DIGITS: Self = Self(0b0100);
    pub const SPECIAL: Self = Self(0b1000);
    pub const ALL: Self = Self(0b1111);
    pub fn contains(self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub fn is_empty(self) -> bool { self.0 == 0 }
}
impl std::ops::BitOr for CharSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}
impl std::ops::BitOrAssign for CharSet {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}
/// Generate a user-selected length without modulo bias.
pub fn generate_password(flags: CharSet, length: usize) -> Result<SecretString, Box<dyn Error>> {
    if flags.is_empty() { return Err("at least one character class is required".into()); }
    if !(8..=128).contains(&length) { return Err("length must be between 8 and 128".into()); }
    let mut pool = Vec::new();
    if flags.contains(CharSet::UPPERCASE) { pool.extend_from_slice(UPPERCASE); }
    if flags.contains(CharSet::LOWERCASE) { pool.extend_from_slice(LOWERCASE); }
    if flags.contains(CharSet::DIGITS) { pool.extend_from_slice(DIGITS); }
    if flags.contains(CharSet::SPECIAL) { pool.extend_from_slice(SPECIAL); }
    let range = u32::MAX as u64 + 1;
    let count = pool.len() as u64;
    let limit = range - range % count;
    let mut value = String::with_capacity(length);
    for _ in 0..length {
        let idx = loop {
            let n = OsRng.next_u32() as u64;
            if n < limit { break (n % count) as usize; }
        };
        value.push(pool[idx] as char);
    }
    Ok(SecretString::from(value))
}
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    #[test]
    fn generator_bounds() {
        assert!(generate_password(CharSet::ALL, 7).is_err());
        assert!(generate_password(CharSet::ALL, 129).is_err());
        assert!(generate_password(CharSet(0), 20).is_err());
    }
    #[test]
    fn generator_output() {
        let a = generate_password(CharSet::DIGITS, 32).unwrap();
        assert!(a.expose_secret().bytes().all(|v| v.is_ascii_digit()));
        assert_eq!(a.expose_secret().len(), 32);
    }
}
