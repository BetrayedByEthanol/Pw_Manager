use argon2::password_hash::rand_core::RngCore;
use std::error::Error;
use argon2::password_hash::rand_core::OsRng;
use rand::Rng;
use secrecy::SecretString;

// Character pools
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

const DEFAULT_LENGTH: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharSet(u8);

impl CharSet {
    pub const UPPERCASE: Self = Self(0b0001);
    pub const LOWERCASE: Self = Self(0b0010);
    pub const DIGITS:    Self = Self(0b0100);
    pub const SPECIAL:   Self = Self(0b1000);

    /// All four character classes — a sensible secure default.
    pub const ALL: Self = Self(0b1111);

    #[inline]
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for CharSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CharSet {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

pub fn generate_password(flags: CharSet) -> Result<SecretString, Box<dyn Error>> {
    if flags.is_empty() {
        return Err("CharSet must include at least one character class".into());
    }

    let mut pool: Vec<u8> = Vec::with_capacity(94);
    if flags.contains(CharSet::UPPERCASE) { pool.extend_from_slice(UPPERCASE); }
    if flags.contains(CharSet::LOWERCASE) { pool.extend_from_slice(LOWERCASE); }
    if flags.contains(CharSet::DIGITS)    { pool.extend_from_slice(DIGITS);    }
    if flags.contains(CharSet::SPECIAL)   { pool.extend_from_slice(SPECIAL);   }

    let password: String = (0..DEFAULT_LENGTH)
        .map(|_| {
            let length: u32 = pool.len().try_into().unwrap();
            let idx: usize = (OsRng.next_u32() % length).try_into().unwrap();
            pool[idx] as char
        })
        .collect();

    Ok(SecretString::new(password.into()))
}