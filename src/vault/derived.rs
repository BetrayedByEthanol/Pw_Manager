use secrecy::{SecretBox, };
use zeroize::Zeroize;

pub struct VaultyDerived<T> where T: Zeroize + ?Sized {
    pub vault_secret: SecretBox<T>,
}
