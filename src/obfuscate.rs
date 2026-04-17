use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::{ SeedableRng};
use rand_core::Rng;

pub fn obfuscate(s: &String) -> Vec<u8> {
    let mut rng = ChaCha12Rng::seed_from_u64(69);
    s.as_bytes()
        .iter()
        .map(|b| b ^ rng.next_u32() as u8)
        .collect()
}

pub fn unobfuscate(s: &Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = ChaCha12Rng::seed_from_u64(69);
    let decoded_bytes = s.iter()
        .map(|&b| b ^ rng.next_u32() as u8)
        .collect();

    Ok(String::from_utf8(decoded_bytes)?)
}