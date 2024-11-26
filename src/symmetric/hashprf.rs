use super::Pseudorandom;
use sha2::{Digest, Sha256};

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00,
];

// Implement a SHA256-based PRF
pub struct Sha256PRF;

impl Pseudorandom for Sha256PRF {
    type Key = [u8; KEY_LENGTH];
    type Output = [u8; 32];

    fn gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        let mut key = [0u8; KEY_LENGTH];
        rng.fill(&mut key);
        key
    }

    fn apply(key: &Self::Key, input: u64) -> Self::Output {
        let mut hasher = Sha256::new();

        // Hash the domain separator
        hasher.update(PRF_DOMAIN_SEP);

        // Hash the key
        hasher.update(key);

        // Hash the input
        hasher.update(input.to_be_bytes());

        // Finalize and convert the first 8 bytes to u64
        let result = hasher.finalize();
        result.into()
    }
}
