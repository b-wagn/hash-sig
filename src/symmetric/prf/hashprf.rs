use super::Pseudorandom;
use sha2::{Digest, Sha256};

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00,
];

// Implement a SHA256-based PRF
// Output Length must be at most 32 bytes
pub struct Sha256PRF<const OUTPUT_LENGTH: usize>;

impl<const OUTPUT_LENGTH: usize> Pseudorandom for Sha256PRF<OUTPUT_LENGTH> {
    type Key = [u8; KEY_LENGTH];
    type Output = [u8; OUTPUT_LENGTH];

    fn gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        let mut key = [0u8; KEY_LENGTH];
        rng.fill(&mut key);
        key
    }

    fn apply(key: &Self::Key, epoch: u64, index: u64) -> Self::Output {
        assert!(
            OUTPUT_LENGTH < 256 / 8,
            "SHA256-PRF: Output length must be less than 256 bit"
        );

        let mut hasher = Sha256::new();

        // Hash the domain separator
        hasher.update(PRF_DOMAIN_SEP);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(epoch.to_be_bytes());

        // Hash the index
        hasher.update(index.to_be_bytes());

        // Finalize and convert the first 8 bytes to u64
        let result = hasher.finalize();
        result[0..OUTPUT_LENGTH].try_into().unwrap()
    }
}
