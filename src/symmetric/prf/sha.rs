use super::Pseudorandom;
use sha3::{Digest, Sha3_256};

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00,
];

// Implement a SHA3-based PRF
// Output Length must be at most 32 bytes
pub struct ShaPRF<const OUTPUT_LENGTH: usize>;

impl<const OUTPUT_LENGTH: usize> Pseudorandom for ShaPRF<OUTPUT_LENGTH> {
    type Key = [u8; KEY_LENGTH];
    type Output = [u8; OUTPUT_LENGTH];

    fn gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        std::array::from_fn(|_| rng.gen())
    }

    fn apply(key: &Self::Key, epoch: u32, index: u64) -> Self::Output {
        let mut hasher = Sha3_256::new();

        // Hash the domain separator
        hasher.update(PRF_DOMAIN_SEP);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(epoch.to_be_bytes());

        // Hash the index
        hasher.update(index.to_be_bytes());

        // Finalize and convert to output
        let result = hasher.finalize();
        result[..OUTPUT_LENGTH].try_into().unwrap()
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            OUTPUT_LENGTH < 256 / 8,
            "SHA PRF: Output length must be less than 256 bit"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use std::collections::HashSet;

    #[test]
    fn test_sha_prf_key_is_random() {
        const K: usize = 10;
        type PRF = ShaPRF<16>;

        let mut rng = thread_rng();
        let mut seen = HashSet::new();
        let mut collisions = 0;

        for _ in 0..K {
            let key = PRF::gen(&mut rng);
            if !seen.insert(key) {
                collisions += 1;
            }
        }

        assert!(collisions < K, "Too many repeated keys in {} trials", K);
    }
}
