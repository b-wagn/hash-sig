use super::Pseudorandom;
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;
use serde::{Serialize, de::DeserializeOwned};

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00,
];
const PRF_DOMAIN_SEP_DOMAIN_ELEMENT: [u8; 1] = [0x00];
const PRF_DOMAIN_SEP_RANDOMNESS: [u8; 1] = [0x01];

// Implement a SHA3-based PRF
// Domain length and randomness length are given in bytes.
// Domain length must be at most 32 bytes
// Randomness length must be at most 32 bytes
pub struct ShaPRF<const DOMAIN_LENGTH: usize, const RAND_LENGTH: usize>;

impl<const DOMAIN_LENGTH: usize, const RAND_LENGTH: usize> Pseudorandom
    for ShaPRF<DOMAIN_LENGTH, RAND_LENGTH>
where
    [u8; DOMAIN_LENGTH]: Serialize + DeserializeOwned,
{
    type Key = [u8; KEY_LENGTH];
    type Domain = [u8; DOMAIN_LENGTH];
    type Randomness = [u8; RAND_LENGTH];

    fn key_gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        rng.random()
    }

    fn get_domain_element(key: &Self::Key, epoch: u32, index: u64) -> Self::Domain {
        // Setup hasher
        let hasher = Keccak256Hash;

        // Collect all input bytes
        // - domain separator
        // - another domain separator for distinguishing the two types of elements
        // that we generate: domain elements and randomness
        // - key
        // - epoch
        // - index
        let combined: Vec<u8> = PRF_DOMAIN_SEP
            .iter()
            .chain(PRF_DOMAIN_SEP_DOMAIN_ELEMENT.iter())
            .chain(key.iter())
            .chain(epoch.to_be_bytes().iter())
            .chain(index.to_be_bytes().iter())
            .copied()
            .collect();

        // Hash and convert to output
        hasher.hash_iter(combined)[..DOMAIN_LENGTH]
            .try_into()
            .unwrap()
    }

    fn get_randomness(
        key: &Self::Key,
        epoch: u32,
        message: &[u8; crate::MESSAGE_LENGTH],
        counter: u64,
    ) -> Self::Randomness {
        // Setup hasher
        let hasher = Keccak256Hash;

        // Collect all input bytes
        // - domain separator
        // - another domain separator for distinguishing the two types of elements
        // that we generate: domain elements and randomness
        // - key
        // - epoch
        // - message
        // - counter
        let combined: Vec<u8> = PRF_DOMAIN_SEP
            .iter()
            .chain(PRF_DOMAIN_SEP_RANDOMNESS.iter())
            .chain(key.iter())
            .chain(epoch.to_be_bytes().iter())
            .chain(message.iter())
            .chain(counter.to_be_bytes().iter())
            .copied()
            .collect();

        // Hash and convert to output
        hasher.hash_iter(combined)[..RAND_LENGTH]
            .try_into()
            .unwrap()
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            DOMAIN_LENGTH <= 256 / 8,
            "SHA PRF: Output length must be less than 256 bit (failed for DOMAIN_LENGTH)"
        );
        assert!(
            RAND_LENGTH <= 256 / 8,
            "SHA PRF: Output length must be less than 256 bit (failed for RAND_LENGTH)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha_prf_key_not_all_same() {
        const K: usize = 10;
        const OUTPUT_LEN: usize = 16;
        const RAND_LEN: usize = 13;
        type PRF = ShaPRF<OUTPUT_LEN, RAND_LEN>;

        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let key = PRF::key_gen(&mut rng);

            let first = key[0];
            if key.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        assert!(
            all_same_count < K,
            "PRF key had identical bytes in all {} trials",
            K
        );
    }
}
