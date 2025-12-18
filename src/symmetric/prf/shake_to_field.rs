use crate::F;

use super::Pseudorandom;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;
use serde::{Serialize, de::DeserializeOwned};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use num_bigint::BigUint;

// Number of pseudorandom bytes to generate one pseudorandom field element
const PRF_BYTES_PER_FE: usize = 16;

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
];
const PRF_DOMAIN_SEP_DOMAIN_ELEMENT: [u8; 1] = [0x00];
const PRF_DOMAIN_SEP_RANDOMNESS: [u8; 1] = [0x01];

/// A pseudorandom function mapping to field elements.
/// It is implemented using Shake128.
/// It outputs DOMAIN_LENGTH_FE or RAND_LENGTH_FE many field elements.
pub struct ShakePRFtoF<const DOMAIN_LENGTH_FE: usize, const RAND_LENGTH_FE: usize>;

impl<const DOMAIN_LENGTH_FE: usize, const RAND_LENGTH_FE: usize> Pseudorandom
    for ShakePRFtoF<DOMAIN_LENGTH_FE, RAND_LENGTH_FE>
where
    [F; DOMAIN_LENGTH_FE]: Serialize + DeserializeOwned,
{
    type Key = [u8; KEY_LENGTH];
    type Domain = [F; DOMAIN_LENGTH_FE];
    type Randomness = [F; RAND_LENGTH_FE];

    fn key_gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        rng.random()
    }

    fn get_domain_element(key: &Self::Key, epoch: u32, index: u64) -> Self::Domain {
        // Create a new SHAKE128 instance
        let mut hasher = Shake128::default();

        // Hash the domain separator
        hasher.update(&PRF_DOMAIN_SEP);

        // Another domain separator for distinguishing the two types of elements
        // that we generate: domain elements and randomness
        hasher.update(&PRF_DOMAIN_SEP_DOMAIN_ELEMENT);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(&epoch.to_be_bytes());

        // Hash the index
        hasher.update(&index.to_be_bytes());

        // Finalize the hash process and create an XofReader
        let mut xof_reader = hasher.finalize_xof();

        // Mapping bytes to field elements
        std::array::from_fn(|_| {
            // Buffer to store the output
            let mut buf = [0u8; PRF_BYTES_PER_FE];

            // Read the extended output into the buffer
            xof_reader.read(&mut buf);

            // Mapping bytes to a field element
            F::from_u128(u128::from_be_bytes(buf))
        })
    }

    fn get_randomness(
        key: &Self::Key,
        epoch: u32,
        message: &[u8; crate::MESSAGE_LENGTH],
        counter: u64,
    ) -> Self::Randomness {
        // Create a new SHAKE128 instance
        let mut hasher = Shake128::default();

        // Hash the domain separator
        hasher.update(&PRF_DOMAIN_SEP);

        // Another domain separator for distinguishing the two types of elements
        // that we generate: domain elements and randomness
        hasher.update(&PRF_DOMAIN_SEP_RANDOMNESS);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(&epoch.to_be_bytes());

        // Hash the message
        hasher.update(message);

        // Hash the counter
        hasher.update(&counter.to_be_bytes());

        // Finalize the hash process and create an XofReader
        let mut xof_reader = hasher.finalize_xof();

        // Mapping bytes to field elements
        std::array::from_fn(|_| {
            // Buffer to store the output
            let mut buf = [0u8; PRF_BYTES_PER_FE];

            // Read the extended output into the buffer
            xof_reader.read(&mut buf);

            // Mapping bytes to a field element
            F::from_u128(u128::from_be_bytes(buf))
        })
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // No check is needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake_to_field_prf_key_not_all_same() {
        const K: usize = 10;
        const DOMAIN_LEN: usize = 4;
        const RAND_LEN: usize = 4;
        type PRF = ShakePRFtoF<DOMAIN_LEN, RAND_LEN>;

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
            "PRF key had identical elements in all {} trials",
            K
        );
    }
}
