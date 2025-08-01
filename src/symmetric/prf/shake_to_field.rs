use std::marker::PhantomData;

use super::Pseudorandom;
use p3_field::PrimeField64;
use serde::{Serialize, de::DeserializeOwned};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use num_bigint::BigUint;

// Number of pseudorandom bytes to generate one pseudorandom field element
const PRF_BYTES_PER_FE: usize = 8;

const KEY_LENGTH: usize = 32; // 32 bytes
const PRF_DOMAIN_SEP: [u8; 16] = [
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
];

/// A pseudorandom function mapping to field elements.
/// It is implemented using Shake128.
/// It outputs OUTPUT_LENGTH_FE many field elements.
pub struct ShakePRFtoF<F, const OUTPUT_LENGTH_FE: usize>(PhantomData<F>);

impl<F, const OUTPUT_LENGTH_FE: usize> Pseudorandom for ShakePRFtoF<F, OUTPUT_LENGTH_FE>
where
    F: PrimeField64,
    [F; OUTPUT_LENGTH_FE]: Serialize + DeserializeOwned,
{
    type Key = [u8; KEY_LENGTH];
    type Output = [F; OUTPUT_LENGTH_FE];

    fn key_gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        rng.random()
    }

    fn apply(key: &Self::Key, epoch: u32, index: u64) -> Self::Output {
        // Create a new SHAKE128 instance
        let mut hasher = Shake128::default();

        // Hash the domain separator
        hasher.update(&PRF_DOMAIN_SEP);

        // Hash the key
        hasher.update(key);

        // Hash the epoch
        hasher.update(&epoch.to_be_bytes());

        // Hash the index
        hasher.update(&index.to_be_bytes());

        // Finalize the hash process and create an XofReader
        let mut xof_reader = hasher.finalize_xof();

        // Buffer to store the output
        let mut prf_output = vec![0u8; PRF_BYTES_PER_FE * OUTPUT_LENGTH_FE];

        // Read the extended output into the buffer
        xof_reader.read(&mut prf_output);

        // Mapping bytes to field elements
        std::array::from_fn(|i| {
            let chunk_start = i * PRF_BYTES_PER_FE;
            let chunk_end = chunk_start + PRF_BYTES_PER_FE;
            let integer_value =
                BigUint::from_bytes_be(&prf_output[chunk_start..chunk_end]) % F::ORDER_U64;
            F::from_u64(integer_value.try_into().unwrap())
        })
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // No check is needed
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_shake_to_field_prf_key_not_all_same() {
        const K: usize = 10;
        const OUTPUT_LEN: usize = 4;
        type PRF = ShakePRFtoF<BabyBear, OUTPUT_LEN>;

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
