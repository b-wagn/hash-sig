use super::Pseudorandom;
use sha3::{Digest, Sha3_256};

use num_bigint::BigUint;
use zkhash::ark_ff::MontConfig;
use zkhash::fields::babybear::{FpBabyBear, FqConfig};

type F = FpBabyBear;
const PRF_BYTE_LEN: usize = 8; //How many PRF bytes we need to generate a uniformly random field element

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
        let mut key = [0u8; KEY_LENGTH];
        rng.fill(&mut key);
        key
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
        result[0..OUTPUT_LENGTH].try_into().unwrap()
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            OUTPUT_LENGTH < 256 / 8,
            "SHA PRF: Output length must be less than 256 bit"
        );
    }
}

pub struct ShaPRFtoF<const OUTPUT_FE_LENGTH: usize>;

impl<const OUTPUT_FE_LENGTH: usize> Pseudorandom for ShaPRFtoF<OUTPUT_FE_LENGTH> {
    type Key = [u8; KEY_LENGTH];
    type Output = [F; OUTPUT_FE_LENGTH];

    fn gen<R: rand::Rng>(rng: &mut R) -> Self::Key {
        let mut key = [0u8; KEY_LENGTH];
        rng.fill(&mut key);
        key
    }

    fn apply(key: &Self::Key, epoch: u32, index: u64) -> Self::Output {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake128,
        };

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
        let mut prf_output = vec![0u8; PRF_BYTE_LEN * OUTPUT_FE_LENGTH]; // Example: 64 bytes of output

        // Read the extended output into the buffer
        xof_reader.read(&mut prf_output);

        // Final result
        let mut result = Vec::new();

        // Mapping bytes to FE
        for chunk in prf_output.chunks(PRF_BYTE_LEN) {
            let integer_value = BigUint::from_bytes_be(chunk) % BigUint::from(FqConfig::MODULUS);
            result.push(F::from(integer_value));
        }
        let slice = &result[0..OUTPUT_FE_LENGTH];
        slice.try_into().expect("Length mismatch")
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // No check is needed
    }
}
