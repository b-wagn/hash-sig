use serde::{Serialize, de::DeserializeOwned};
use sha3::{Digest, Sha3_256};

use super::MessageHash;
use crate::{
    MESSAGE_LENGTH, TWEAK_SEPARATOR_FOR_MESSAGE_HASH, symmetric::message_hash::bytes_to_chunks,
};

/// A message hash implemented using SHA3
/// All lengths must be given in Bytes.
/// All lengths must be less than 255 bits.
/// Randomness length must be non-zero.
/// CHUNK_SIZE has to be 1,2,4, or 8.
pub struct ShaMessageHash<
    const PARAMETER_LEN: usize,
    const RAND_LEN: usize,
    const NUM_CHUNKS: usize,
    const CHUNK_SIZE: usize,
>;

impl<
    const PARAMETER_LEN: usize,
    const RAND_LEN: usize,
    const NUM_CHUNKS: usize,
    const CHUNK_SIZE: usize,
> MessageHash for ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS, CHUNK_SIZE>
where
    [u8; PARAMETER_LEN]: Serialize + DeserializeOwned,
    [u8; RAND_LEN]: Serialize + DeserializeOwned,
{
    type Parameter = [u8; PARAMETER_LEN];

    type Randomness = [u8; RAND_LEN];

    const DIMENSION: usize = NUM_CHUNKS;

    const BASE: usize = 1 << CHUNK_SIZE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        rng.random()
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8> {
        let mut hasher = Sha3_256::new();

        // first add randomness
        hasher.update(randomness);

        // now add the parameter
        hasher.update(parameter);

        // now add tweak (= domain separator + epoch)
        // domain separator: this is a message hash tweak.
        hasher.update([TWEAK_SEPARATOR_FOR_MESSAGE_HASH]);
        hasher.update(epoch.to_le_bytes());

        // now add the actual message to be hashed
        hasher.update(message);

        // finalize the hash, and take as many bytes as we need
        let hash = hasher.finalize();
        // turn the bytes in the hash into chunks
        bytes_to_chunks(&hash[0..NUM_CHUNKS * CHUNK_SIZE / 8], CHUNK_SIZE)
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            [1, 2, 4, 8].contains(&CHUNK_SIZE),
            "SHA Message Hash: Chunk Size must be 1, 2, 4, or 8"
        );
        assert!(
            PARAMETER_LEN < 256 / 8,
            "SHA Message Hash: Parameter Length must be less than 256 bit"
        );
        assert!(
            RAND_LEN < 256 / 8,
            "SHA Message Hash: Randomness Length must be less than 256 bit"
        );
        assert!(
            RAND_LEN > 0,
            "SHA Message Hash: Randomness Length must be non-zero"
        );
        assert!(
            NUM_CHUNKS * CHUNK_SIZE <= 256,
            "SHA Message Hash: Hash Length (= NUM_CHUNKS * CHUNK_SIZE) must be at most 256 bits"
        );
        assert!(
            Self::BASE <= 1 << 8,
            "SHA Message Hash: Base must be at most 2^8"
        );
        assert!(
            Self::DIMENSION <= 1 << 8,
            "SHA Message Hash: Dimension must be at most 2^8"
        );
    }
}

// Example instantiations
pub type ShaMessageHash128x3 = ShaMessageHash<16, 16, 16, 8>;
pub type ShaMessageHash192x3 = ShaMessageHash<24, 24, 48, 4>;

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn test_apply_128x3() {
        let mut rng = rand::rng();

        let parameter = rng.random();

        let message = rng.random();

        let epoch = 13;
        let randomness = ShaMessageHash128x3::rand(&mut rng);

        ShaMessageHash128x3::internal_consistency_check();
        ShaMessageHash128x3::apply(&parameter, epoch, &randomness, &message);
    }

    #[test]
    fn test_apply_192x3() {
        let mut rng = rand::rng();

        let parameter = rng.random();

        let message = rng.random();

        let epoch = 13;
        let randomness = ShaMessageHash192x3::rand(&mut rng);

        ShaMessageHash192x3::internal_consistency_check();
        ShaMessageHash192x3::apply(&parameter, epoch, &randomness, &message);
    }

    #[test]
    fn test_randomness_is_not_all_same() {
        const TRIALS: usize = 10;
        let mut rng = rand::rng();

        let mut identical_count = 0;

        for _ in 0..TRIALS {
            let r = ShaMessageHash192x3::rand(&mut rng);
            let first = r[0];
            if r.iter().all(|&b| b == first) {
                identical_count += 1;
            }
        }

        assert!(
            identical_count < TRIALS,
            "All generated randomness arrays had identical bytes"
        );
    }
}
