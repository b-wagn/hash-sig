use crate::{
    symmetric::message_hash::bytes_to_chunks, MESSAGE_LENGTH, TWEAK_SEPARATOR_FOR_MESSAGE_HASH,
};

use super::MessageHash;

use sha3::{Digest, Sha3_256};

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
{
    type Parameter = [u8; PARAMETER_LEN];

    type Randomness = [u8; RAND_LEN];

    const NUM_CHUNKS: usize = NUM_CHUNKS;

    const CHUNK_SIZE: usize = CHUNK_SIZE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        let mut rand = [0u8; RAND_LEN];
        rng.fill_bytes(&mut rand);
        rand
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
        hasher.update(&[TWEAK_SEPARATOR_FOR_MESSAGE_HASH]);
        hasher.update(epoch.to_le_bytes());

        // now add the actual message to be hashed
        hasher.update(message);

        // finalize the hash, and take as many bytes as we need
        let hash = hasher.finalize();
        // turn the bytes in the hash into chunks
        let chunks: Vec<u8> =
            bytes_to_chunks(&hash[0..NUM_CHUNKS * CHUNK_SIZE / 8], Self::CHUNK_SIZE);
        chunks
    }

    #[cfg(test)]
    fn internal_consistency_check() {
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
            NUM_CHUNKS * CHUNK_SIZE < 256,
            "SHA Message Hash: Hash Length (= NUM_CHUNKS * CHUNK_SIZE) must be less than 256 bit"
        );
    }
}

// Example instantiations
pub type ShaMessageHash128x3 = ShaMessageHash<16, 16, 16, 8>;
pub type ShaMessageHash192x3 = ShaMessageHash<24, 24, 48, 4>;

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::MESSAGE_LENGTH;

    use super::*;

    #[test]
    fn test_apply_128x3() {
        let mut rng = thread_rng();

        let mut parameter = [0u8; 16];
        rng.fill(&mut parameter);

        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        let epoch = 13;
        let randomness = ShaMessageHash128x3::rand(&mut rng);

        ShaMessageHash128x3::internal_consistency_check();
        ShaMessageHash128x3::apply(&parameter, epoch, &randomness, &message);
    }

    #[test]
    fn test_apply_192x3() {
        let mut rng = thread_rng();

        let mut parameter = [0u8; 24];
        rng.fill(&mut parameter);

        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        let epoch = 13;
        let randomness = ShaMessageHash192x3::rand(&mut rng);

        ShaMessageHash192x3::internal_consistency_check();
        ShaMessageHash192x3::apply(&parameter, epoch, &randomness, &message);
    }
}
