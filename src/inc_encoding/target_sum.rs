use crate::{symmetric::message_hash::MessageHash, MESSAGE_LENGTH};

use super::IncomparableEncoding;

/// Incomparable Encoding Scheme based on Target Sums,
/// implemented from a given message hash.
/// CHUNK_SIZE has to be 1,2,4, or 8.
/// TARGET_SUM determines how we set the target sum,
/// and has direct impact on the signer's running time,
/// or equivalently the success probability of this encoding scheme.
/// It is recommended to set it close to the expected sum, which is:
///
/// ```ignore
///     const MAX_CHUNK_VALUE: usize = (1 << MH::CHUNK_SIZE) - 1
///     const EXPECTED_SUM: usize = MH::NUM_CHUNKS * Self::MAX_CHUNK_VALUE / 2
/// ```
pub struct TargetSumEncoding<MH: MessageHash, const TARGET_SUM: usize> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH: MessageHash, const TARGET_SUM: usize> TargetSumEncoding<MH, TARGET_SUM> {
    const NUM_CHUNKS: usize = MH::NUM_CHUNKS;
    const TARGET_SUM: usize = TARGET_SUM;
}

impl<MH: MessageHash, const TARGET_SUM: usize> IncomparableEncoding
    for TargetSumEncoding<MH, TARGET_SUM>
{
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    const NUM_CHUNKS: usize = Self::NUM_CHUNKS;

    /// we did one experiment with random message hashes.
    /// In production, this should be estimated via more
    /// extensive experiments with concrete hash functions.
    const MAX_TRIES: usize = 100000;

    const CHUNK_SIZE: usize = MH::CHUNK_SIZE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        MH::rand(rng)
    }

    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u16>, super::EncodingError> {
        // apply the message hash first to get chunks
        let chunks = MH::apply(parameter, epoch, randomness, message);
        let chunks_u16: Vec<u16> = chunks.iter().map(|&x| x as u16).collect();
        let chunks_u32: Vec<u32> = chunks.iter().map(|&x| x as u32).collect();

        let sum: u32 = chunks_u32.iter().sum();
        // only output the chunks sum to the target sum
        return if sum as usize != Self::TARGET_SUM {
            Err(())
        } else {
            Ok(chunks_u16)
        };
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // chunk size must be 1, 2, 4, or 8
        assert!(
            MH::CHUNK_SIZE > 0 && MH::CHUNK_SIZE <= 8 && 8 % MH::CHUNK_SIZE == 0,
            "Winternitz Encoding: Chunk Size must be 1, 2, 4, or 8"
        );
        // also check internal consistency of message hash
        MH::internal_consistency_check();
    }
}
