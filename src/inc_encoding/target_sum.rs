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
///     const MAX_CHUNK_VALUE: usize = MH::BASE - 1
///     const EXPECTED_SUM: usize = MH::DIMENSION * MAX_CHUNK_VALUE / 2
/// ```
pub struct TargetSumEncoding<MH: MessageHash, const TARGET_SUM: usize> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH: MessageHash, const TARGET_SUM: usize> IncomparableEncoding
    for TargetSumEncoding<MH, TARGET_SUM>
{
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    const DIMENSION: usize = MH::DIMENSION;

    /// we did one experiment with random message hashes.
    /// In production, this should be estimated via more
    /// extensive experiments with concrete hash functions.
    const MAX_TRIES: usize = 100000;

    const BASE: usize = MH::BASE;

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
        let sum: u32 = chunks.iter().map(|&x| x as u32).sum();
        // only output something if the chunks sum to the target sum
        if sum as usize == TARGET_SUM {
            Ok(chunks)
        } else {
            Err(())
        }
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // base must not be too large
        assert!(
            Self::BASE <= 1 << 16,
            "Target Sum Encoding: Base must be at most 2^16"
        );

        // also check internal consistency of message hash
        MH::internal_consistency_check();
    }
}
