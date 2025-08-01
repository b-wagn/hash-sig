use crate::{MESSAGE_LENGTH, symmetric::message_hash::MessageHash};

use super::{EncodingError, IncomparableEncoding};
use thiserror::Error;

/// Specific errors that can occur during target sum encoding.
#[derive(Debug, Error)]
pub enum TargetSumError {
    /// Returned when the generated chunks do not sum to the required target.
    #[error("Target sum mismatch: expected {expected}, but got {actual}.")]
    Mismatch { expected: usize, actual: usize },
}

/// Incomparable Encoding Scheme based on Target Sums,
/// implemented from a given message hash.
///
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
    const MAX_TRIES: usize = 100_000;

    const BASE: usize = MH::BASE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        MH::rand(rng)
    }

    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u8>, EncodingError> {
        // apply the message hash first to get chunks
        let chunks = MH::apply(parameter, epoch, randomness, message);
        let sum: u32 = chunks.iter().map(|&x| x as u32).sum();
        // only output something if the chunks sum to the target sum
        if sum as usize == TARGET_SUM {
            Ok(chunks)
        } else {
            Err(TargetSumError::Mismatch {
                expected: TARGET_SUM,
                actual: sum as usize,
            }
            .into())
        }
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // base and dimension must not be too large
        assert!(
            Self::BASE <= 1 << 8,
            "Target Sum Encoding: Base must be at most 2^8"
        );
        assert!(
            Self::DIMENSION <= 1 << 8,
            "Target Sum Encoding: Dimension must be at most 2^8"
        );

        // also check internal consistency of message hash
        MH::internal_consistency_check();
    }
}
