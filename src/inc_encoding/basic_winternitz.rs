use crate::{
    symmetric::message_hash::{bytes_to_chunks, MessageHash},
    MESSAGE_LENGTH,
};

use super::IncomparableEncoding;

/// Incomparable Encoding Scheme based on the basic
/// Winternitz scheme, implemented from a given message hash.
///
/// Note: this supports chunk sizes 1,2,4, and 8, and the
/// base of the message hash must be 2 ** CHUNK_SIZE
///
/// Unfortunately, Rust cannot deal with logarithms and ceils in constants.
/// Therefore, the user needs to supply NUM_CHUNKS_CHECKSUM. This value can
/// be computed before compilation with the following steps:
/// ```ignore
///     base = 2 ** MH::CHUNK_SIZE
///     num_chunks_message = MH::DIMENSION
///     max_checksum = num_chunks_message * (base - 1)
///     num_chunks_checksum = 1 + math.floor(math.log(max_checksum, base))
/// ```
pub struct WinternitzEncoding<
    MH: MessageHash,
    const CHUNK_SIZE: usize,
    const NUM_CHUNKS_CHECKSUM: usize,
> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH: MessageHash, const CHUNK_SIZE: usize, const NUM_CHUNKS_CHECKSUM: usize>
    IncomparableEncoding for WinternitzEncoding<MH, CHUNK_SIZE, NUM_CHUNKS_CHECKSUM>
{
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    const DIMENSION: usize = MH::DIMENSION + NUM_CHUNKS_CHECKSUM;

    const MAX_TRIES: usize = 1;

    const BASE: usize = MH::BASE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        MH::rand(rng)
    }

    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u8>, super::EncodingError> {
        // apply the message hash to get chunks
        let mut chunks_message = MH::apply(parameter, epoch, randomness, message);

        // now, we compute the checksum
        let checksum: u64 = chunks_message
            .iter()
            .map(|&x| Self::BASE as u64 - 1 - x as u64)
            .sum();

        // we split the checksum into chunks, in little-endian
        let checksum_bytes = checksum.to_le_bytes();
        let chunks_checksum = bytes_to_chunks(&checksum_bytes, CHUNK_SIZE);

        // Assemble the resulting vector
        // we take all message chunks, followed by the checksum chunks.
        // Note that we only want to take the first NUM_CHUNKS_CHECKSUM chunks.
        // The remaining ones must be zero anyways.
        chunks_message.extend_from_slice(&chunks_checksum[..NUM_CHUNKS_CHECKSUM]);

        Ok(chunks_message)
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // chunk size must be 1, 2, 4, or 8
        assert!(
            [1, 2, 4, 8].contains(&CHUNK_SIZE),
            "Winternitz Encoding: Chunk Size must be 1, 2, 4, or 8"
        );

        // base and dimension must not be too large
        assert!(
            CHUNK_SIZE <= 8,
            "Winternitz Encoding: Base must be at most 2^8"
        );
        assert!(
            Self::DIMENSION <= 1 << 8,
            "Winternitz Encoding: Dimension must be at most 2^8"
        );

        // chunk size and base of MH must be consistent
        assert!(
            MH::BASE == Self::BASE && MH::BASE == 1 << CHUNK_SIZE,
            "Winternitz Encoding: Base and chunk size not consistent with message hash"
        );

        // also check internal consistency of message hash
        MH::internal_consistency_check();
    }
}
