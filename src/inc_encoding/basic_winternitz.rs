use crate::{
    symmetric::message_hash::{bytes_to_chunks, MessageHash},
    MESSAGE_LENGTH,
};

use super::IncomparableEncoding;

/// Incomparable Encoding Scheme based on the basic
/// Winternitz scheme, implemented from a given message hash.
///
///
/// Unfortunately, Rust cannot deal with logarithms and ceils in constants.
/// Therefore, the user needs to supply NUM_CHUNKS_CHECKSUM. This value can
/// be computed before compilation with the following steps:
/// ```ignore
///     base = 2 ** MH::CHUNK_SIZE
///     num_chunks_message = MH::NUM_CHUNKS
///     max_checksum = num_chunks_message * (base - 1)
///     num_chunks_checksum = 1 + math.floor(math.log(max_checksum, base))
/// ```

pub struct WinternitzEncoding<MH: MessageHash, const NUM_CHUNKS_CHECKSUM: usize> {
    _marker_mh: std::marker::PhantomData<MH>,
}

impl<MH: MessageHash, const NUM_CHUNKS_CHECKSUM: usize>
    WinternitzEncoding<MH, NUM_CHUNKS_CHECKSUM>
{
    const NUM_CHUNKS_MESSAGE: usize = MH::NUM_CHUNKS;
    const BASE: usize = 1 << MH::CHUNK_SIZE;
    const NUM_CHUNKS: usize = Self::NUM_CHUNKS_MESSAGE + NUM_CHUNKS_CHECKSUM;
}

impl<MH: MessageHash, const NUM_CHUNKS_CHECKSUM: usize> IncomparableEncoding
    for WinternitzEncoding<MH, NUM_CHUNKS_CHECKSUM>
{
    type Parameter = MH::Parameter;

    type Randomness = MH::Randomness;

    const NUM_CHUNKS: usize = Self::NUM_CHUNKS;

    const MAX_TRIES: usize = 1;

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
        // apply the message hash to get chunks
        let chunks_message = MH::apply(parameter, epoch, randomness, message);

        // now, we compute the checksum
        let checksum: u64 = chunks_message
            .iter()
            .map(|&x| Self::BASE as u64 - 1 - x as u64)
            .sum();

        // we split the checksum into chunks, in little-endian
        let checksum_bytes = checksum.to_le_bytes();
        let chunks_checksum: Vec<u8> = bytes_to_chunks(&checksum_bytes, Self::CHUNK_SIZE);

        // Assemble the resulting vector
        // we take all message chunks, followed by the checksum chunks.
        // Note that we only want to take the first NUM_CHUNKS_CHECKSUM chunks.
        // The remaining ones must be zero anyways.
        let mut chunks = Vec::with_capacity(chunks_message.len() + NUM_CHUNKS_CHECKSUM);
        chunks.extend_from_slice(&chunks_message);
        chunks.extend_from_slice(&chunks_checksum[..NUM_CHUNKS_CHECKSUM]);
        let chunks_u16: Vec<u16> = chunks.iter().map(|&x| x as u16).collect();
        Ok(chunks_u16)
    }
}
