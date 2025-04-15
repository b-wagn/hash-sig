use rand::Rng;

use crate::MESSAGE_LENGTH;

/// Trait to model a hash function used for message hashing.
///
/// This is a variant of a tweakable hash function that we use for
/// message hashing. Specifically, it contains one more input,
/// and is always executed with respect to epochs, i.e., tweaks
/// are implicitly derived from the epoch.
pub trait MessageHash {
    type Parameter: Clone + Sized;
    type Randomness;

    const NUM_CHUNKS: usize;

    /// Must be 1, 2, 4, or 8
    const CHUNK_SIZE: usize;

    /// Generates a random domain element.
    fn rand<R: Rng>(rng: &mut R) -> Self::Randomness;

    /// Applies the message hash to a parameter, an epoch,
    /// a randomness, and a message. It outputs a list of chunks.
    /// The list contains NUM_CHUNKS many elements, each between
    /// 0 and 2^CHUNK_SIZE - 1 (inclusive).
    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8>;

    /// Function to check internal consistency of any given parameters
    /// For testing only, and expected to panic if something is wrong.
    #[cfg(test)]
    fn internal_consistency_check();
}

pub mod poseidon;
pub mod sha;

/// Isolates a chunk of bits from a byte based on the specified chunk index and chunk size.
///
/// This function takes a byte and extracts a specified chunk of bits, where the chunk's
/// position is determined by the `chunk_index` and the size of the chunk is defined
/// by `chunk_size`. It is assumed that `window_size` divides 8 and is between 1 and 8.
const fn isolate_chunk_from_byte(byte: u8, chunk_index: usize, chunk_size: usize) -> u8 {
    // Ensure chunk size divides 8 and is between 1 and 8
    assert!(chunk_size > 0 && chunk_size <= 8 && 8 % chunk_size == 0);

    // Ensure the chunk index is within bounds
    assert!(chunk_index < 8 / chunk_size);

    // exit early if chunk is the entire byte
    if chunk_size == 8 {
        return byte;
    }

    // Calculate the start bit position of the i-th chunk
    let start_bit_pos = chunk_index * chunk_size;

    // Create a bitmask for chunk_size many bits
    let mask = (1u8 << chunk_size) - 1;

    // Shift the byte right and apply the mask
    (byte >> start_bit_pos) & mask
}

/// Function to turn a list of bytes into a list of chunks.
/// That is, each byte is split up into chunks containing `chunk_size`
/// many bits. For example, if `bytes` contains 6 elements, and
/// `chunk_size` is 2, then the result contains 6 * (8/2) = 24 elements.
///  It is assumed that `window_size` divides 8 and is between 1 and 8.
pub fn bytes_to_chunks(bytes: &[u8], chunk_size: usize) -> Vec<u8> {
    // Ensure chunk size divides 8 and is between 1 and 8
    assert!(chunk_size > 0 && chunk_size <= 8 && 8 % chunk_size == 0);

    // iterate over all chunks and isolate them
    let chunks_per_byte = 8 / chunk_size;
    let num_chunks = bytes.len() * chunks_per_byte;
    let mut chunks = Vec::with_capacity(num_chunks);
    for chunk_index in 0..num_chunks {
        // first find the right byte
        let byte_index = chunk_index / chunks_per_byte;
        let byte = bytes[byte_index];
        // now isolate the chunk and store it
        let chunk_index_in_byte = chunk_index % chunks_per_byte;
        let chunk = isolate_chunk_from_byte(byte, chunk_index_in_byte, chunk_size);
        chunks.push(chunk);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::{bytes_to_chunks, isolate_chunk_from_byte};

    #[test]
    fn test_isolate_chunk_from_byte() {
        // In this test, we check that `isolate_chunk_from_byte` works as expected

        let byte: u8 = 0b01101100;

        assert_eq!(isolate_chunk_from_byte(byte, 0, 2), 0b00);
        assert_eq!(isolate_chunk_from_byte(byte, 1, 2), 0b11);
        assert_eq!(isolate_chunk_from_byte(byte, 2, 2), 0b10);
        assert_eq!(isolate_chunk_from_byte(byte, 3, 2), 0b01);

        assert_eq!(isolate_chunk_from_byte(byte, 0, 4), 0b1100);
        assert_eq!(isolate_chunk_from_byte(byte, 1, 4), 0b0110);
    }

    #[test]
    fn test_bytes_to_chunks() {
        // In this test, we check that `bytes_to_chunks` works as expected

        let byte_a: u8 = 0b01101100;
        let byte_b: u8 = 0b10100110;

        let bytes = [byte_a, byte_b];
        let expected_chunks = [0b00, 0b11, 0b10, 0b01, 0b10, 0b01, 0b10, 0b10];

        let chunks = bytes_to_chunks(&bytes, 2);

        assert_eq!(chunks.len(), 8);

        for i in 0..chunks.len() {
            assert_eq!(chunks[i], expected_chunks[i]);
        }

        // now test chunk size 8
        let chunks = bytes_to_chunks(&bytes, 8);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], byte_a);
        assert_eq!(chunks[1], byte_b);
    }
}
