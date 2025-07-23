use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

use crate::MESSAGE_LENGTH;

/// Trait to model a hash function used for message hashing.
///
/// This is a variant of a tweakable hash function that we use for
/// message hashing. Specifically, it contains one more input,
/// and is always executed with respect to epochs, i.e., tweaks
/// are implicitly derived from the epoch.
///
/// Note that BASE must be at most 2^8, as we encode chunks as u8.
pub trait MessageHash {
    type Parameter: Clone + Sized + Serialize + DeserializeOwned;
    type Randomness: Serialize + DeserializeOwned;

    /// number of entries in a hash
    const DIMENSION: usize;

    /// each hash entry is between 0 and BASE - 1
    const BASE: usize;

    /// Generates a random domain element.
    fn rand<R: Rng>(rng: &mut R) -> Self::Randomness;

    /// Applies the message hash to a parameter, an epoch,
    /// a randomness, and a message. It outputs a list of chunks.
    /// The list contains DIMENSION many elements, each between
    /// 0 and BASE - 1 (inclusive).
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
pub mod top_level_poseidon;

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

/// Splits a list of bytes into smaller fixed-size bit chunks.
///
/// Each byte in the input slice is divided into `chunk_size`-bit chunks,
/// starting from the least significant bits. The `chunk_size` must divide 8 exactly
/// (i.e., valid values are 1, 2, 4, or 8), since each byte contains 8 bits.
///
/// # Arguments
/// - `bytes`: A slice of bytes to be chunked.
/// - `chunk_size`: The size (in bits) of each output chunk.
///
/// # Returns
/// A vector of `u8` values where each element is a `chunk_size`-bit chunk
/// from the original input. The number of chunks returned is: `bytes.len() * (8 / chunk_size)`
///
/// # Example
/// ```text
/// // Input: [0b01101100]
/// // Chunk size: 2
/// // Output: [0b00, 0b11, 0b10, 0b01]   (from least to most significant)
/// let chunks = bytes_to_chunks(&[0b01101100], 2);
/// assert_eq!(chunks, vec![0b00, 0b11, 0b10, 0b01]);
/// ```
#[must_use]
pub fn bytes_to_chunks(bytes: &[u8], chunk_size: usize) -> Vec<u8> {
    // Only the chunk sizes 1, 2, 4, or 8 are valid.
    //
    // This avoids invalid bit manipulations and guarantees predictable output length.
    assert!(
        [1, 2, 4, 8].contains(&chunk_size),
        "chunk_size must be 1, 2, 4, or 8"
    );

    // Calculate how many chunks each byte will produce.
    let chunks_per_byte = 8 / chunk_size;

    // Process each byte in the input slice.
    bytes
        .iter()
        .flat_map(|&byte| {
            // For the current byte, split it into `chunks_per_byte` many chunks.
            //
            // Each chunk is extracted by masking the appropriate bits.
            (0..chunks_per_byte).map(move |i| {
                // Extract the i-th chunk from this byte using a helper function.
                isolate_chunk_from_byte(byte, i, chunk_size)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{bytes_to_chunks, isolate_chunk_from_byte};

    #[test]
    fn test_isolate_chunk_from_byte() {
        // In this test, we check that `isolate_chunk_from_byte` works as expected

        let byte: u8 = 0b0110_1100;

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

        let byte_a: u8 = 0b0110_1100;
        let byte_b: u8 = 0b1010_0110;

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
