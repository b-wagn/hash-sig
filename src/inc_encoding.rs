use rand::Rng;

use crate::MESSAGE_LENGTH;

/// Error during encoding
pub type EncodingError = ();

/// Trait to model incomparable encoding schemes.
/// These schemes allow to encode a message into a codeword.
///
/// A codeword is vector of a fixed dimension containing
/// integer elements between 0 and BASE - 1.
/// We require BASE to be at most 1 << 16 to ensure that
/// the entries fit into u16.
///
/// The main feature of these encodings is that no two distinct
/// codewords are "comparable", i.e., for no two codewords
/// x = (x_1,..,x_k) and x' = (x'_1,..,x'_k) we have
/// x_i > x_i' for all i = 1,...,k.
pub trait IncomparableEncoding {
    type Parameter;
    type Randomness;

    /// number of entries in a codeword
    const DIMENSION: usize;

    /// how often one should try at most
    /// to resample randomness before giving up.
    const MAX_TRIES: usize;

    /// base of the code, i.e., codeword entries
    /// are between 0 and BASE - 1
    const BASE: usize;

    /// Samples a randomness to be used for the encoding.
    fn rand<R: Rng>(rng: &mut R) -> Self::Randomness;

    /// Apply the incomparable encoding to a message.
    /// It could happen that this fails. Otherwise,
    /// implementations must guarantee that the
    /// result is indeed a valid codeword.
    fn encode(
        parameter: &Self::Parameter,
        message: &[u8; MESSAGE_LENGTH],
        randomness: &Self::Randomness,
        epoch: u32,
    ) -> Result<Vec<u16>, EncodingError>;

    /// Function to check internal consistency of any given parameters
    /// For testing only, and expected to panic if something is wrong.
    #[cfg(test)]
    fn internal_consistency_check();
}

pub mod basic_winternitz;
pub mod target_sum;
