use crate::MESSAGE_LENGTH;
use rand::Rng;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Error enum for the signing process.
#[derive(Debug, Error)]
pub enum SigningError {
    /// Occurs when the probabilistic message encoding fails to produce a valid codeword
    /// after the maximum number of attempts.
    #[error("Failed to encode message after {attempts} attempts.")]
    EncodingAttemptsExceeded { attempts: usize },
}

/// Trait to model a synchronized signature scheme.
/// We sign messages with respect to epochs.
/// We assume each we sign for each epoch only once.
pub trait SignatureScheme {
    type PublicKey: Serialize + DeserializeOwned;
    type SecretKey: Serialize + DeserializeOwned;
    type Signature: Serialize + DeserializeOwned;

    /// number of epochs that are supported
    /// with one key. Must be a power of two.
    const LIFETIME: u64;

    /// Generates a new key pair, returning the public and private keys.
    ///
    /// The key can sign with respect to all epochs in the range
    /// `activation_epoch..activation_epoch+num_active_epochs`.
    ///
    /// The caller must ensure that this is a valid range, i.e., that
    /// `activation_epoch+num_active_epochs <= LIFETIME`.
    fn key_gen<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey);

    /// Signs a message and returns the signature.
    /// The signature is with respect to a given epoch.
    fn sign<R: Rng>(
        rng: &mut R,
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError>;

    /// Verifies a signature with respect to public key, epoch, and message digest.
    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool;

    /// Function to check internal consistency of any given parameters
    /// For testing only, and expected to panic if something is wrong.
    #[cfg(test)]
    fn internal_consistency_check();
}

pub mod generalized_xmss;

#[cfg(test)]
mod test_templates {
    use serde::{Serialize, de::DeserializeOwned};

    use super::*;

    /// Generic test for any implementation of the `SignatureScheme` trait.
    /// Tests correctness, i.e., that honest key gen, honest signing, implies
    /// that the verifier accepts the signature. A random message is used.
    pub fn test_signature_scheme_correctness<T: SignatureScheme>(
        epoch: u32,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) {
        let mut rng = rand::rng();

        // Generate a key pair
        let (pk, sk) = T::key_gen(&mut rng, activation_epoch, num_active_epochs);

        // Sample random test message
        let message = rng.random();

        // Sign the message
        let signature = T::sign(&mut rng, &sk, epoch, &message);

        // Ensure signing was successful
        assert!(
            signature.is_ok(),
            "Signing failed: {:?}. Epoch was {:?}",
            signature.err(),
            epoch
        );

        // Verify the signature
        let signature = signature.unwrap();
        let is_valid = T::verify(&pk, epoch, &message, &signature);
        assert!(
            is_valid,
            "Signature verification failed. . Epoch was {:?}",
            epoch
        );

        test_bincode_round_trip_consistency(&pk);
        test_bincode_round_trip_consistency(&sk);
        test_bincode_round_trip_consistency(&signature);
    }

    fn test_bincode_round_trip_consistency<T: Serialize + DeserializeOwned>(ori: &T) {
        use bincode::serde::{decode_from_slice, encode_to_vec};
        let config = bincode::config::standard();
        let bytes_ori = encode_to_vec(ori, config).expect("Bincode encode should not fail");
        let (dec, _): (T, _) =
            decode_from_slice(&bytes_ori, config).expect("Bincode decode should not fail");
        let bytes_dec = encode_to_vec(dec, config).expect("Bincode encode should not fail");
        assert_eq!(bytes_ori, bytes_dec, "Serde consistency check failed");
    }
}
