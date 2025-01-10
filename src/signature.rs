use rand::Rng;

use crate::MESSAGE_LENGTH;

/// Error enum for signatures
#[derive(Debug)]
pub enum SigningError {
    InvalidMessageLength,
    UnluckyFailure,
}

/// Trait to model a synchronized signature scheme.
/// We sign messages with respect to epochs.
/// We assume each we sign for each epoch only once.
pub trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;

    /// number of epochs that are supported
    /// with one key. Must be a power of two.
    const LIFETIME: u64;

    /// Generates a new key pair, returning the public and private keys.
    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

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
    use rand::thread_rng;

    use super::*;

    /// Generic test for any implementation of the `SignatureScheme` trait.
    /// Tests internal consistency of parameters
    pub fn _test_signature_scheme_internal_consistency<T: SignatureScheme>() {
        T::internal_consistency_check();
    }

    /// Generic test for any implementation of the `SignatureScheme` trait.
    /// Tests correctness, i.e., that honest key gen, honest signing, implies
    /// that the verifier accepts the signature. A random message is used.
    pub fn _test_signature_scheme_correctness<T: SignatureScheme>(epoch: u32) {
        let mut rng = thread_rng();

        // Generate a key pair
        let (pk, sk) = T::gen(&mut rng);

        // Sample random test message
        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        // Sign the message
        let signature = T::sign(&mut rng, &sk, epoch, &message);

        // Ensure signing was successful
        assert!(
            signature.is_ok(),
            "Signing failed: {:?}. Epoch was {:?}",
            signature.err(),
            epoch
        );

        // Verify the signature.
        let signature = signature.unwrap();
        let is_valid = T::verify(&pk, epoch, &message, &signature);
        assert!(
            is_valid,
            "Signature verification failed. . Epoch was {:?}",
            epoch
        );
    }
}
