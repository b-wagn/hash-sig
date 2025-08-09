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

/// Defines the interface for a **synchronized signature scheme**.
///
/// ## Overview
///
/// In a synchronized (or stateful) signature scheme, keys are associated with a fixed
/// lifetime, which is divided into discrete time periods called **epochs**. A key pair
/// is restricted to signing only one message per epoch. Reusing an epoch to sign a
/// different message will compromise the security of the scheme.
///
/// This model is particularly well-suited for consensus protocols like Ethereum's
/// proof-of-stake (lean Ethereum), where validators sign messages
/// (e.g., block proposals or attestations) at regular, predetermined intervals.
///
/// ## Theoretical Foundation
///
/// This trait abstracts the family of post-quantum signature schemes presented in
/// "Hash-Based Multi-Signatures for Post-Quantum Ethereum" [DKKW25] and its
/// extension "LeanSig for Post-Quantum Ethereum". These schemes are variants of
/// the **eXtended Merkle Signature Scheme (XMSS)**, which builds a many-time signature
/// scheme from a one-time signature (OTS) primitive and a Merkle tree.
///
/// The core components are:
/// 1.  **One-Time Signatures**: Each epoch corresponds to a single WOTS-like key pair.
/// 2.  **Merkle Tree**: A Merkle tree is built over all one-time public keys, and its
///     root becomes the main, many-time public key. This provides a commitment to the
///     entire set of one-time keys.
/// 3.  **Incomparable Encoding**: A function that maps a message to a codeword, which
///     in turn determines how the one-time signature is generated. Different encodings
///     provide different trade-offs between signature size and verification cost.
pub trait SignatureScheme {
    /// The public key used for verification. It typically contains the Merkle root
    /// and any public parameters required by the underlying cryptographic primitives
    /// (e.g., for a tweakable hash function).
    ///
    /// The key must be serializable to allow for network transmission and storage.
    type PublicKey: Serialize + DeserializeOwned;

    /// The secret key used for signing. It contains the master secret material
    /// (e.g., a PRF key) from which all one-time secret keys are derived.
    /// It may also pre-compute and store the full Merkle tree for performance.
    ///
    /// The key must be serializable for persistence and secure backup.
    type SecretKey: Serialize + DeserializeOwned;

    /// The signature object produced by the signing algorithm. It contains all the
    /// necessary proof elements for a verifier to validate the signature, such as
    /// the Merkle authentication path and the one-time signature components.
    type Signature: Serialize + DeserializeOwned;

    /// The total number of epochs a key pair is valid for, denoted as $L$ in the
    /// literature. This value **must** be a power of two to accommodate the binary
    /// Merkle tree structure used in the underlying XMSS-like construction.
    const LIFETIME: u64;

    /// Generates a new cryptographic key pair.
    ///
    /// This function creates a fresh public key for verifying signatures and a
    /// corresponding secret key for creating them. The generated key pair can be
    /// specified to be active only for a specific sub-range of its total `LIFETIME`,
    /// which is a practical optimization for key management.
    ///
    /// ### Parameters
    /// * `rng`: A cryptographically secure random number generator.
    /// * `activation_epoch`: The starting epoch for which this key is active.
    /// * `num_active_epochs`: The number of consecutive epochs for which this key is active.
    ///
    /// ### Returns
    /// A tuple containing the new `(PublicKey, SecretKey)`.
    fn key_gen<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey);

    /// Produces a digital signature for a given message at a specific epoch.
    ///
    /// This method cryptographically binds a message to the signer's identity for a
    /// single, unique epoch. It strictly enforces the "one-signature-per-epoch" rule.
    /// The signing process may be probabilistic, typically involving a randomized
    /// message encoding step that might require multiple attempts.
    ///
    /// ### Parameters
    /// * `rng`: A random number generator, required for signature schemes that use
    ///   probabilistic components (e.g., randomized message encoding).
    /// * `sk`: A reference to the secret key to be used for signing.
    /// * `epoch`: The specific epoch for which the signature is being created.
    /// * `message`: A fixed-size byte array representing the message to be signed.
    ///
    /// ### Returns
    /// A `Result` which is:
    /// * `Ok(Self::Signature)` on success, containing the generated signature.
    /// * `Err(SigningError)` on failure, for instance, if the probabilistic
    ///   encoding step fails to produce a valid codeword within the allowed attempts.
    fn sign<R: Rng>(
        rng: &mut R,
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError>;

    /// Verifies a digital signature against a public key, message, and epoch.
    ///
    /// This function determines if a signature is authentic and was generated by the
    /// holder of the corresponding secret key for the specified message and epoch.
    /// The verification process typically involves re-computing the one-time public
    /// key from the signature's components and then verifying its inclusion in the
    /// Merkle tree via the provided authentication path.
    ///
    /// ### Parameters
    /// * `pk`: A reference to the public key against which to verify the signature.
    /// * `epoch`: The epoch the signature corresponds to.
    /// * `message`: The message that was supposedly signed.
    /// * `sig`: A reference to the signature to be verified.
    ///
    /// ### Returns
    /// `true` if the signature is valid according to the scheme's rules, `false` otherwise.
    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool;

    /// A test-only function to assert that the generic parameters chosen for the
    /// signature scheme are valid and compatible.
    ///
    /// ### Panics
    /// This function will panic if any of the internal consistency checks fail.
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
