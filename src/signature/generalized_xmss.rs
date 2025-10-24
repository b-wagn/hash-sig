use std::marker::PhantomData;

use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    MESSAGE_LENGTH,
    inc_encoding::IncomparableEncoding,
    signature::SignatureSchemeSecretKey,
    symmetric::{
        prf::Pseudorandom,
        tweak_hash::{TweakableHash, chain},
        tweak_hash_tree::{HashSubTree, HashTreeOpening, combined_path, hash_tree_verify},
    },
};

use super::{SignatureScheme, SigningError};

/// Implementation of the generalized XMSS signature scheme
/// from any incomparable encoding scheme and any tweakable hash
///
/// It also uses a PRF for key generation, and one has to specify
/// the (base 2 log of the) key lifetime.
///
/// Note: lifetimes beyond 2^32 are not supported.
pub struct GeneralizedXMSSSignatureScheme<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    _prf: std::marker::PhantomData<PRF>,
    _ie: std::marker::PhantomData<IE>,
    _th: std::marker::PhantomData<TH>,
}

/// Signature for GeneralizedXMSSSignatureScheme
/// It contains a Merkle authentication path, encoding randomness, and a list of hashes
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,
    rho: IE::Randomness,
    hashes: Vec<TH::Domain>,
}

/// Public key for GeneralizedXMSSSignatureScheme
/// It contains a Merkle root and a parameter for the tweakable hash
#[derive(Serialize, Deserialize)]
pub struct GeneralizedXMSSPublicKey<TH: TweakableHash> {
    root: TH::Domain,
    parameter: TH::Parameter,
}

/// Secret key for GeneralizedXMSSSignatureScheme
/// It contains a PRF key and a Merkle tree.
///
/// Note: one may choose to regenerate the tree on the fly, but this
/// would be costly for signatures.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct GeneralizedXMSSSecretKey<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> {
    prf_key: PRF::Key,
    parameter: TH::Parameter,
    activation_epoch: usize,
    num_active_epochs: usize,
    top_tree: HashSubTree<TH>,
    left_bottom_tree_index: usize,
    left_bottom_tree: HashSubTree<TH>,
    right_bottom_tree: HashSubTree<TH>,
    _encoding_type: PhantomData<IE>,
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    SignatureSchemeSecretKey for GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    fn get_activation_interval(&self) -> std::ops::Range<u64> {
        let start = self.activation_epoch as u64;
        let end = start + self.num_active_epochs as u64;
        start..end
    }

    fn get_prepared_interval(&self) -> std::ops::Range<u64> {
        // the key is prepared for all epochs covered by the left and right bottom tree
        // and each bottom tree covers exactly 2^{LOG_LIFETIME / 2} leafs
        let leafs_per_bottom_tree = 1 << (LOG_LIFETIME / 2);
        let start = (self.left_bottom_tree_index * leafs_per_bottom_tree) as u64;
        let end = start + (2 * leafs_per_bottom_tree as u64);
        start..end
    }

    fn advance_preparation(&mut self) {
        // First, check if advancing is possible by comparing to activation interval.
        let leafs_per_bottom_tree = 1 << (LOG_LIFETIME / 2);
        let next_prepared_end_epoch =
            self.left_bottom_tree_index * leafs_per_bottom_tree + 3 * leafs_per_bottom_tree;
        if next_prepared_end_epoch as u64 > self.get_activation_interval().end {
            return;
        }

        // We compute the new right bottom subtree (using the helper function bottom_tree_from_prf_key)
        let new_right_bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
            &self.prf_key,
            self.left_bottom_tree_index + 2,
            &self.parameter,
        );

        // The bottom tree that was previously right should now be left.
        // So, we move the right bottom subtree to the left one and update our index.
        // We also write the new right bottom tree into the right bottom tree field.
        // Note that once the function terminates, the old left bottom tree is dropped
        // from memory. So, at any point in time, we have at most 4 trees in memory,
        // namely, the three bottom trees (two current, one new) and the top tree.
        self.left_bottom_tree =
            std::mem::replace(&mut self.right_bottom_tree, new_right_bottom_tree);
        self.left_bottom_tree_index += 1;
    }
}

/// Helper function to take a desired activation time (given by start and duration)
/// and potentially increase it, so that, for C = 1 << (LOG_LIFETIME/2).
///     1. the new duration is a multiple of C
///     2. the new duration is at least 2 * C
///     3. the new activation time starts at a multiple of C
///     4. the new activation interval is contained in [0...C^2) = [0,..LIFETIME).
///     5. the new interval contains the desired interval.
///
/// The returned result is a pair (start, excl_end) of integers, such that the new
/// activation interval is given by [start * C , excl_end * C).
fn expand_activation_time<const LOG_LIFETIME: usize>(
    desired_activation_epoch: usize,
    desired_num_active_epochs: usize,
) -> (usize, usize) {
    let lifetime = 1usize << LOG_LIFETIME;
    let c = 1usize << (LOG_LIFETIME / 2);
    // c_mask has the form 1...10...0, with LOG_LIFETIME / 2 many 0's.
    let c_mask = !(c - 1);

    let desired_start = desired_activation_epoch;
    let desired_end = desired_activation_epoch + desired_num_active_epochs;

    // 1. Start by aligning the *start* downward to a multiple of C.
    // we can do that by bitwise and with c_mask.
    let mut start = desired_start & c_mask;

    // 2. Round the *end* upward to a multiple of C.
    // This guarantees the original interval is fully contained.
    let mut end = (desired_end + c - 1) & c_mask;

    // 3. Enforce minimum duration of 2*C.
    if end - start < 2 * c {
        end = start + 2 * c;
    }

    // 4. If the new interval exceeds lifetime, shift it left to fit inside [0, lifetime)
    if end > lifetime {
        let duration = end - start;
        if duration > lifetime {
            // Pathological: expanded interval exceeds lifetime
            start = 0;
            end = lifetime;
        } else {
            end = lifetime;
            start = (lifetime - duration) & c_mask;
        }
    }

    // now divide by c to get what we want
    start >>= LOG_LIFETIME / 2;
    end >>= LOG_LIFETIME / 2;

    (start, end)
}

/// Helper function to compute a bottom tree from the PRF key. The PRF key is used to re-generate
/// the secret keys, then the public keys are generated and hashed to obtain the leafs of the
/// bottom tree. Then the bottom tree is computed.
fn bottom_tree_from_prf_key<
    PRF: Pseudorandom,
    IE: IncomparableEncoding,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
>(
    prf_key: &PRF::Key,
    bottom_tree_index: usize,
    parameter: &TH::Parameter,
) -> HashSubTree<TH>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    let leafs_per_bottom_tree = 1 << (LOG_LIFETIME / 2);
    let num_chains = IE::DIMENSION;
    let chain_length = IE::BASE;

    // the range of epochs covered by that bottom tree
    let epoch_start = bottom_tree_index * leafs_per_bottom_tree;
    let epochs: Vec<u32> = (epoch_start..epoch_start + leafs_per_bottom_tree)
        .map(|e| e as u32)
        .collect();

    // Attempt to use the optimized batch computation path.
    let chain_ends_hashes = TH::try_compute_leaves_batched::<PRF>(
        prf_key,
        parameter,
        &epochs,
        num_chains,
        chain_length,
    )
    .unwrap_or_else(|| {
        // Fallback to the generic parallel scalar implementation.
        epochs
            .par_iter()
            .map(|&epoch| {
                let chain_ends: Vec<_> = (0..num_chains)
                    .into_par_iter()
                    .map(|c_idx| {
                        let start = PRF::get_domain_element(prf_key, epoch, c_idx as u64).into();
                        chain::<TH>(parameter, epoch, c_idx as u8, 0, chain_length - 1, &start)
                    })
                    .collect();
                TH::apply(parameter, &TH::tree_tweak(0, epoch), &chain_ends)
            })
            .collect()
    });

    // now that we have the hashes of all chain ends (= leafs of our tree), we can compute the bottom tree
    HashSubTree::new_bottom_tree(
        LOG_LIFETIME,
        bottom_tree_index,
        parameter,
        chain_ends_hashes,
    )
}

impl<
    PRF: Pseudorandom,
    IE: IncomparableEncoding + Sync + Send,
    TH: TweakableHash,
    const LOG_LIFETIME: usize,
> SignatureScheme for GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Domain: Into<TH::Domain>,
    PRF::Randomness: Into<IE::Randomness>,
    TH::Parameter: Into<IE::Parameter>,
{
    type PublicKey = GeneralizedXMSSPublicKey<TH>;

    type SecretKey = GeneralizedXMSSSecretKey<PRF, IE, TH, LOG_LIFETIME>;

    type Signature = GeneralizedXMSSSignature<IE, TH>;

    const LIFETIME: u64 = 1 << LOG_LIFETIME;

    fn key_gen<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (Self::PublicKey, Self::SecretKey) {
        // checks for `activation_epoch` and `num_active_epochs`
        assert!(
            activation_epoch + num_active_epochs <= Self::LIFETIME as usize,
            "Key gen: `activation_epoch` and `num_active_epochs` are invalid for this lifetime"
        );

        // Note: this implementation uses the top-bottom tree approach, which is as follows:
        //
        // We envision that the full Merkle tree into one top tree and `sqrt(LIFETIME)` bottom trees.
        // The top tree contains the root and the `LOG_LIFETIME/2` layers below it. This top tree has
        // `sqrt(LIFETIME)` many leafs (but can be sparse and have less). For each leaf that exists,
        // this leaf is the roof of a bottom tree. Thus, there are at most `sqrt(LIFETIME)` bottom trees,
        // each having `sqrt(LIFETIME)` leafs. We now restrict increase the activation time to be a
        // multiple of `sqrt(LIFETIME)` that aligns with these bottom trees, and is at least of length
        // `2*sqrt(LIFETIME)` so that we have at least two bottom trees.
        //
        // Our invariant is that the secret key always stores the full top tree and two consecutive
        // bottom trees. The secret key can then sign epochs contained in the leafs of these two
        // consecutive bottom trees, and we provide an update function that re-computes the next bottom
        // tree and drops the older of the two current ones (function advance_preparation).
        //
        // During key generation, we first generate all bottom trees and store their roots, then we
        // generate the top tree just from their roots.

        // before we do anything, we expand our activation range so that the
        // top-bottom tree approach can be applied cleanly.
        let leafs_per_bottom_tree = 1 << (LOG_LIFETIME / 2);
        let (start_bottom_tree_index, end_bottom_tree_index) =
            expand_activation_time::<LOG_LIFETIME>(activation_epoch, num_active_epochs);
        let num_bottom_trees = end_bottom_tree_index - start_bottom_tree_index;
        assert!(num_bottom_trees >= 2);
        let activation_epoch = start_bottom_tree_index * leafs_per_bottom_tree;
        let num_active_epochs = num_bottom_trees * leafs_per_bottom_tree;

        // we need a random parameter to be used for the tweakable hash
        let parameter = TH::rand_parameter(rng);

        // we need a PRF key to generate our list of actual secret keys
        let prf_key = PRF::key_gen(rng);

        // first, we build all bottom trees and keep track of their root. We treat the first two
        // bottom trees differently, as we want to keep them in our key. While building the bottom
        // trees, we generate all hash chains using our PRF key, and hash their ends to get the
        // leafs of our bottom trees. This is done in `bottom_tree_from_prf_key`.
        let (left_bottom_tree, right_bottom_tree) = rayon::join(
            || {
                bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
                    &prf_key,
                    start_bottom_tree_index,
                    &parameter,
                )
            },
            || {
                bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
                    &prf_key,
                    start_bottom_tree_index + 1,
                    &parameter,
                )
            },
        );
        let left_bottom_tree_index = start_bottom_tree_index;

        let mut roots_of_bottom_trees = Vec::with_capacity(num_bottom_trees);
        roots_of_bottom_trees.push(left_bottom_tree.root());
        roots_of_bottom_trees.push(right_bottom_tree.root());

        // the rest of the bottom trees in parallel
        roots_of_bottom_trees.extend(
            (start_bottom_tree_index + 2..end_bottom_tree_index)
                .into_par_iter()
                .map(|bottom_tree_index| {
                    let bottom_tree = bottom_tree_from_prf_key::<PRF, IE, TH, LOG_LIFETIME>(
                        &prf_key,
                        bottom_tree_index,
                        &parameter,
                    );
                    bottom_tree.root()
                })
                .collect::<Vec<_>>(), // note: roots are in the correct order.
        );

        // second, we build the top tree, which has the roots of our bottom trees
        // as leafs. the root of it will be our public key.
        let top_tree = HashSubTree::new_top_tree(
            rng,
            LOG_LIFETIME,
            start_bottom_tree_index,
            &parameter,
            roots_of_bottom_trees,
        );
        let root = top_tree.root();

        // assemble public key and secret key
        let pk = GeneralizedXMSSPublicKey { root, parameter };
        let sk = GeneralizedXMSSSecretKey {
            prf_key,
            parameter,
            activation_epoch,
            num_active_epochs,
            top_tree,
            left_bottom_tree_index,
            left_bottom_tree,
            right_bottom_tree,
            _encoding_type: PhantomData,
        };

        (pk, sk)
    }

    fn sign(
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError> {
        // check that epoch is indeed a valid epoch in the activation range

        assert!(
            sk.get_activation_interval().contains(&(epoch as u64)),
            "Signing: key not active during this epoch."
        );

        // check that we are already prepared for this epoch
        assert!(
            sk.get_prepared_interval().contains(&(epoch as u64)),
            "Signing: key not yet prepared for this epoch, try calling sk.advance_preparation."
        );

        // first component of the signature is the Merkle path that
        // opens the one-time pk for that epoch, where the one-time pk
        // will be recomputed by the verifier from the signature.
        let leafs_per_bottom_tree = 1 << (LOG_LIFETIME / 2);
        let boundary_between_bottom_trees =
            (sk.left_bottom_tree_index * leafs_per_bottom_tree + leafs_per_bottom_tree) as u32;
        let bottom_tree = if epoch < boundary_between_bottom_trees {
            &sk.left_bottom_tree
        } else {
            &sk.right_bottom_tree
        };
        let path = combined_path(&sk.top_tree, bottom_tree, epoch);

        // now, we need to encode our message using the incomparable encoding.
        // we retry until we get a valid codeword, or until we give up.
        let max_tries = IE::MAX_TRIES;
        let mut attempts = 0;
        let mut x = None;
        let mut rho = None;
        while attempts < max_tries {
            // get a randomness and try to encode the message. Note: we get the randomness from the PRF
            // which ensures that signing is deterministic. The PRF is applied to the message and the epoch.
            // While the intention is that users of the scheme never call sign twice with the same (epoch, sk) pair,
            // this deterministic approach ensures that calling sign twice is fine, as long as the message stays the same.
            let curr_rho = PRF::get_randomness(&sk.prf_key, epoch, message, attempts as u64).into();
            let curr_x = IE::encode(&sk.parameter.into(), message, &curr_rho, epoch);

            // check if we have found a valid codeword, and if so, stop searching
            if curr_x.is_ok() {
                rho = Some(curr_rho);
                x = curr_x.ok();
                break;
            }

            attempts += 1;
        }

        // if we have not found a valid codeword, return an error
        if x.is_none() {
            return Err(SigningError::EncodingAttemptsExceeded {
                attempts: max_tries,
            });
        }

        // otherwise, unwrap x and rho
        let x = x.unwrap();
        let rho = rho.unwrap();

        // we will include rho in the signature, and
        // we use x to determine how far the signer walks in the chains
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );

        // In parallel, compute the hash values for each chain based on the codeword `x`.
        let hashes = (0..num_chains)
            .into_par_iter()
            .map(|chain_index| {
                // get back to the start of the chain from the PRF
                let start = PRF::get_domain_element(&sk.prf_key, epoch, chain_index as u64).into();
                // now walk the chain for a number of steps determined by the current chunk of x
                let steps = x[chain_index] as usize;
                chain::<TH>(&sk.parameter, epoch, chain_index as u8, 0, steps, &start)
            })
            .collect();

        // assemble the signature: Merkle path, randomness, chain elements
        Ok(GeneralizedXMSSSignature { path, rho, hashes })
    }

    fn verify(
        pk: &Self::PublicKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
        sig: &Self::Signature,
    ) -> bool {
        assert!(
            (epoch as u64) < Self::LIFETIME,
            "Generalized XMSS - Verify: Epoch too large."
        );

        // first get back the codeword and make sure
        // encoding succeeded with the given randomness.
        let Ok(x) = IE::encode(&pk.parameter.into(), message, &sig.rho, epoch) else {
            return false;
        };

        // now, we recompute the epoch's one-time public key
        // from the hashes by walking hash chains.
        let chain_length = IE::BASE;
        let num_chains = IE::DIMENSION;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );
        let mut chain_ends = Vec::with_capacity(num_chains);
        for (chain_index, xi) in x.iter().enumerate() {
            // If the signer has already walked x[i] steps, then we need
            // to walk chain_length - 1 - x[i] steps to reach the end of the chain
            // Note: by our consistency checks, we have chain_length <= 2^8, so chain_length - 1 fits into u8
            let steps = (chain_length - 1) as u8 - xi;
            let start_pos_in_chain = *xi;
            let start = &sig.hashes[chain_index];
            let end = chain::<TH>(
                &pk.parameter,
                epoch,
                chain_index as u8,
                start_pos_in_chain,
                steps as usize,
                start,
            );
            chain_ends.push(end);
        }

        // this set of chain ends should be a leaf in the Merkle tree
        // we verify that by checking the Merkle authentication path
        hash_tree_verify(
            &pk.parameter,
            &pk.root,
            epoch,
            chain_ends.as_slice(),
            &sig.path,
        )
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // we check consistency of all internally used components
        // namely, PRF, incomparable encoding, and tweak hash
        PRF::internal_consistency_check();
        IE::internal_consistency_check();
        TH::internal_consistency_check();

        // assert BASE and DIMENSION are small enough to make sure that we can fit
        // pos_in_chain and chain_index in u8.

        assert!(
            IE::BASE <= 1 << 8,
            "Generalized XMSS: Encoding base too large, must be at most 2^8"
        );
        assert!(
            IE::DIMENSION <= 1 << 8,
            "Generalized XMSS: Encoding dimension too large, must be at most 2^8"
        );

        // LOG_LIFETIME needs to be even, so that we can use the top-bottom tree approach
        assert!(
            LOG_LIFETIME.is_multiple_of(2),
            "Generalized XMSS: LOG_LIFETIME must be multiple of two"
        );
    }
}

/// Instantiations of the generalized XMSS signature scheme based on Poseidon2
pub mod instantiations_poseidon;
/// Instantiations of the generalized XMSS signature scheme based on the
/// top level target sum encoding using Poseidon2
pub mod instantiations_poseidon_top_level;
/// Instantiations of the generalized XMSS signature scheme based on SHA
pub mod instantiations_sha;

#[cfg(test)]
mod tests {
    use crate::{
        inc_encoding::{basic_winternitz::WinternitzEncoding, target_sum::TargetSumEncoding},
        signature::test_templates::test_signature_scheme_correctness,
        symmetric::{
            message_hash::{
                MessageHash,
                poseidon::PoseidonMessageHashW1,
                sha::{ShaMessageHash, ShaMessageHash192x3},
            },
            prf::{sha::ShaPRF, shake_to_field::ShakePRFtoF},
            tweak_hash::{poseidon::PoseidonTweakW1L5, sha::ShaTweak192192},
        },
    };

    use super::*;

    #[test]
    pub fn test_winternitz() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24, 24>;
        type TH = ShaTweak192192;
        type MH = ShaMessageHash192x3;
        const CHUNK_SIZE: usize = 4;
        const NUM_CHUNKS_CHECKSUM: usize = 3;
        type IE = WinternitzEncoding<MH, CHUNK_SIZE, NUM_CHUNKS_CHECKSUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();
        test_signature_scheme_correctness::<Sig>(289, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_winternitz_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const CHUNK_SIZE: usize = 1;
        const _BASE: usize = 2;
        const NUM_CHUNKS_CHECKSUM: usize = 8;
        type IE = WinternitzEncoding<MH, CHUNK_SIZE, NUM_CHUNKS_CHECKSUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);

        test_signature_scheme_correctness::<Sig>(12, 10, (1 << 5) - 10);
        test_signature_scheme_correctness::<Sig>(19, 4, 20);
        test_signature_scheme_correctness::<Sig>(16, 16, 4);
        test_signature_scheme_correctness::<Sig>(11, 1, 29);
    }

    #[test]
    pub fn test_target_sum() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24, 24>;
        type TH = ShaTweak192192;
        type MH = ShaMessageHash192x3;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 8;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(13, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(9, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(21, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(31, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_target_sum_poseidon() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_deterministic() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShakePRFtoF<7, 5>;
        type TH = PoseidonTweakW1L5;
        type MH = PoseidonMessageHashW1;
        const BASE: usize = MH::BASE;
        const NUM_CHUNKS: usize = MH::DIMENSION;
        const MAX_CHUNK_VALUE: usize = BASE - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 6;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        // we sign the same (epoch, message) pair twice (which users of this code should not do)
        // and ensure that it produces the same randomness for the signature.
        let mut rng = rand::rng();
        let (_pk, mut sk) = Sig::key_gen(&mut rng, 0, 1 << LOG_LIFETIME);
        let message = rng.random();
        let epoch = 29;

        // prepare key for epoch
        let mut iterations = 0;
        while !sk.get_prepared_interval().contains(&(epoch as u64)) && iterations < epoch {
            sk.advance_preparation();
            iterations += 1;
        }
        assert!(
            sk.get_prepared_interval().contains(&(epoch as u64)),
            "Did not even try signing, failed to advance key preparation to desired epoch {:?}.",
            epoch
        );

        let sig1 = Sig::sign(&sk, epoch, &message).unwrap();
        let sig2 = Sig::sign(&sk, epoch, &message).unwrap();
        let rho1 = sig1.rho;
        let rho2 = sig2.rho;
        assert_eq!(rho1, rho2);
    }

    #[test]
    pub fn test_large_base_sha() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24, 8>;
        type TH = ShaTweak192192;

        // use chunk size 8
        type MH = ShaMessageHash<24, 8, 32, 8>;
        const TARGET_SUM: usize = 1 << 12;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(0, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(11, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_large_dimension_sha() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24, 8>;
        type TH = ShaTweak192192;

        // use 256 chunks
        type MH = ShaMessageHash<24, 8, 256, 1>;
        const TARGET_SUM: usize = 128;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;
        const LOG_LIFETIME: usize = 10;
        type Sig = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        Sig::internal_consistency_check();

        test_signature_scheme_correctness::<Sig>(2, 0, Sig::LIFETIME as usize);
        test_signature_scheme_correctness::<Sig>(19, 0, Sig::LIFETIME as usize);
    }

    #[test]
    pub fn test_expand_activation_time() {
        const LOG_LIFETIME: usize = 4;

        // no padding needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 8);
        assert!((start == 0) && (end_excl == 2));

        // no padding needed in principle, but is extended to minimum duration of two bottom trees
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 4);
        assert!((start == 0) && (end_excl == 2));

        // simple padding needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 7);
        assert!((start == 0) && (end_excl == 2));

        // simple padding needed, and extended to minimum duration of two bottom trees
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(0, 3);
        assert!((start == 0) && (end_excl == 2));

        // padding on both sides needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(1, 8);
        assert!((start == 0) && (end_excl == 3));

        // padding only in the end needed
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(8, 5);
        assert!((start == 2) && (end_excl == 4));

        // large padding to the left needed because of two bottom trees constraint
        let (start, end_excl) = expand_activation_time::<LOG_LIFETIME>(12, 2);
        assert!((start == 2) && (end_excl == 4));
    }
}
