use rand::Rng;

use crate::{
    inc_encoding::IncomparableEncoding,
    symmetric::{
        prf::Pseudorandom,
        tweak_hash::{chain, TweakableHash},
        tweak_hash_tree::{
            build_tree, hash_tree_path, hash_tree_root, hash_tree_verify, HashTree, HashTreeOpening,
        },
    },
    MESSAGE_LENGTH,
};

use super::{SignatureScheme, SigningError};

/// Implementation of the generalized XMSS signature scheme
/// from any incomparable encoding scheme and any tweakable hash
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
    _marker_prf: std::marker::PhantomData<PRF>,
    _marker_ie: std::marker::PhantomData<IE>,
    _marker_th: std::marker::PhantomData<TH>,
}

/// Signature for GeneralizedXMSSSignatureScheme
/// It contains a Merkle authentication path, encoding randomness, and a list of hashes
pub struct GeneralizedXMSSSignature<IE: IncomparableEncoding, TH: TweakableHash> {
    path: HashTreeOpening<TH>,
    rho: IE::Randomness,
    hashes: Vec<TH::Domain>,
}

/// Public key for GeneralizedXMSSSignatureScheme
/// It contains a Merkle root and a parameter for the tweakable hash
pub struct GeneralizedXMSSPublicKey<TH: TweakableHash> {
    root: TH::Domain,
    parameter: TH::Parameter,
}

/// Secret key for GeneralizedXMSSSignatureScheme
/// It contains a PRF key and a Merkle tree.
///
/// Note: one may choose to regenerate the tree on the fly, but this
/// would be costly for signatures.
pub struct GeneralizedXMSSSecretKey<PRF: Pseudorandom, TH: TweakableHash> {
    prf_key: PRF::Key,
    tree: HashTree<TH>,
    parameter: TH::Parameter,
}

impl<PRF: Pseudorandom, IE: IncomparableEncoding, TH: TweakableHash, const LOG_LIFETIME: usize>
    SignatureScheme for GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>
where
    PRF::Output: Into<TH::Domain>,
    TH::Parameter: Into<IE::Parameter>,
{
    type PublicKey = GeneralizedXMSSPublicKey<TH>;

    type SecretKey = GeneralizedXMSSSecretKey<PRF, TH>;

    type Signature = GeneralizedXMSSSignature<IE, TH>;

    const LIFETIME: u64 = 1 << LOG_LIFETIME;

    fn gen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        // Note: this implementation first generates all one-time sk's
        // and one-time pk's and then computes a Merkle tree in one go.
        // For a large lifetime (e.g., L = 2^32), this approach is not
        // well  suited  when  running on, say, 16 GiB of RAM. In this
        // setting, a more sophisticated approach is needed, e.g., one
        // could first  compute half (or quarter) of  one-time sk/pk's
        // and then their root, then save them to disc,  continue with
        // the second half, and then combine both.

        // we need a random parameter to be used for the tweakable hash
        let parameter = TH::rand_parameter(rng);

        // we need a PRF key to generate our list of actual secret keys
        let prf_key = PRF::gen(rng);

        // for each epoch, generate the secret key for the epoch
        // an epoch secret key is a list of random domain elements
        // we have one such element per chain, and we have one
        // chain per chunk of the codeword. In the same go, we also generate
        // the respective public key, which is obtained by walking the hash
        // chain starting at the secret key.
        let num_chains = IE::NUM_CHUNKS;
        let chain_length = 1 << IE::CHUNK_SIZE;
        let mut chain_starts = Vec::with_capacity(Self::LIFETIME as usize);
        let mut chain_ends = Vec::with_capacity(Self::LIFETIME as usize);

        for epoch in 0..Self::LIFETIME {
            let mut epoch_chain_starts = Vec::with_capacity(num_chains);
            let mut epoch_chain_ends = Vec::with_capacity(num_chains);

            // each epoch has a number of chains
            for chain_index in 0..num_chains {
                // each chain start is just a PRF evaluation
                let start = PRF::apply(&prf_key, epoch as u32, chain_index as u64).into();
                // walk the chain to get the public chain end
                let end = chain::<TH>(
                    &parameter,
                    epoch as u32,
                    chain_index as u16,
                    0,
                    chain_length - 1,
                    &start,
                );
                // collect
                epoch_chain_starts.push(start);
                epoch_chain_ends.push(end);
            }
            chain_starts.push(epoch_chain_starts);
            chain_ends.push(epoch_chain_ends);
        }

        // now build a Merkle tree on top of these chain ends / public keys
        let chain_ends_slices: Vec<&[TH::Domain]> =
            chain_ends.iter().map(|v| v.as_slice()).collect();
        let tree = build_tree(&parameter, &chain_ends_slices);
        let root = hash_tree_root(&tree);

        // assemble public key and secret key
        let pk = GeneralizedXMSSPublicKey {
            root,
            parameter: parameter.clone(),
        };
        let sk = GeneralizedXMSSSecretKey {
            prf_key,
            tree,
            parameter,
        };

        (pk, sk)
    }

    fn sign<R: Rng>(
        rng: &mut R,
        sk: &Self::SecretKey,
        epoch: u32,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Result<Self::Signature, SigningError> {
        // check first that we have the correct message length
        if message.len() != MESSAGE_LENGTH {
            return Err(SigningError::InvalidMessageLength);
        }

        // first component of the signature is the Merkle path that
        // opens the one-time pk for that epoch, where the one-time pk
        // will be recomputed by the verifier from the hashes
        let path = hash_tree_path(&sk.tree, epoch);

        // now, we need to encode our message using the incomparable encoding
        // we retry until we get a valid codeword, or until we give up
        let max_tries = IE::MAX_TRIES;
        let mut attempts = 0;
        let mut x = None;
        let mut rho = None;
        while attempts < max_tries {
            // sample a randomness and try to encode the message
            let curr_rho = IE::rand(rng);
            let curr_x = IE::encode(&sk.parameter.into(), message, &curr_rho, epoch);

            // check if we have found a valid codeword, and if so, stop searching
            if curr_x.is_ok() {
                rho = Some(curr_rho);
                x = curr_x.ok().map(Some).unwrap_or(None);
                break;
            }

            attempts += 1;
        }

        // if we have not found a valid codeword, return an error
        if x.is_none() {
            return Err(SigningError::UnluckyFailure);
        }

        // otherwise, unwrap x and rho
        let x = x.unwrap();
        let rho = rho.unwrap();

        // we will include rho in the signature, and
        // we use x to determine how far the signer walks in the chains
        let num_chains = IE::NUM_CHUNKS;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );
        let mut hashes = Vec::with_capacity(num_chains);
        for chain_index in 0..num_chains {
            // get back the start of the chain from the PRF
            let start = PRF::apply(&sk.prf_key, epoch as u32, chain_index as u64).into();
            // now walk the chain for a number of steps determined by x
            let steps = x[chain_index];
            let hash_in_chain = chain::<TH>(
                &sk.parameter,
                epoch,
                chain_index as u16,
                0,
                steps as usize,
                &start,
            );
            hashes.push(hash_in_chain);
        }

        // assemble the signature
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
        let x = IE::encode(&pk.parameter.into(), message, &sig.rho, epoch);
        if x.is_err() {
            return false;
        }
        let x = x.unwrap();

        // now, we recompute the epoch one-time public key
        // from the hashes, but walking hash chains.
        let chain_length = 1 << IE::CHUNK_SIZE;
        let num_chains = IE::NUM_CHUNKS;
        assert!(
            x.len() == num_chains,
            "Encoding is broken: returned too many or too few chunks."
        );
        let mut chain_ends = Vec::with_capacity(num_chains);
        for chain_index in 0..num_chains {
            // If the signer has already walked x[i] steps, then we need
            // to walk chain_length - 1 - x[i] steps to reach the end of the chain
            let steps = chain_length - 1 - x[chain_index];
            let start_pos_in_chain = x[chain_index];
            let start = &sig.hashes[chain_index];
            let end = chain::<TH>(
                &pk.parameter,
                epoch,
                chain_index as u16,
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
}

/// Instantiations of the generalized XMSS signature scheme based on SHA
pub mod instantiations_sha;

#[cfg(test)]
mod tests {
    use crate::{
        inc_encoding::{basic_winternitz::WinternitzEncoding, target_sum::TargetSumEncoding},
        signature::test_templates::_test_signature_scheme_correctness,
        symmetric::{
            message_hash::{sha::ShaMessageHash192x3, MessageHash},
            prf::hashprf::ShaPRF,
            tweak_hash::sha::ShaTweak192192,
        },
    };

    use super::*;

    #[test]
    pub fn test_correctness_winternitz() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24>;
        type TH = ShaTweak192192;
        type MH = ShaMessageHash192x3;
        const _CHUNK_SIZE: usize = 2;
        const NUM_CHUNKS_CHECKSUM: usize = 3;
        type IE = WinternitzEncoding<MH, NUM_CHUNKS_CHECKSUM>;
        const LOG_LIFETIME: usize = 9;
        type SIG = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        _test_signature_scheme_correctness::<SIG>(289);
        _test_signature_scheme_correctness::<SIG>(2);
        _test_signature_scheme_correctness::<SIG>(19);
        _test_signature_scheme_correctness::<SIG>(0);
        _test_signature_scheme_correctness::<SIG>(11);
    }

    #[test]
    pub fn test_correctness_target_sum() {
        // Note: do not use these parameters, they are just for testing
        type PRF = ShaPRF<24>;
        type TH = ShaTweak192192;
        type MH = ShaMessageHash192x3;
        const CHUNK_SIZE: usize = MH::CHUNK_SIZE;
        const NUM_CHUNKS: usize = MH::NUM_CHUNKS;
        const MAX_CHUNK_VALUE: usize = (1 << CHUNK_SIZE) - 1;
        const EXPECTED_SUM: usize = NUM_CHUNKS * MAX_CHUNK_VALUE / 2;
        type IE = TargetSumEncoding<MH, EXPECTED_SUM>;
        const LOG_LIFETIME: usize = 8;
        type SIG = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        _test_signature_scheme_correctness::<SIG>(13);
        _test_signature_scheme_correctness::<SIG>(9);
        _test_signature_scheme_correctness::<SIG>(21);
        _test_signature_scheme_correctness::<SIG>(0);
        _test_signature_scheme_correctness::<SIG>(31);
    }
}
