use rand::Rng;
use rayon::prelude::*;
use serde::{Serialize, de::DeserializeOwned};

use crate::symmetric::prf::Pseudorandom;

/// Trait to model a tweakable hash function.
///
/// This trait defines the core operations for a hash function that uses
/// tweaks for domain separation. A tweak acts as an address or identifier
/// that ensures different applications of the hash produce distinct outputs.
///
/// The hash function maps `[Domain]` → `Domain`, supporting both single
/// values and lists of values.
pub trait TweakableHash {
    /// Public parameter type for the hash function
    type Parameter: Copy + Sized + Send + Sync + Serialize + DeserializeOwned;

    /// Tweak type for domain separation
    type Tweak;

    /// Domain element type (output and input to the hash)
    type Domain: Copy + PartialEq + Sized + Send + Sync + Serialize + DeserializeOwned;

    /// Generates a random public parameter.
    fn rand_parameter<R: Rng>(rng: &mut R) -> Self::Parameter;

    /// Generates a random domain element.
    fn rand_domain<R: Rng>(rng: &mut R) -> Self::Domain;

    /// Returns a tweak to be used in Merkle tree node hashing.
    ///
    /// The tweak is derived from the node's level and position within that level.
    ///
    /// Tree tweaks are guaranteed to be distinct from chain tweaks.
    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak;

    /// Returns a tweak to be used in hash chain iteration.
    ///
    /// The tweak is derived from the epoch, chain index, and position within the chain.
    ///
    /// Chain tweaks are guaranteed to be distinct from tree tweaks.
    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak;

    /// Applies the tweakable hash to a parameter, tweak, and message.
    ///
    /// # Arguments
    /// * `parameter` - Public parameter for the hash function
    /// * `tweak` - Domain separator (tree or chain tweak)
    /// * `message` - Input message (one or more domain elements)
    ///
    /// # Returns
    /// Single domain element representing the hash output
    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain;

    /// Computes bottom tree leaves by walking hash chains for multiple epochs.
    ///
    /// This method has a default scalar implementation that processes epochs in parallel.
    /// Hash functions implementing `PackedTweakableHash` can override this to use SIMD.
    ///
    /// # Arguments
    /// * `prf_key` - PRF key for generating chain starting points
    /// * `parameter` - Hash function parameter
    /// * `epochs` - Slice of epoch numbers to process
    /// * `num_chains` - Number of hash chains per epoch
    /// * `chain_length` - Length of each hash chain
    ///
    /// # Returns
    /// Vector of leaf hashes, one per epoch, in the same order as `epochs`
    fn compute_tree_leaves<PRF>(
        prf_key: &PRF::Key,
        parameter: &Self::Parameter,
        epochs: &[u32],
        num_chains: usize,
        chain_length: usize,
    ) -> Vec<Self::Domain>
    where
        PRF: Pseudorandom,
        PRF::Domain: Into<Self::Domain>,
        Self: Sized,
    {
        // Default scalar implementation: process each epoch in parallel
        epochs
            .par_iter()
            .map(|&epoch| {
                // For each epoch, walk all chains in parallel
                let chain_ends: Vec<_> = (0..num_chains)
                    .into_par_iter()
                    .map(|c_idx| {
                        let start = PRF::get_domain_element(prf_key, epoch, c_idx as u64).into();
                        chain::<Self>(parameter, epoch, c_idx as u8, 0, chain_length - 1, &start)
                    })
                    .collect();
                // Hash all chain ends together to get the leaf
                Self::apply(parameter, &Self::tree_tweak(0, epoch), &chain_ends)
            })
            .collect()
    }

    /// Function to check internal consistency of any given parameters.
    ///
    /// This is for testing only and is expected to panic if something is wrong.
    #[cfg(test)]
    fn internal_consistency_check();
}

/// Function implementing hash chains, implemented over a tweakable hash function
/// The chain is specific to an epoch `epoch`, and an index `chain_index`. All
/// evaluations of the tweakable hash function use the given parameter `parameter`
/// and tweaks determined by `epoch`, `chain_index`, and their position in the chain.
/// We start walking the chain at position `start_pos_in_chain` with `start`,
/// and then walk the chain for `steps` many steps. For example, walking two steps
/// with `start = A` would mean we walk A -> B -> C, and then return C.
pub fn chain<TH: TweakableHash>(
    parameter: &TH::Parameter,
    epoch: u32,
    chain_index: u8,
    start_pos_in_chain: u8,
    steps: usize,
    start: &TH::Domain,
) -> TH::Domain {
    // keep track of what we have
    let mut current = *start;

    // otherwise, walk the right amount of steps
    for j in 0..steps {
        let tweak = TH::chain_tweak(epoch, chain_index, start_pos_in_chain + (j as u8) + 1u8);
        current = TH::apply(parameter, &tweak, &[current]);
    }

    // return where we are now
    current
}

pub mod poseidon;
pub mod sha;

#[cfg(test)]
mod tests {
    use sha::ShaTweak128192;

    use super::*;
    use proptest::prelude::*;

    type TestTH = ShaTweak128192;

    #[test]
    fn test_chain_associative() {
        let mut rng = rand::rng();

        // we test that first walking k steps, and then walking the remaining steps
        // is the same as directly walking all steps.

        let epoch = 9;
        let chain_index = 20;
        let parameter = TestTH::rand_parameter(&mut rng);
        let start = TestTH::rand_domain(&mut rng);
        let total_steps = 16;

        // walking directly
        let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

        for split in 0..=total_steps {
            let steps_a = split;
            let steps_b = total_steps - split;

            // walking indirectly
            let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);
            let end_indirect = chain::<TestTH>(
                &parameter,
                epoch,
                chain_index,
                steps_a as u8,
                steps_b,
                &intermediate,
            );

            // should be the same
            assert_eq!(end_direct, end_indirect);
        }
    }

    #[test]
    fn test_chain_associative_max_value() {
        let mut rng = rand::rng();

        // we test that first walking k steps, and then walking the remaining steps
        // is the same as directly walking all steps.

        let epoch = 12;
        let chain_index = 210;
        let parameter = TestTH::rand_parameter(&mut rng);
        let start = TestTH::rand_domain(&mut rng);
        let total_steps = u8::MAX as usize; // max if we say that pos_in_chain is u8

        // walking directly
        let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

        for split in 0..=total_steps {
            let steps_a = split;
            let steps_b = total_steps - split;

            // walking indirectly
            let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);
            let end_indirect = chain::<TestTH>(
                &parameter,
                epoch,
                chain_index,
                steps_a as u8,
                steps_b,
                &intermediate,
            );

            // should be the same
            assert_eq!(end_direct, end_indirect);
        }
    }

    proptest! {
        #[test]
        fn proptest_chain_associative(
            // Random epoch for domain separation (small range to keep tests fast)
            epoch in 0u32..100,

            // Random chain index to simulate different chains (small range to keep tests fast)
            chain_index in 0u8..10,

            // Total number of steps to walk along the chain (bounded to keep tests fast)
            total_steps in 0usize..16,
        ) {
            // Random number generator for generating parameters and start point
            let mut rng = rand::rng();

            // Generate a random public parameter for the tweakable hash function
            let parameter = TestTH::rand_parameter(&mut rng);

            // Generate a random starting domain element (initial hash state)
            let start = TestTH::rand_domain(&mut rng);

            // Compute the result of walking the entire chain in one go
            let end_direct = chain::<TestTH>(&parameter, epoch, chain_index, 0, total_steps, &start);

            // For every way of splitting the walk into two segments...
            for split in 0..=total_steps {
                let steps_a = split;                  // First segment length
                let steps_b = total_steps - split;    // Second segment length

                // First walk: from start, walk `steps_a` steps
                let intermediate = chain::<TestTH>(&parameter, epoch, chain_index, 0, steps_a, &start);

                // Second walk: continue from intermediate point for `steps_b` steps
                let end_indirect = chain::<TestTH>(
                    &parameter,
                    epoch,
                    chain_index,
                    steps_a as u8,   // Start position for second segment
                    steps_b,
                    &intermediate,
                );

                // Check that walking in one go or in two segments gives the same result
                prop_assert_eq!(end_direct, end_indirect);
            }
        }
    }
}
