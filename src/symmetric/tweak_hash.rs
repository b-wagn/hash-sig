use p3_field::{Field, PackedField};
use rand::Rng;
use serde::{Serialize, de::DeserializeOwned};

/// Trait to model a tweakable hash function.
/// Such a function takes a public parameter, a tweak, and a
/// message to be hashed. The tweak should be understood as an
/// address for domain separation.
///
/// In our setting, we require the support of hashing lists of
/// hashes. Therefore, we just define a type `Domain` and the
/// hash function maps from [Domain] to Domain.
///
/// We also require that the tweak hash already specifies how
/// to obtain distinct tweaks for applications in chains and
/// applications in Merkle trees.
pub trait TweakableHash {
    type Parameter: Copy + Sized + Send + Sync + Serialize + DeserializeOwned;
    type Tweak;
    type Domain: Copy + PartialEq + Sized + Send + Sync + Serialize + DeserializeOwned;

    /// Generates a random public parameter.
    fn rand_parameter<R: Rng>(rng: &mut R) -> Self::Parameter;

    /// Generates a random domain element.
    fn rand_domain<R: Rng>(rng: &mut R) -> Self::Domain;

    /// Returns a tweak to be used in the Merkle tree.
    /// Note: this is assumed to be distinct from the outputs of chain_tweak
    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak;

    /// Returns a tweak to be used in chains.
    /// Note: this is assumed to be distinct from the outputs of tree_tweak
    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak;

    /// Applies the tweakable hash to parameter, tweak, and message.
    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain;

    /// Function to check internal consistency of any given parameters
    /// For testing only, and expected to panic if something is wrong.
    #[cfg(test)]
    fn internal_consistency_check();
}

/// Trait to model a tweakable hash function that supports packed (SIMD) operations.
///
/// This trait enables SIMD-accelerated hash tree construction by processing
/// multiple hash computations in parallel. The HASH_LEN and TWEAK_LEN parameters
/// must match the lengths used in the Domain type of the underlying TweakableHash.
pub trait PackedTweakableHash<P, F>: TweakableHash
where
    P: PackedField<Scalar = F>,
    F: Field,
{
    /// Applies the hash to a batch of WIDTH pairs in parallel using SIMD.
    ///
    /// # Arguments
    /// * `parameter` - The public parameter (scalar, broadcasted to all lanes)
    /// * `tweak` - Packed tweak values for WIDTH parallel computations
    /// * `left` - Packed left children (SoA format)
    /// * `right` - Packed right children (SoA format)
    ///
    /// # Returns
    /// Packed parent hashes.
    fn apply_packed<const HASH_LEN: usize, const TWEAK_LEN: usize>(
        parameter: &Self::Parameter,
        tweak: [P; TWEAK_LEN],
        left: [P; HASH_LEN],
        right: [P; HASH_LEN],
    ) -> [P; HASH_LEN];

    /// Generates packed tweaks for a batch of tree nodes at the same level.
    ///
    /// # Arguments
    /// * `level` - The level in the tree (scalar, same for all lanes)
    /// * `starting_pos` - Packed positions [pos, pos+1, ..., pos+WIDTH-1]
    ///
    /// # Returns
    /// Packed tweak values.
    fn tree_tweak_packed<const TWEAK_LEN: usize>(level: u8, starting_pos: P) -> [P; TWEAK_LEN];
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
