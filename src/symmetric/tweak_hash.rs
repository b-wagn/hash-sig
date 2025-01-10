use rand::Rng;

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
    type Parameter: Copy + Sized;
    type Tweak;
    type Domain: Copy + PartialEq + Sized;

    /// Generates a random public parameter.
    fn rand_parameter<R: Rng>(rng: &mut R) -> Self::Parameter;

    /// Generates a random domain element.
    fn rand_domain<R: Rng>(rng: &mut R) -> Self::Domain;

    /// Returns a tweak to be used in the Merkle tree.
    /// Note: this is assumed to be distinct from the outputs of chain_tweak
    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak;

    /// Returns a tweak to be used in chains.
    /// Note: this is assumed to be distinct from the outputs of tree_tweak
    fn chain_tweak(epoch: u32, chain_index: u16, pos_in_chain: u16) -> Self::Tweak;

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

/// Function implementing hash chains, implemented over a tweakable hash function
/// The chain is specific to an epoch `epoch`, and an index `chain_index`. All
/// evaluations of the tweakable hash function use the given parameter `parameter`
/// and tweaks determined by `epoch`, `chain_index`, and their position in the chain.
/// We start walking the chain at position `start_pos_in_chain` with `start`,
/// and then walk the chain for `steps` many steps. For example, walking two steps
/// with `start = A` would mean we walk A -> B -> C, and then return C.
pub(crate) fn chain<TH: TweakableHash>(
    parameter: &TH::Parameter,
    epoch: u32,
    chain_index: u16,
    start_pos_in_chain: u16,
    steps: usize,
    start: &TH::Domain,
) -> TH::Domain {
    // keep track of what we have
    let mut current = start.clone();

    // otherwise, walk the right amount of steps
    for j in 0..steps {
        let tweak = TH::chain_tweak(epoch, chain_index, start_pos_in_chain + (j as u16) + 1);
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
    use rand::thread_rng;

    type TestTH = ShaTweak128192;

    #[test]
    fn test_chain_associative() {
        let mut rng = thread_rng();

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
                steps_a as u16,
                steps_b,
                &intermediate,
            );

            // should be the same
            assert_eq!(end_direct, end_indirect);
        }
    }
}
