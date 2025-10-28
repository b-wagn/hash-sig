use core::array;

use p3_field::{Algebra, PackedValue, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;
use rayon::prelude::*;
use serde::{Serialize, de::DeserializeOwned};

use crate::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use crate::TWEAK_SEPARATOR_FOR_TREE_HASH;
use crate::poseidon2_16;
use crate::poseidon2_24;
use crate::symmetric::tweak_hash::chain;
use crate::{F, PackedF};

use super::TweakableHash;

const DOMAIN_PARAMETERS_LENGTH: usize = 4;
/// The state width for compressing a single hash in a chain.
const CHAIN_COMPRESSION_WIDTH: usize = 16;
/// The state width for merging two hashes in a tree or for the sponge construction.
const MERGE_COMPRESSION_WIDTH: usize = 24;

/// Packs scalar arrays into SIMD-friendly vertical layout.
///
/// Transposes from horizontal layout `[[F; N]; WIDTH]` to vertical layout `[PackedF; N]`.
///
/// Input layout (horizontal): each row is one complete array
/// ```text
/// data[0] = [a0, a1, a2, ..., aN]
/// data[1] = [b0, b1, b2, ..., bN]
/// data[2] = [c0, c1, c2, ..., cN]
/// ...
/// ```
///
/// Output layout (vertical): each PackedF holds one element from each array
/// ```text
/// result[0] = PackedF([a0, b0, c0, ...])  // All first elements
/// result[1] = PackedF([a1, b1, c1, ...])  // All second elements
/// result[2] = PackedF([a2, b2, c2, ...])  // All third elements
/// ...
/// ```
///
/// This vertical packing enables efficient SIMD operations where a single instruction
/// processes the same element position across multiple arrays simultaneously.
#[inline]
fn pack_array<const N: usize>(data: &[[F; N]]) -> [PackedF; N] {
    array::from_fn(|i| PackedF::from_fn(|j| data[j][i]))
}

/// Unpacks SIMD vertical layout back into scalar arrays.
///
/// Transposes from vertical layout `[PackedF; N]` to horizontal layout `[[F; N]; WIDTH]`.
///
/// This is the inverse operation of `pack_array`. The output buffer must be preallocated
/// with size `[WIDTH][N]` where `WIDTH = PackedF::WIDTH`.
///
/// Input layout (vertical): each PackedF holds one element from each array
/// ```text
/// packed_data[0] = PackedF([a0, b0, c0, ...])
/// packed_data[1] = PackedF([a1, b1, c1, ...])
/// packed_data[2] = PackedF([a2, b2, c2, ...])
/// ...
/// ```
///
/// Output layout (horizontal): each row is one complete array
/// ```text
/// output[0] = [a0, a1, a2, ..., aN]
/// output[1] = [b0, b1, b2, ..., bN]
/// output[2] = [c0, c1, c2, ..., cN]
/// ...
/// ```
#[inline]
fn unpack_array<const N: usize>(packed_data: &[PackedF; N], output: &mut [[F; N]]) {
    for (i, data) in packed_data.iter().enumerate().take(N) {
        let unpacked_v = data.as_slice();
        for j in 0..PackedF::WIDTH {
            output[j][i] = unpacked_v[j];
        }
    }
}

/// Enum to implement tweaks.
pub enum PoseidonTweak {
    TreeTweak {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak {
        epoch: u32,
        chain_index: u8,
        pos_in_chain: u8,
    },
}

impl PoseidonTweak {
    fn to_field_elements<const TWEAK_LEN: usize>(&self) -> [F; TWEAK_LEN] {
        // We first represent the entire tweak as one big integer
        let mut acc = match self {
            Self::TreeTweak {
                level,
                pos_in_level,
            } => {
                ((*level as u128) << 40)
                    | ((*pos_in_level as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_TREE_HASH as u128)
            }
            Self::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                ((*epoch as u128) << 24)
                    | ((*chain_index as u128) << 16)
                    | ((*pos_in_chain as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_CHAIN_HASH as u128)
            }
        };

        // Now we interpret this integer in base-p to get field elements
        std::array::from_fn(|_| {
            let digit = (acc % F::ORDER_U64 as u128) as u64;
            acc /= F::ORDER_U64 as u128;
            F::from_u64(digit)
        })
    }
}

/// Poseidon Compression Function
///
/// Computes:
///     PoseidonCompress(x) = Truncate(PoseidonPermute(x) + x)
///
/// This function works generically over `A: Algebra<F>`, allowing it to process both:
/// - Scalar fields,
/// - Packed SIMD fields
///
/// This follows the Plonky3 pattern that enables automatic SIMD optimization.
///
/// - `WIDTH`: total state width (input length to permutation).
/// - `OUT_LEN`: number of output elements to return.
/// - `perm`: a Poseidon permutation over `[A; WIDTH]`.
/// - `input`: slice of input values, must be `≤ WIDTH` and `≥ OUT_LEN`.
///
/// ### Warning: Input Padding
/// The `input` slice is **always silently padded with zeros** to match the permutation's `WIDTH`.
/// This means that inputs that are distinct but become identical after zero-padding
/// (e.g., `[A, B]` and `[A, B, 0]`) will produce the same hash. If your use case
/// requires distinguishing between such inputs, you must handle it externally, for example,
/// by encoding the input's length as part of the message.
///
/// Returns: the first `OUT_LEN` elements of the permuted and compressed state.
///
/// Panics:
/// - If `input.len() < OUT_LEN`
/// - If `OUT_LEN > WIDTH`
pub fn poseidon_compress<A, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    input: &[A],
) -> [A; OUT_LEN]
where
    A: Algebra<F> + Copy,
    P: Permutation<[A; WIDTH]>,
{
    assert!(
        input.len() >= OUT_LEN,
        "Poseidon Compression: Input length must be at least output length."
    );

    // Copy the input into a fixed-width buffer, zero-padding unused elements if any.
    let mut padded_input = [A::ZERO; WIDTH];
    padded_input[..input.len()].copy_from_slice(input);

    // Start with the input as the initial state.
    let mut state = padded_input;

    // Apply the Poseidon permutation in-place.
    perm.permute_mut(&mut state);

    // Feed-forward: Add the input back into the state element-wise.
    for i in 0..WIDTH {
        state[i] += padded_input[i];
    }

    // Truncate and return the first `OUT_LEN` elements of the state.
    state[..OUT_LEN]
        .try_into()
        .expect("OUT_LEN is larger than permutation width")
}

/// Computes a Poseidon-based domain separator by compressing an array of `u32`
/// values using a fixed Poseidon instance.
///
/// This function works generically over `A: Algebra<F>`, allowing it to process both:
/// - Scalar fields,
/// - Packed SIMD fields
///
/// ### Usage constraints
/// - This function is private because it's tailored to a very specific case:
///   the Poseidon2 instance with arity 24 and a fixed 4-word input.
/// - As this function operates on constants, its output can be **precomputed**
///   for significant performance gains, especially within a circuit.
/// - If generalization is ever needed, a more generic and slower version should be used.
fn poseidon_safe_domain_separator<A, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    params: &[u32; DOMAIN_PARAMETERS_LENGTH],
) -> [A; OUT_LEN]
where
    A: Algebra<F> + Copy,
    P: Permutation<[A; WIDTH]>,
{
    // Combine params into a single number in base 2^32
    //
    // WARNING: We can use a u128 instead of a BigUint only because `params`
    // has 4 elements in base 2^32.
    let mut acc: u128 = 0;
    for &param in params {
        acc = (acc << 32) | (param as u128);
    }

    // Compute base-p decomposition
    //
    // We can use 24 as hardcoded because the only time we use this function
    // is for the corresponding Poseidon instance.
    let input = std::array::from_fn::<_, 24, _>(|_| {
        let digit = (acc % F::ORDER_U64 as u128) as u64;
        acc /= F::ORDER_U64 as u128;
        A::from(F::from_u64(digit))
    });

    poseidon_compress::<A, _, WIDTH, OUT_LEN>(perm, &input)
}

/// Poseidon Sponge Hash Function
///
/// Absorbs an arbitrary-length input using the Poseidon sponge construction
/// and outputs `OUT_LEN` field elements. Domain separation is achieved by
/// injecting a `capacity_value` into the state.
///
/// This function works generically over `A: Algebra<F>`, allowing it to process both:
/// - Scalar fields,
/// - Packed SIMD fields
///
/// ### Parameters
/// - `WIDTH`: sponge state width.
/// - `OUT_LEN`: number of output elements.
/// - `perm`: Poseidon permutation over `[A; WIDTH]`.
/// - `capacity_value`: values to occupy the capacity part of the state (must be < `WIDTH`).
/// - `input`: message to hash (any length).
///
/// ### Sponge Construction
/// This follows the classic sponge structure:
/// - **Absorption**: inputs are added chunk-by-chunk into the first `rate` elements of the state.
/// - **Squeezing**: outputs are read from the first `rate` elements of the state, permuted as needed.
///
/// ### Panics
/// - If `capacity_value.len() >= WIDTH`
fn poseidon_sponge<A, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    capacity_value: &[A],
    input: &[A],
) -> [A; OUT_LEN]
where
    A: Algebra<F> + Copy,
    P: Permutation<[A; WIDTH]>,
{
    // The capacity length must be strictly smaller than the width to have a non-zero rate.
    // This check prevents a panic from subtraction underflow when calculating the rate.
    assert!(
        capacity_value.len() < WIDTH,
        "Capacity length must be smaller than the state width."
    );
    let rate = WIDTH - capacity_value.len();

    let extra_elements = (rate - (input.len() % rate)) % rate;
    let mut input_vector = input.to_vec();
    // We pad the input with zeros to make its length a multiple of the rate.
    //
    // This is safe because the input's original length is effectively encoded
    // in the `capacity_value`, which serves as a domain separator.
    input_vector.resize(input.len() + extra_elements, A::ZERO);

    // initialize
    let mut state = [A::ZERO; WIDTH];
    state[rate..].copy_from_slice(capacity_value);

    // absorb
    for chunk in input_vector.chunks(rate) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        perm.permute_mut(&mut state);
    }

    // squeeze
    let mut out = vec![];
    while out.len() < OUT_LEN {
        out.extend_from_slice(&state[..rate]);
        perm.permute_mut(&mut state);
    }
    let slice = &out[0..OUT_LEN];
    slice.try_into().expect("Length mismatch")
}

/// A tweakable hash function implemented using Poseidon2
///
/// Note: HASH_LEN, TWEAK_LEN, CAPACITY, and PARAMETER_LEN must
/// be given in the unit "number of field elements".
pub struct PoseidonTweakHash<
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
    const TWEAK_LEN: usize,
    const CAPACITY: usize,
    const NUM_CHUNKS: usize,
>;

impl<
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
    const TWEAK_LEN: usize,
    const CAPACITY: usize,
    const NUM_CHUNKS: usize,
> TweakableHash for PoseidonTweakHash<PARAMETER_LEN, HASH_LEN, TWEAK_LEN, CAPACITY, NUM_CHUNKS>
where
    [F; PARAMETER_LEN]: Serialize + DeserializeOwned,
    [F; HASH_LEN]: Serialize + DeserializeOwned,
{
    type Parameter = [F; PARAMETER_LEN];

    type Tweak = PoseidonTweak;

    type Domain = [F; HASH_LEN];

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        rng.random()
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        rng.random()
    }

    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak {
        PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak {
        PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        }
    }

    fn apply(
        parameter: &Self::Parameter,
        tweak: &Self::Tweak,
        message: &[Self::Domain],
    ) -> Self::Domain {
        // we are in one of three cases:
        // (1) hashing within chains. We use compression mode.
        // (2) hashing two siblings in the tree. We use compression mode.
        // (3) hashing a long vector of chain ends. We use sponge mode.

        let tweak_fe = tweak.to_field_elements::<TWEAK_LEN>();

        match message {
            [single] => {
                // we compress parameter, tweak, message
                let perm = poseidon2_16();
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(single.iter())
                    .copied()
                    .collect();
                poseidon_compress::<F, _, CHAIN_COMPRESSION_WIDTH, HASH_LEN>(&perm, &combined_input)
            }

            [left, right] => {
                // we compress parameter, tweak, message (now containing two parts)
                let perm = poseidon2_24();
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(left.iter())
                    .chain(right.iter())
                    .copied()
                    .collect();
                poseidon_compress::<F, _, MERGE_COMPRESSION_WIDTH, HASH_LEN>(&perm, &combined_input)
            }

            _ if message.len() > 2 => {
                // Hashing many blocks
                let perm = poseidon2_24();
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(message.iter().flatten())
                    .copied()
                    .collect();

                let lengths: [u32; DOMAIN_PARAMETERS_LENGTH] = [
                    PARAMETER_LEN as u32,
                    TWEAK_LEN as u32,
                    NUM_CHUNKS as u32,
                    HASH_LEN as u32,
                ];
                let capacity_value =
                    poseidon_safe_domain_separator::<F, _, MERGE_COMPRESSION_WIDTH, CAPACITY>(
                        &perm, &lengths,
                    );
                poseidon_sponge::<F, _, MERGE_COMPRESSION_WIDTH, HASH_LEN>(
                    &perm,
                    &capacity_value,
                    &combined_input,
                )
            }
            _ => [F::ONE; HASH_LEN], // Unreachable case, added for safety
        }
    }

    #[allow(clippy::too_many_lines)]
    fn compute_tree_leaves<PRF>(
        prf_key: &PRF::Key,
        parameter: &Self::Parameter,
        epochs: &[u32],
        num_chains: usize,
        chain_length: usize,
    ) -> Vec<Self::Domain>
    where
        PRF: crate::symmetric::prf::Pseudorandom,
        PRF::Domain: Into<Self::Domain>,
    {
        // Verify that num_chains matches the encoding dimension.
        assert_eq!(
            num_chains, NUM_CHUNKS,
            "Poseidon SIMD implementation requires num_chains == NUM_CHUNKS. Got num_chains={}, NUM_CHUNKS={}",
            num_chains, NUM_CHUNKS
        );

        // SIMD-ACCELERATED IMPLEMENTATION
        //
        // This path leverages architecture-specific SIMD instructions.
        // `PackedF` represents multiple field elements processed in parallel.
        //
        // The key point: process multiple epochs simultaneously using SIMD.
        // Each SIMD lane corresponds to one epoch.

        // Determine SIMD width based on architecture.
        let width = PackedF::WIDTH;

        // Allocate output buffer for all leaves.
        let mut leaves = vec![[F::ZERO; HASH_LEN]; epochs.len()];

        // PREPARE PACKED CONSTANTS

        // Broadcast the hash parameter to all SIMD lanes.
        // Each lane will use the same parameter for its epoch.
        let packed_parameter: [PackedF; PARAMETER_LEN] =
            array::from_fn(|i| PackedF::from(parameter[i]));

        // Create Poseidon permutation instances.
        // - Width-16 for chain compression,
        // - Width-24 for sponge hashing.
        let chain_perm = poseidon2_16();
        let sponge_perm = poseidon2_24();

        // Compute domain separator for the sponge construction.
        // This ensures different use cases produce different outputs.
        let lengths = [
            PARAMETER_LEN as u32,
            TWEAK_LEN as u32,
            NUM_CHUNKS as u32,
            HASH_LEN as u32,
        ];
        let capacity_val =
            poseidon_safe_domain_separator::<PackedF, _, MERGE_COMPRESSION_WIDTH, CAPACITY>(
                &sponge_perm,
                &lengths,
            );

        // PARALLEL SIMD PROCESSING
        //
        // Process epochs in batches of size `width`.
        // Each batch is handled by one thread.
        // Within each batch, SIMD processes `width` epochs simultaneously.
        epochs
            .par_chunks_exact(width)
            .zip(leaves.par_chunks_exact_mut(width))
            .for_each(|(epoch_chunk, leaves_chunk)| {
                // STEP 1: GENERATE AND PACK CHAIN STARTING POINTS
                //
                // For each chain, generate starting points for all epochs in the chunk.
                // Use vertical packing: transpose from [lane][element] to [element][lane].
                //
                // This layout enables efficient SIMD operations across epochs.

                let mut packed_chain_ends: [[PackedF; HASH_LEN]; NUM_CHUNKS] =
                    array::from_fn(|c_idx| {
                        // Generate starting points for this chain across all epochs.
                        let starts: [[F; HASH_LEN]; PackedF::WIDTH] = array::from_fn(|lane| {
                            PRF::get_domain_element(prf_key, epoch_chunk[lane], c_idx as u64).into()
                        });

                        // Transpose to vertical packing for SIMD efficiency.
                        pack_array(&starts)
                    });

                // STEP 2: WALK CHAINS IN PARALLEL USING SIMD
                //
                // For each chain, walk all epochs simultaneously using SIMD.
                //
                // Cache strategy: process one chain at a time to maximize locality.
                // All epochs for that chain stay in registers across iterations.

                for (chain_index, packed_chain_end) in
                    packed_chain_ends.iter_mut().enumerate().take(num_chains)
                {
                    // Walk this chain for `chain_length - 1` steps.
                    // The starting point is step 0, so we need `chain_length - 1` iterations.
                    for step in 0..chain_length - 1 {
                        // Current position in the chain.
                        let pos = (step + 1) as u8;

                        // Generate tweaks for all epochs in this SIMD batch.
                        // Each lane gets a tweak specific to its epoch.
                        let packed_tweak = array::from_fn::<_, TWEAK_LEN, _>(|t_idx| {
                            PackedF::from_fn(|lane| {
                                Self::chain_tweak(epoch_chunk[lane], chain_index as u8, pos)
                                    .to_field_elements::<TWEAK_LEN>()[t_idx]
                            })
                        });

                        // Assemble the packed input for the hash function.
                        // Layout: [parameter | tweak | current_value]
                        let mut packed_input_arr = [PackedF::ZERO; CHAIN_COMPRESSION_WIDTH];
                        let mut current_pos = 0;

                        // Copy parameter into the input buffer.
                        packed_input_arr[current_pos..current_pos + PARAMETER_LEN]
                            .copy_from_slice(&packed_parameter);
                        current_pos += PARAMETER_LEN;

                        // Copy tweak into the input buffer.
                        packed_input_arr[current_pos..current_pos + TWEAK_LEN]
                            .copy_from_slice(&packed_tweak);
                        current_pos += TWEAK_LEN;

                        // Copy current chain value into the input buffer.
                        packed_input_arr[current_pos..current_pos + HASH_LEN]
                            .copy_from_slice(packed_chain_end);

                        // Apply the hash function to advance the chain.
                        // This single call processes all epochs in parallel.
                        *packed_chain_end =
                            poseidon_compress::<PackedF, _, CHAIN_COMPRESSION_WIDTH, HASH_LEN>(
                                &chain_perm,
                                &packed_input_arr,
                            );
                    }
                }

                // STEP 3: HASH CHAIN ENDS TO PRODUCE TREE LEAVES
                //
                // All chains have been walked to their endpoints.
                // Now hash all chain ends together to form the tree leaf.
                //
                // This uses the sponge construction for variable-length input.

                // Generate tree tweaks for all epochs.
                // Level 0 indicates this is a bottom-layer leaf in the tree.
                let packed_tree_tweak = array::from_fn::<_, TWEAK_LEN, _>(|t_idx| {
                    PackedF::from_fn(|lane| {
                        Self::tree_tweak(0, epoch_chunk[lane]).to_field_elements::<TWEAK_LEN>()
                            [t_idx]
                    })
                });

                // Assemble the sponge input.
                // Layout: [parameter | tree_tweak | all_chain_ends]
                let packed_leaf_input: Vec<_> = packed_parameter
                    .iter()
                    .chain(packed_tree_tweak.iter())
                    .chain(packed_chain_ends.iter().flatten())
                    .copied()
                    .collect();

                // Apply the sponge hash to produce the leaf.
                // This absorbs all chain ends and squeezes out the final hash.
                let packed_leaves = poseidon_sponge::<PackedF, _, _, _>(
                    &sponge_perm,
                    &capacity_val,
                    &packed_leaf_input,
                );

                // STEP 4: UNPACK RESULTS TO SCALAR REPRESENTATION
                //
                // Convert from vertical packing back to scalar layout.
                // Each lane becomes one leaf in the output slice.

                unpack_array(&packed_leaves, leaves_chunk);
            });

        // HANDLE REMAINDER EPOCHS
        //
        // If the total number of epochs is not divisible by the SIMD width,
        // process the remaining epochs using scalar code.
        //
        // This ensures correctness for all input sizes.

        let remainder_start = (epochs.len() / width) * width;
        for (i, epoch) in epochs[remainder_start..].iter().enumerate() {
            let global_index = remainder_start + i;

            // Walk all chains for this epoch.
            let chain_ends: Vec<_> = (0..NUM_CHUNKS)
                .map(|c_idx| {
                    let start = PRF::get_domain_element(prf_key, *epoch, c_idx as u64).into();
                    chain::<Self>(parameter, *epoch, c_idx as u8, 0, chain_length - 1, &start)
                })
                .collect();

            // Hash the chain ends to produce the leaf.
            leaves[global_index] =
                Self::apply(parameter, &Self::tree_tweak(0, *epoch), &chain_ends);
        }

        leaves
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            CAPACITY < 24,
            "Poseidon Tweak Chain Hash: Capacity must be less than 24"
        );
        assert!(
            PARAMETER_LEN + TWEAK_LEN + HASH_LEN <= 16,
            "Poseidon Tweak Chain Hash: Input lengths too large for Poseidon instance"
        );
        assert!(
            PARAMETER_LEN + TWEAK_LEN + 2 * HASH_LEN <= 24,
            "Poseidon Tweak Tree Hash: Input lengths too large for Poseidon instance"
        );

        let bits_per_fe = f64::floor(f64::log2(F::ORDER_U64 as f64));
        let state_bits = bits_per_fe * f64::from(24_u32);
        assert!(
            state_bits >= f64::from((DOMAIN_PARAMETERS_LENGTH * 32) as u32),
            "Poseidon Tweak Leaf Hash: not enough field elements to hash the domain separator"
        );

        let bits_for_tree_tweak = f64::from(32 + 8_u32);
        let bits_for_chain_tweak = f64::from(32 + 8 + 8 + 8_u32);
        let tweak_fe_bits = bits_per_fe * f64::from(TWEAK_LEN as u32);
        assert!(
            tweak_fe_bits >= bits_for_tree_tweak,
            "Poseidon Tweak Hash: not enough field elements to encode the tree tweak"
        );
        assert!(
            tweak_fe_bits >= bits_for_chain_tweak,
            "Poseidon Tweak Hash: not enough field elements to encode the chain tweak"
        );
    }
}

// Example instantiations
#[cfg(test)]
pub type PoseidonTweak44 = PoseidonTweakHash<4, 4, 3, 9, 128>;
#[cfg(test)]
pub type PoseidonTweak37 = PoseidonTweakHash<3, 7, 3, 9, 128>;
#[cfg(test)]
pub type PoseidonTweakW1L5 = PoseidonTweakHash<5, 7, 2, 9, 163>;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use num_bigint::BigUint;
    use rand::Rng;

    use super::*;

    #[test]
    fn test_apply_44() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        PoseidonTweak44::internal_consistency_check();

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let message_two = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        let _ = PoseidonTweak44::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak44::chain_tweak(2, 3, 4);
        let _ = PoseidonTweak44::apply(&parameter, &tweak_chain, &[message_one]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let chains = [PoseidonTweak44::rand_domain(&mut rng); 128];
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        let _ = PoseidonTweak44::apply(&parameter, &tweak_tree, &chains);
    }

    #[test]
    fn test_apply_37() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        PoseidonTweak37::internal_consistency_check();

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let message_two = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_tree = PoseidonTweak37::tree_tweak(0, 3);
        let _ = PoseidonTweak37::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak37::chain_tweak(2, 3, 4);
        let _ = PoseidonTweak37::apply(&parameter, &tweak_chain, &[message_one]);
    }

    #[test]
    fn test_rand_parameter_not_all_same() {
        // Setup a umber of trials
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let parameter = PoseidonTweak44::rand_parameter(&mut rng);

            // Check if all elements in `parameter` are identical
            let first = parameter[0];
            if parameter.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        // If all K trials resulted in identical values, fail the test
        assert!(
            all_same_count < K,
            "rand_parameter generated identical elements in all {K} trials"
        );
    }

    #[test]
    fn test_rand_domain_not_all_same() {
        // Setup a umber of trials
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let domain = PoseidonTweak44::rand_domain(&mut rng);

            // Check if all elements in `domain` are identical
            let first = domain[0];
            if domain.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        // If all K trials resulted in identical values, fail the test
        assert!(
            all_same_count < K,
            "rand_domain generated identical elements in all {} trials",
            K
        );
    }

    #[test]
    fn test_tree_tweak_field_elements() {
        // Tweak
        let level = 1u8;
        let pos_in_level = 2u32;
        let sep = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;

        // Compute tweak_bigint
        let tweak_bigint: BigUint =
            (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        // Use the field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Extract field elements in base-p
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        // Check actual output
        let tweak = PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements() {
        // Tweak
        let epoch = 1u32;
        let chain_index = 2u8;
        let pos_in_chain = 3u8;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        // Compute tweak_bigint = (epoch << 24) + (chain_index << 16) + (pos_in_chain << 8) + sep
        let tweak_bigint: BigUint = (BigUint::from(epoch) << 24)
            + (BigUint::from(chain_index) << 16)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        // Use the field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Extract field elements in base-p
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        // Check actual output
        let tweak = PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_tree_tweak_field_elements_max_values() {
        let level = u8::MAX;
        let pos_in_level = u32::MAX;
        let sep = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;

        let tweak_bigint: BigUint =
            (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        let p = BigUint::from(F::ORDER_U64);
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        let tweak = PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements_max_values() {
        let epoch = u32::MAX;
        let chain_index = u8::MAX;
        let pos_in_chain = u8::MAX;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        let tweak_bigint: BigUint = (BigUint::from(epoch) << 24)
            + (BigUint::from(chain_index) << 16)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        let p = BigUint::from(F::ORDER_U64);
        let expected = [
            F::from_u128((&tweak_bigint % &p).try_into().unwrap()),
            F::from_u128(((&tweak_bigint / &p) % &p).try_into().unwrap()),
        ];

        let tweak = PoseidonTweak::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<2>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_tree_tweak_injective() {
        let mut rng = rand::rng();

        // basic test to check that tree tweak maps from
        // parameters to field elements array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let level = rng.random();
            let pos_in_level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some((prev_level, prev_pos_in_level)) =
                map.insert(tweak_encoding, (level, pos_in_level))
            {
                assert_eq!(
                    (prev_level, prev_pos_in_level),
                    (level, pos_in_level),
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    prev_level,
                    prev_pos_in_level,
                    level,
                    pos_in_level,
                    tweak_encoding
                );
            }
        }

        // inputs with common level
        let mut map = HashMap::new();
        let level = rng.random();
        for _ in 0..10_000 {
            let pos_in_level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some(prev_pos_in_level) = map.insert(tweak_encoding, pos_in_level) {
                assert_eq!(
                    prev_pos_in_level, pos_in_level,
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    level, prev_pos_in_level, level, pos_in_level, tweak_encoding
                );
            }
        }

        // inputs with common pos_in_level
        let mut map = HashMap::new();
        let pos_in_level = rng.random();
        for _ in 0..10_000 {
            let level = rng.random();
            let tweak_encoding = PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_field_elements::<2>();

            if let Some(prev_level) = map.insert(tweak_encoding, level) {
                assert_eq!(
                    prev_level, level,
                    "Collision detected for ({},{}) and ({},{}) with output {:?}",
                    prev_level, pos_in_level, level, pos_in_level, tweak_encoding
                );
            }
        }
    }

    #[test]
    fn test_chain_tweak_injective() {
        let mut rng = rand::rng();

        // basic test to check that chain tweak maps from
        // parameters to field element array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let epoch = rng.random();
            let chain_index = rng.random();
            let pos_in_chain = rng.random();

            let input = (epoch, chain_index, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed epoch
        let mut map = HashMap::new();
        let epoch = rng.random();
        for _ in 0..10_000 {
            let chain_index = rng.random();
            let pos_in_chain = rng.random();

            let input = (chain_index, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed chain_index
        let mut map = HashMap::new();
        let chain_index = rng.random();
        for _ in 0..10_000 {
            let epoch = rng.random();
            let pos_in_chain = rng.random();

            let input = (epoch, pos_in_chain);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }

        // inputs with fixed pos_in_chain
        let mut map = HashMap::new();
        let pos_in_chain = rng.random();
        for _ in 0..10_000 {
            let epoch = rng.random();
            let chain_index = rng.random();

            let input = (epoch, chain_index);

            let tweak_encoding = PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_field_elements::<2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }
    }
}
