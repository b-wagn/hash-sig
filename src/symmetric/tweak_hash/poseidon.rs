use p3_baby_bear::BabyBear;
use p3_baby_bear::default_babybear_poseidon2_16;
use p3_baby_bear::default_babybear_poseidon2_24;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;
use p3_symmetric::Permutation;
use serde::{Serialize, de::DeserializeOwned};

use crate::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use crate::TWEAK_SEPARATOR_FOR_TREE_HASH;

use super::TweakableHash;

type F = BabyBear;

const DOMAIN_PARAMETERS_LENGTH: usize = 4;
/// The state width for compressing a single hash in a chain.
const CHAIN_COMPRESSION_WIDTH: usize = 16;
/// The state width for merging two hashes in a tree or for the sponge construction.
const MERGE_COMPRESSION_WIDTH: usize = 24;

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
    fn to_field_elements<F, const TWEAK_LEN: usize>(&self) -> [F; TWEAK_LEN]
    where
        F: PrimeField64,
    {
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
            let digit = acc % F::ORDER_U64 as u128;
            acc /= F::ORDER_U64 as u128;
            F::from_u128(digit)
        })
    }
}

/// Poseidon Compression Function.
///
/// Computes:
///     PoseidonCompress(x) = Truncate(PoseidonPermute(x) + x)
///
/// This function takes an input slice `x`, applies the Poseidon permutation,
/// adds the original input back (as a feed-forward), and returns the first `OUT_LEN` elements.
///
/// - `WIDTH`: total state width (input length to permutation).
/// - `OUT_LEN`: number of output elements to return.
/// - `perm`: a Poseidon permutation over `[F; WIDTH]`.
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
#[must_use]
pub(crate) fn poseidon_compress<F, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    input: &[F],
) -> [F; OUT_LEN]
where
    F: PrimeField64,
    P: Permutation<[F; WIDTH]>,
{
    assert!(
        input.len() >= OUT_LEN,
        "Poseidon Compression: Input length must be at least output length."
    );

    // Copy the input into a fixed-width buffer, zero-padding unused elements if any.
    let mut padded_input = [F::ZERO; WIDTH];
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
/// ### Usage constraints
/// - This function is private because it's tailored to a very specific case:
///   the Poseidon2 instance with arity 24 and a fixed 4-word input.
/// - As this function operates on constants, its output can be **precomputed**
///   for significant performance gains, especially within a circuit.
/// - If generalization is ever needed, a more generic and slower version should be used.
fn poseidon_safe_domain_separator<F, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    params: &[u32; DOMAIN_PARAMETERS_LENGTH],
) -> [F; OUT_LEN]
where
    F: PrimeField64,
    P: Permutation<[F; WIDTH]>,
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
        let digit = acc % F::ORDER_U64 as u128;
        acc /= F::ORDER_U64 as u128;
        F::from_u128(digit)
    });

    poseidon_compress::<_, _, WIDTH, OUT_LEN>(perm, &input)
}

/// Poseidon Sponge Hash Function.
///
/// Absorbs an arbitrary-length input using the Poseidon sponge construction
/// and outputs `OUT_LEN` field elements. Domain separation is achieved by
/// injecting a `capacity_value` into the state.
///
/// - `WIDTH`: sponge state width.
/// - `OUT_LEN`: number of output elements.
/// - `perm`: Poseidon permutation over `[F; WIDTH]`.
/// - `capacity_value`: values to occupy the capacity part of the state (must be ≤ `WIDTH`).
/// - `input`: message to hash (any length).
///
/// This follows the classic sponge structure:
/// - Absorption: inputs are added chunk-by-chunk into the first `rate` elements of the state.
/// - Squeezing: outputs are read from the first `rate` elements of the state, permuted as needed.
///
/// Panics:
/// - If `capacity_value.len() >= WIDTH`
fn poseidon_sponge<F, P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    capacity_value: &[F],
    input: &[F],
) -> [F; OUT_LEN]
where
    F: PrimeField64,
    P: Permutation<[F; WIDTH]>,
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
    input_vector.resize(input.len() + extra_elements, F::ZERO);

    // initialize
    let mut state = [F::ZERO; WIDTH];
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

        let tweak_fe = tweak.to_field_elements::<F, TWEAK_LEN>();

        match message {
            [single] => {
                // we compress parameter, tweak, message
                let perm = default_babybear_poseidon2_16();
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
                let perm = default_babybear_poseidon2_24();
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
                let perm = default_babybear_poseidon2_24();
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
pub type PoseidonTweak44 = PoseidonTweakHash<4, 4, 3, 9, 128>;
pub type PoseidonTweak37 = PoseidonTweakHash<3, 7, 3, 9, 128>;
pub type PoseidonTweakW1L18 = PoseidonTweakHash<5, 7, 2, 9, 163>;
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
        PoseidonTweak44::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let message_one = PoseidonTweak44::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak44::chain_tweak(2, 3, 4);
        PoseidonTweak44::apply(&parameter, &tweak_chain, &[message_one]);

        // test that nothing is panicking
        let parameter = PoseidonTweak44::rand_parameter(&mut rng);
        let chains = [PoseidonTweak44::rand_domain(&mut rng); 128];
        let tweak_tree = PoseidonTweak44::tree_tweak(0, 3);
        PoseidonTweak44::apply(&parameter, &tweak_tree, &chains);
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
        PoseidonTweak37::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = PoseidonTweak37::rand_parameter(&mut rng);
        let message_one = PoseidonTweak37::rand_domain(&mut rng);
        let tweak_chain = PoseidonTweak37::chain_tweak(2, 3, 4);
        PoseidonTweak37::apply(&parameter, &tweak_chain, &[message_one]);
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
        let computed = tweak.to_field_elements::<F, 2>();
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
        let computed = tweak.to_field_elements::<F, 2>();
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
        let computed = tweak.to_field_elements::<F, 2>();
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
        let computed = tweak.to_field_elements::<F, 2>();
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
            .to_field_elements::<F, 2>();

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
            .to_field_elements::<F, 2>();

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
            .to_field_elements::<F, 2>();

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
            .to_field_elements::<F, 2>();

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
            .to_field_elements::<F, 2>();

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
            .to_field_elements::<F, 2>();

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
            .to_field_elements::<F, 2>();

            if let Some(prev_input) = map.insert(tweak_encoding, input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }
    }
}
