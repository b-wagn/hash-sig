use zkhash::ark_ff::MontConfig;
use zkhash::ark_ff::One;
use zkhash::ark_ff::UniformRand;
use zkhash::ark_ff::Zero;
use zkhash::poseidon2::poseidon2_instance_babybear::{
    POSEIDON2_BABYBEAR_16_PARAMS, POSEIDON2_BABYBEAR_24_PARAMS,
};
use zkhash::{
    fields::babybear::{FpBabyBear, FqConfig},
    poseidon2::poseidon2::Poseidon2,
};

use crate::TWEAK_SEPARATOR_FOR_CHAIN_HASH;
use crate::TWEAK_SEPARATOR_FOR_TREE_HASH;

use super::TweakableHash;

type F = FpBabyBear;

/// Modulus of the field as u128
///
// Note: It's fine to take only the first limb as we are using prime fields with <= 64 bits
const MODULUS_128: u128 = FqConfig::MODULUS.0[0] as u128;

const DOMAIN_PARAMETERS_LENGTH: usize = 4;

/// Enum to implement tweaks.
pub enum PoseidonTweak<
    const LOG_LIFETIME: usize,
    const CEIL_LOG_NUM_CHAINS: usize,
    const CHUNK_SIZE: usize,
> {
    TreeTweak {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak {
        epoch: u32,
        chain_index: u16,
        pos_in_chain: u16,
    },
    _Marker(std::marker::PhantomData<F>),
}

impl<const LOG_LIFETIME: usize, const CEIL_LOG_NUM_CHAINS: usize, const CHUNK_SIZE: usize>
    PoseidonTweak<LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE>
{
    fn to_field_elements<const TWEAK_LEN: usize>(&self) -> [F; TWEAK_LEN] {
        // we need to convert from integers to field elements,
        // Note: taking into account the constants
        // LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE,
        // we know that the tweak can be represented using at most
        // LOG_LIFETIME + CEIL_LOG_NUM_CHAINS + CHUNK_SIZE many
        // bits.

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
                ((*epoch as u128) << 40)
                    | ((*chain_index as u128) << 24)
                    | ((*pos_in_chain as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_CHAIN_HASH as u128)
            }
            _ => 0,
        };

        // Get the modulus
        let p = MODULUS_128;

        // Now we interpret this integer in base-p to get field elements
        std::array::from_fn(|_| {
            let digit = acc % p;
            acc /= p;
            F::from(digit)
        })
    }
}

/// Function to first pad input to appropriate length and
/// then apply the Poseidon permutation.
fn poseidon_padded_permute(instance: &Poseidon2<F>, input: &[F]) -> Vec<F> {
    assert!(
        input.len() <= instance.get_t(),
        "Poseidon Compression: Input length too large for Poseidon parameters."
    );

    // pad input with zeroes to have exactly length instance.get_t()
    let mut padded_input = input.to_vec();
    padded_input.resize_with(instance.get_t(), F::zero);

    // apply permutation and return
    instance.permutation(&padded_input)
}

/// Poseidon Compression Function, using the Poseidon Permutation.
/// It works as PoseidonCompress(x) = Truncate(PoseidonPermute(x) + x)
pub fn poseidon_compress<const OUT_LEN: usize>(
    instance: &Poseidon2<F>,
    input: &[F],
) -> [F; OUT_LEN] {
    assert!(
        input.len() >= OUT_LEN,
        "Poseidon Compression: Input length must be at least output length."
    );

    // first permute input
    let permuted_input = poseidon_padded_permute(instance, input);
    // now, add them, but only for the positions we actually output.
    std::array::from_fn(|i| permuted_input[i] + input[i])
}

/// Computes a Poseidon-based domain separator by compressing an array of `usize`
/// values (interpreted as 32-bit words) using a fixed Poseidon instance.
///
/// ### Usage constraints
/// - This function is private because it's tailored to one very specific case:
///   the Poseidon2 instance with arity 24 and a fixed 4-word input.
/// - If generalization is ever needed, a more generic and slower version should be used.
fn poseidon_safe_domain_separator<const OUT_LEN: usize>(
    instance: &Poseidon2<F>,
    params: &[u32; DOMAIN_PARAMETERS_LENGTH],
) -> [F; OUT_LEN] {
    // Combine params into a single number in base 2^32
    //
    // WARNING: We can use a u128 instead of a BigUint only because `params`
    // has 4 elements in base 2^32.
    let mut acc: u128 = 0;
    for &param in params {
        acc = (acc << 32) | (param as u128);
    }

    // Get the modulus
    let p = MODULUS_128;

    // Compute base-p decomposition
    //
    // We can use 24 as hardcoded because the only time we use this function
    // is for the corresponding Poseidon instance.
    let input = std::array::from_fn::<_, 24, _>(|_| {
        let digit = acc % p;
        acc /= p;
        F::from(digit)
    });

    // Compress the input using Poseidon
    poseidon_compress(instance, &input)
}

/// Poseidon Sponge hash
/// Takes an input of arbitrary length
/// Capacity must hold an appropriate domain separator, e.g., hash of the lengths
pub fn poseidon_sponge<const OUT_LEN: usize>(
    instance: &Poseidon2<F>,
    capacity_value: &[F],
    input: &[F],
) -> [F; OUT_LEN] {
    // capacity must be shorter than the width
    assert!(
        capacity_value.len() < instance.get_t(),
        "Poseidon Sponge: Capacity must be smaller than the state size."
    );

    let rate = instance.get_t() - capacity_value.len();

    let extra_elements = (rate - (input.len() % rate)) % rate;
    let mut input_vector = input.to_vec();

    // padding with 0s
    input_vector.resize_with(input.len() + extra_elements, F::zero);

    // sponge mode has three phases: initialize, absorb, squeeze

    // initialize
    let mut state = vec![F::zero(); rate];
    state.extend_from_slice(capacity_value);

    // absorb
    for chunk in input_vector.chunks(rate) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        state = instance.permutation(&state);
    }

    // squeeze
    let mut out = vec![];
    while out.len() < OUT_LEN {
        out.extend_from_slice(&state[..rate]);
        state = instance.permutation(&state);
    }
    let slice = &out[0..OUT_LEN];
    slice.try_into().expect("Length mismatch")
}

/// A tweakable hash function implemented using Poseidon2
///
/// Note: HASH_LEN, TWEAK_LEN, CAPACITY, and PARAMETER_LEN must
/// be given in the unit "number of field elements".
pub struct PoseidonTweakHash<
    const LOG_LIFETIME: usize,
    const CEIL_LOG_NUM_CHAINS: usize,
    const CHUNK_SIZE: usize,
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
    const TWEAK_LEN: usize,
    const CAPACITY: usize,
    const NUM_CHUNKS: usize,
>;

impl<
        const LOG_LIFETIME: usize,
        const CEIL_LOG_NUM_CHAINS: usize,
        const CHUNK_SIZE: usize,
        const PARAMETER_LEN: usize,
        const HASH_LEN: usize,
        const TWEAK_LEN: usize,
        const CAPACITY: usize,
        const NUM_CHUNKS: usize,
    > TweakableHash
    for PoseidonTweakHash<
        LOG_LIFETIME,
        CEIL_LOG_NUM_CHAINS,
        CHUNK_SIZE,
        PARAMETER_LEN,
        HASH_LEN,
        TWEAK_LEN,
        CAPACITY,
        NUM_CHUNKS,
    >
{
    type Parameter = [F; PARAMETER_LEN];

    type Tweak = PoseidonTweak<LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE>;

    type Domain = [F; HASH_LEN];

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        std::array::from_fn(|_| F::rand(rng))
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        std::array::from_fn(|_| F::rand(rng))
    }

    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak {
        PoseidonTweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u32, chain_index: u16, pos_in_chain: u16) -> Self::Tweak {
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

        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);
        let instance_short = Poseidon2::new(&POSEIDON2_BABYBEAR_16_PARAMS);
        let tweak_fe = PoseidonTweak::to_field_elements::<TWEAK_LEN>(tweak);

        match message {
            [single] => {
                // we compress parameter, tweak, message
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(single.iter())
                    .copied()
                    .collect();
                poseidon_compress(&instance_short, &combined_input)
            }
            [left, right] => {
                // we compress parameter, tweak, message (now containing two parts)
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(left.iter())
                    .chain(right.iter())
                    .copied()
                    .collect();
                poseidon_compress(&instance, &combined_input)
            }
            _ if message.len() > 2 => {
                let combined_input: Vec<F> = parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(message.iter().flatten())
                    .copied()
                    .collect();
                let lengths: [_; DOMAIN_PARAMETERS_LENGTH] = [
                    PARAMETER_LEN as u32,
                    TWEAK_LEN as u32,
                    NUM_CHUNKS as u32,
                    HASH_LEN as u32,
                ];
                let safe_input = poseidon_safe_domain_separator::<CAPACITY>(&instance, &lengths);
                poseidon_sponge(&instance, &safe_input, &combined_input)
            }
            _ => [F::one(); HASH_LEN], // Unreachable case, added for safety
        }
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        use num_bigint::BigUint;

        assert!(
            BigUint::from(FqConfig::MODULUS) < BigUint::from(u64::MAX),
            "The prime field used is too large"
        );
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
        let state_bits = f64::log2(
            BigUint::from(FqConfig::MODULUS)
                .to_string()
                .parse()
                .unwrap(),
        ) * f64::from(24_u32);
        assert!(
            state_bits >= f64::from((DOMAIN_PARAMETERS_LENGTH * 32) as u32),
            "Poseidon Tweak Leaf Hash: not enough field elements to hash the domain separator"
        );
    }
}

// Example instantiations
pub type PoseidonTweak44 = PoseidonTweakHash<20, 8, 2, 4, 4, 3, 9, 128>;
pub type PoseidonTweak37 = PoseidonTweakHash<20, 8, 2, 3, 7, 3, 9, 128>;
pub type PoseidonTweakW1L18 = PoseidonTweakHash<18, 8, 1, 5, 7, 2, 9, 163>;
pub type PoseidonTweakW1L5 = PoseidonTweakHash<5, 8, 1, 5, 7, 2, 9, 163>;

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_apply_44() {
        let mut rng = thread_rng();

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
        let mut rng = thread_rng();

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
        let mut rng = thread_rng();
        // Setup a umber of trials
        const K: usize = 10;
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
            "rand_parameter generated identical elements in all {} trials",
            K
        );
    }

    #[test]
    fn test_rand_domain_not_all_same() {
        let mut rng = thread_rng();
        // Setup a umber of trials
        const K: usize = 10;
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
        let tweak_bigint = (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        // Use the field modulus
        let p = BigUint::from(FqConfig::MODULUS);

        // Extract field elements in base-p
        let expected = [
            F::from(&tweak_bigint % &p),
            F::from((&tweak_bigint / &p) % &p),
            F::from((&tweak_bigint / (&p * &p)) % &p),
        ];

        // Check actual output
        let tweak = PoseidonTweak::<0, 0, 0>::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<3>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements() {
        // Tweak
        let epoch = 1u32;
        let chain_index = 2u16;
        let pos_in_chain = 3u16;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        // Compute tweak_bigint = (epoch << 40) + (chain_index << 24) + (pos_in_chain << 8) + sep
        let tweak_bigint = (BigUint::from(epoch) << 40)
            + (BigUint::from(chain_index) << 24)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        // Use the field modulus
        let p = BigUint::from(FqConfig::MODULUS);

        // Extract field elements in base-p
        let expected = [
            F::from(&tweak_bigint % &p),
            F::from((&tweak_bigint / &p) % &p),
            F::from((&tweak_bigint / (&p * &p)) % &p),
        ];

        // Check actual output
        let tweak = PoseidonTweak::<0, 0, 0>::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<3>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_tree_tweak_field_elements_max_values() {
        let level = u8::MAX;
        let pos_in_level = u32::MAX;
        let sep = TWEAK_SEPARATOR_FOR_TREE_HASH as u64;

        let tweak_bigint = (BigUint::from(level) << 40) + (BigUint::from(pos_in_level) << 8) + sep;

        let p = BigUint::from(FqConfig::MODULUS);
        let expected = [
            F::from(&tweak_bigint % &p),
            F::from((&tweak_bigint / &p) % &p),
            F::from((&tweak_bigint / (&p * &p)) % &p),
        ];

        let tweak = PoseidonTweak::<0, 0, 0>::TreeTweak {
            level,
            pos_in_level,
        };
        let computed = tweak.to_field_elements::<3>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_chain_tweak_field_elements_max_values() {
        let epoch = u32::MAX;
        let chain_index = u16::MAX;
        let pos_in_chain = u16::MAX;
        let sep = TWEAK_SEPARATOR_FOR_CHAIN_HASH as u64;

        let tweak_bigint = (BigUint::from(epoch) << 40)
            + (BigUint::from(chain_index) << 24)
            + (BigUint::from(pos_in_chain) << 8)
            + sep;

        let p = BigUint::from(FqConfig::MODULUS);
        let expected = [
            F::from(&tweak_bigint % &p),
            F::from((&tweak_bigint / &p) % &p),
            F::from((&tweak_bigint / (&p * &p)) % &p),
        ];

        let tweak = PoseidonTweak::<0, 0, 0>::ChainTweak {
            epoch,
            chain_index,
            pos_in_chain,
        };
        let computed = tweak.to_field_elements::<3>();
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_poseidon_safe_domain_separator_small() {
        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);

        // Some small parameters
        let params: [u32; 4] = [1, 2, 3, 4];

        // Compute with the optimized function
        let actual = poseidon_safe_domain_separator::<4>(&instance, &params);

        // Ensure decomposed inputs match the manual base-p values
        assert_eq!(
            actual,
            [
                F::from(1518816068),
                F::from(1903366844),
                F::from(704597956),
                F::from(30279094)
            ]
        );
    }

    #[test]
    fn test_poseidon_safe_domain_separator_large() {
        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);

        // Example parameters: treat them as 32-bit words to be concatenated
        let params = [u32::MAX; 4];

        // Compute with the optimized function
        let actual = poseidon_safe_domain_separator::<4>(&instance, &params);

        // Ensure decomposed inputs match the manual base-p values
        assert_eq!(
            actual,
            [
                F::from(1938593574),
                F::from(935512994),
                F::from(910478564),
                F::from(584381639)
            ]
        );
    }
}
