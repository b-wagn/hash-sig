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

use num_bigint::BigUint;

use super::TweakableHash;

type F = FpBabyBear;

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
    fn to_field_elements<const TWEAK_LEN: usize>(&self) -> Vec<F> {
        // we need to convert from integers to field elements,
        // Note: taking into account the constants
        // LOG_LIFETIME, CEIL_LOG_NUM_CHAINS, CHUNK_SIZE,
        // we know that the tweak can be represented using at most
        // LOG_LIFETIME + CEIL_LOG_NUM_CHAINS + CHUNK_SIZE many
        // bits.

        let tweak_bigint = match self {
            PoseidonTweak::TreeTweak {
                level,
                pos_in_level,
            } => {
                (BigUint::from(*level) << 40)
                    + (BigUint::from(*pos_in_level) << 8)
                    + crate::TWEAK_SEPARATOR_FOR_TREE_HASH
            }
            PoseidonTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                (BigUint::from(*epoch) << 40)
                    + (BigUint::from(*chain_index) << 24)
                    + (BigUint::from(*pos_in_chain) << 8)
                    + crate::TWEAK_SEPARATOR_FOR_CHAIN_HASH
            }
            _ => BigUint::from(0 as u32),
        };
        let mut tweak_fe: [F; TWEAK_LEN] = [F::zero(); TWEAK_LEN];
        tweak_fe.iter_mut().fold(tweak_bigint, |acc, item| {
            let tmp = acc.clone() % BigUint::from(FqConfig::MODULUS);
            *item = F::from(tmp.clone());
            (acc - tmp) / (BigUint::from(FqConfig::MODULUS))
        }); //interpreting the number base-p
        tweak_fe.to_vec()
    }
}

/// Function to first pad input to apopropriate length and
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
    // now, add them, but only for the positions
    // we actually output.
    let mut output = [F::zero(); OUT_LEN];
    for i in 0..OUT_LEN {
        output[i] = permuted_input[i] + input[i];
    }
    output
}

///Construct a domain separator based on @params array of usize treated as u32.
///Hashes @params with a compression mode

pub fn poseidon_safe_domain_separator<const OUT_LEN: usize>(
    instance: &Poseidon2<F>,
    params: &[usize],
) -> [F; OUT_LEN] {
    let domain_uint = params.iter().fold(BigUint::ZERO, |acc, &item| {
        acc * BigUint::from(((1 as u64) << 32) as u64) + (item as u32)
    }); //collect the vector into a number

    //Creating a Poseidon input
    let mut input = vec![F::zero(); instance.get_t()];
    input.iter_mut().fold(domain_uint, |acc, item| {
        let tmp = acc.clone() % BigUint::from(FqConfig::MODULUS);
        *item = F::from(tmp.clone());
        (acc - tmp) / (BigUint::from(FqConfig::MODULUS))
    }); //interpreting the number base-p
    poseidon_compress::<OUT_LEN>(instance, &input)
}

///Poseidon Sponge hash
///Takes input of arbitrary length
///Capacity must hold an appropriate domain separator, e.g. hash of the lengths
pub fn poseidon_sponge<const OUT_LEN: usize>(
    instance: &Poseidon2<F>,
    capacity_value: &[F],
    input: &[F],
) -> [F; OUT_LEN] {
    //capacity must be shorter than the width
    assert!(
        capacity_value.len() < instance.get_t(),
        "Poseidon Sponge: Capacity must be smaller than the state size."
    );

    let rate = instance.get_t() - capacity_value.len();

    let extra_elements = (rate - (input.len() % rate)) % rate;
    let mut input_vector = input.to_vec().clone();
    input_vector.resize_with(extra_elements, F::zero); //padding with 0s

    //Initialize
    let mut state = vec![F::zero(); rate];
    state.extend_from_slice(capacity_value);
    //Absorb
    for chunk in input_vector.chunks(rate) {
        for i in 0..chunk.len() {
            state[i] = state[i] + chunk[i];
            instance.permutation(&state);
        }
    }
    //Squeeze
    let mut out = vec![];
    while out.len() < OUT_LEN {
        out.extend_from_slice(&state[..rate]);
        instance.permutation(&state);
    }
    let slice = &out[0..OUT_LEN];
    slice.try_into().expect("Length mismatch")
}

/// A tweakable hash function implemented using Poseidon2
///
/// Note: HASH_LEN,TWEAK_LEN, CAPACITY, and PARAMETER_LEN must be given in
/// the unit "number of field elements".
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
        let mut par = [F::one(); PARAMETER_LEN];
        for i in 0..PARAMETER_LEN {
            par[i] = F::rand(rng);
        }
        par
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        let mut dom = [F::one(); HASH_LEN];
        for i in 0..HASH_LEN {
            dom[i] = F::rand(rng);
        }
        dom
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

    fn consistency_check() -> bool {
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
        ) * f64::from(24 as u32);
        assert!(
            state_bits >= f64::from((crate::DOMAIN_PARAMETERS_LENGTH * 32) as u32),
            "Parameter mismatch: not enough field elements to hash the domain separator"
        );
        true
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

        let l = message.len();
        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);
        let instance_short = Poseidon2::new(&POSEIDON2_BABYBEAR_16_PARAMS);
        if l == 1 {
            // we compress parameter, tweak, message
            let message_unpacked = message[0];
            let tweak_fe = PoseidonTweak::to_field_elements::<TWEAK_LEN>(tweak);
            let combined_input: Vec<F> = parameter
                .iter()
                .chain(tweak_fe.iter())
                .chain(message_unpacked.iter())
                .cloned()
                .collect();
            return poseidon_compress::<HASH_LEN>(&instance_short, &combined_input);
        }
        if l == 2 {
            // we compress parameter, tweak, message (now containing two parts)
            let message_unpacked_left = message[0];
            let message_unpacked_right = message[1];
            let tweak_fe = PoseidonTweak::to_field_elements::<TWEAK_LEN>(tweak);
            let combined_input: Vec<F> = parameter
                .iter()
                .chain(tweak_fe.iter())
                .chain(message_unpacked_left.iter())
                .chain(message_unpacked_right.iter())
                .cloned()
                .collect();
            return poseidon_compress::<HASH_LEN>(&instance, &combined_input);
        }
        if l > 2 {
            let tweak_fe = PoseidonTweak::to_field_elements::<TWEAK_LEN>(tweak);
            let combined_input: Vec<F> = parameter
                .iter()
                .chain(tweak_fe.iter())
                .chain(message.iter().flat_map(|sub_arr| sub_arr.iter()))
                .cloned()
                .collect();
            let lengths: [usize; crate::DOMAIN_PARAMETERS_LENGTH] =
                [PARAMETER_LEN, TWEAK_LEN, NUM_CHUNKS, HASH_LEN];
            let safe_input = poseidon_safe_domain_separator::<CAPACITY>(&instance, &lengths);
            let capacity_value = poseidon_compress::<CAPACITY>(&instance, &safe_input);
            let res = poseidon_sponge(&instance, &capacity_value, &combined_input);
            return res;
        }
        // will never be reached
        [F::one(); HASH_LEN]
    }
}

// Example instantiations
pub type PoseidonTweak44 = PoseidonTweakHash<20, 8, 2, 4, 4, 3, 9, 128>;
pub type PoseidonTweak37 = PoseidonTweakHash<20, 8, 2, 3, 7, 3, 9, 128>;

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_apply_44() {
        let mut rng = thread_rng();

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
}
