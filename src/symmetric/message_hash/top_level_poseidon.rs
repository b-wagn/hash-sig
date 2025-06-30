use num_bigint::BigUint;
use num_traits::Zero;
use zkhash::ark_ff::MontConfig;
use zkhash::ark_ff::PrimeField;
use zkhash::ark_ff::UniformRand;
use zkhash::fields::babybear::FpBabyBear;
use zkhash::fields::babybear::FqConfig;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_babybear::POSEIDON2_BABYBEAR_24_PARAMS;

use super::MessageHash;
use crate::hypercube::hypercube_find_layer;
use crate::hypercube::hypercube_part_size;
use crate::hypercube::map_to_vertex;
use crate::symmetric::message_hash::poseidon::encode_epoch;
use crate::symmetric::message_hash::poseidon::encode_message;
use crate::symmetric::tweak_hash::poseidon::poseidon_compress;
use crate::MESSAGE_LENGTH;

type F = FpBabyBear;

/// Function to make a list of field elements to a vertex in layers 0, ..., FINAL_LAYER
/// of the hypercube {0,...,BASE-1}^DIMENSION.
///
/// BASE and DIMENSION up to 2^8 (inclusive) are supported
fn map_into_hypercube_part<
    const DIMENSION: usize,
    const BASE: usize,
    const FINAL_LAYER: usize,
    const INPUT_LEN: usize,
>(
    field_elements: &[F; INPUT_LEN],
) -> Vec<u8> {
    // Combine field elements into one big integer
    let p = BigUint::from(FqConfig::MODULUS);
    let mut acc = BigUint::ZERO;
    for fe in field_elements.iter() {
        acc = &acc * &p + BigUint::from(fe.into_bigint());
    }

    // Take this big integer modulo the total output domain size
    let dom_size = hypercube_part_size(BASE, DIMENSION, FINAL_LAYER);
    acc %= dom_size;

    // Figure out in which layer we are, and index of the vertex in the layer
    let (layer, offset) = hypercube_find_layer(BASE, DIMENSION, acc);

    // Map this to a vertex in layers 0, ..., FINAL_LAYER
    // Note: if we move this part to the encoding instead of message hash
    // then we do not need to call map_to_vertex if the layer is not right
    map_to_vertex(BASE, DIMENSION, layer, offset)
}

/// A message hash implemented using Poseidon2, mapping into the top layers.
/// That is, we look at the hypercube {0,...,BASE-1}^DIMENSION and partition
/// it into layers:
///      layer 0 is {(BASE-1,...,BASE-1)}
///      layer (BASE-1)*DIMENSION is {(0,...,0)}
///      layer T contains all (x_1,...,x_DIMENSION)
///             with (BASE-1)*DIMENSION - sum_i x_i = T
/// Then, this message hash maps into layers 0 to FINAL_LAYER (inclusive)
///
/// Note: PARAMETER_LEN, RAND_LEN, TWEAK_LEN_FE, MSG_LEN_FE, and HASH_LEN_FE
/// must be given in the unit "number of field elements".
///
/// POS_OUTPUT_LEN_FE specifies how many field elements we get from Poseidon2,
/// before we then take these field elements and decode them
/// into an element of the top layers. This must be a multiple of 8.
///
/// BASE must be at most 2^8
pub struct TopLevelPoseidonMessageHash<
    const POS_OUTPUT_LEN_FE: usize,
    const DIMENSION: usize,
    const BASE: usize,
    const FINAL_LAYER: usize,
    const TWEAK_LEN_FE: usize,
    const MSG_LEN_FE: usize,
    const PARAMETER_LEN: usize,
    const RAND_LEN: usize,
>;

impl<
        const POS_OUTPUT_LEN_FE: usize,
        const DIMENSION: usize,
        const BASE: usize,
        const FINAL_LAYER: usize,
        const TWEAK_LEN_FE: usize,
        const MSG_LEN_FE: usize,
        const PARAMETER_LEN: usize,
        const RAND_LEN: usize,
    > MessageHash
    for TopLevelPoseidonMessageHash<
        POS_OUTPUT_LEN_FE,
        DIMENSION,
        BASE,
        FINAL_LAYER,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
        PARAMETER_LEN,
        RAND_LEN,
    >
{
    type Parameter = [F; PARAMETER_LEN];

    type Randomness = [F; RAND_LEN];

    const DIMENSION: usize = DIMENSION;

    const BASE: usize = BASE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        std::array::from_fn(|_| F::rand(rng))
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8> {
        // we need a Poseidon instance
        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);

        // first, encode the message and the epoch as field elements
        let message_fe = encode_message::<MSG_LEN_FE>(message);
        let epoch_fe = encode_epoch::<TWEAK_LEN_FE>(epoch);

        // now, invoke Poseidon a few times, to get field elements
        let iterations = POS_OUTPUT_LEN_FE / 8;
        let mut pos_outputs = [F::zero(); POS_OUTPUT_LEN_FE];
        for i in 0..iterations {
            // iteration domain separator
            let iteration_index = [F::from(i as u8)];

            // assemble input for this iteration
            let combined_input: Vec<F> = randomness
                .iter()
                .chain(parameter.iter())
                .chain(epoch_fe.iter())
                .chain(message_fe.iter())
                .chain(iteration_index.iter())
                .copied()
                .collect();

            let iteration_pos_output: [F; 8] = poseidon_compress(&instance, &combined_input);
            pos_outputs[i * 8..(i + 1) * 8].copy_from_slice(&iteration_pos_output);
        }

        // turn the field elements into an element in the part
        // of the hypercube that we care about.
        map_into_hypercube_part::<DIMENSION, BASE, FINAL_LAYER, POS_OUTPUT_LEN_FE>(&pos_outputs)
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // POS_OUTPUT_LEN_FE must be a multiple of 8
        assert!(
            POS_OUTPUT_LEN_FE % 8 == 0,
            "Top Level Poseidon Message Hash: POS_OUTPUT_LEN_FE must be a multiple of 8"
        );

        // Number of iterations we require should fit in a field element
        // For simplicity we require at most 2^8 iterations
        assert!(
            (POS_OUTPUT_LEN_FE / 8) < 1 << 8,
            "Top Level Poseidon Message Hash: POS_OUTPUT_LEN_FE / 8 must be less then 2^8 "
        );

        // FINAL_LAYER must be a valid layer
        assert!(
            FINAL_LAYER <= (BASE - 1) * DIMENSION,
            "Top Level Poseidon Message Hash: FINAL-LAYER must be a valid layer"
        );

        // Base and dimension check
        assert!(
            Self::BASE <= 1 << 8,
            "Poseidon Message Hash: Base must be at most 2^8"
        );
        assert!(
            Self::DIMENSION <= 1 << 8,
            "Poseidon Message Hash: Dimension must be at most 2^8"
        );

        // How many bits can be represented by one field element
        let bits_per_fe = f64::floor(f64::log2(
            BigUint::from(FqConfig::MODULUS)
                .to_string()
                .parse()
                .unwrap(),
        ));

        // Check that we have enough bits to encode message
        let message_fe_bits = bits_per_fe * f64::from(MSG_LEN_FE as u32);
        assert!(
            message_fe_bits >= f64::from((8_u32) * (MESSAGE_LENGTH as u32)),
            "Top Level Poseidon Message Hash: Parameter mismatch: not enough field elements to encode the message"
        );

        // Check that we have enough bits to encode tweak
        // Epoch is a u32, and we have one domain separator byte
        let tweak_fe_bits = bits_per_fe * f64::from(TWEAK_LEN_FE as u32);
        assert!(
            tweak_fe_bits >= f64::from(32 + 8_u32),
            "Top Level Poseidon Message Hash: Parameter mismatch: not enough field elements to encode the epoch tweak"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use zkhash::ark_ff::One;
    use zkhash::ark_ff::UniformRand;

    use crate::symmetric::message_hash::{
        top_level_poseidon::TopLevelPoseidonMessageHash, MessageHash,
    };

    #[test]
    fn test_apply() {
        const BASE: usize = 12;
        const DIMENSION: usize = 40;
        const FINAL_LAYER: usize = 175;

        type MH = TopLevelPoseidonMessageHash<48, DIMENSION, BASE, FINAL_LAYER, 3, 9, 4, 4>;

        let mut rng = thread_rng();

        let mut parameter = [F::one(); 4];
        for p in &mut parameter {
            *p = F::rand(&mut rng);
        }

        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        let epoch = 313;
        let randomness = MH::rand(&mut rng);

        MH::internal_consistency_check();
        let hash: Vec<u8> = MH::apply(&parameter, epoch, &randomness, &message);

        // we also want that the output is in the relevant part of the hypercube,
        // i.e., we want that the output is in some layer between 0 and FINAL_LAYER
        // by definition, this means (BASE-1)*DIMENSION - sum_i x_i <= FINAL_LAYER,
        // i.e., sum_i hash_i >= (BASE-1)*DIMENSION - FINAL_LAYER.

        let sum: usize = hash.iter().map(|&x| x as usize).sum();
        let lower_bound = (BASE - 1) * DIMENSION - FINAL_LAYER;

        assert!(
            sum >= lower_bound,
            "Output was not in the correct part of the lower bound"
        );
    }
}
