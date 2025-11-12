use num_bigint::BigUint;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField;
use p3_field::PrimeField64;
use serde::{Serialize, de::DeserializeOwned};

use super::MessageHash;
use super::poseidon::encode_epoch;
use super::poseidon::encode_message;
use crate::F;
use crate::MESSAGE_LENGTH;
use crate::hypercube::hypercube_find_layer;
use crate::hypercube::hypercube_part_size;
use crate::hypercube::map_to_vertex;
use crate::poseidon2_24;
use crate::symmetric::tweak_hash::poseidon::poseidon_compress;

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
    let mut acc = BigUint::ZERO;
    for fe in field_elements {
        acc = &acc * F::ORDER_U64 + fe.as_canonical_biguint();
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

/// A message hash implemented using Poseidon2 that maps messages into the top layers
/// of a hypercube structure.
///
/// Specifically, consider the hypercube {0, ..., BASE-1}^DIMENSION, partitioned into layers as follows:
///
/// - **Layer 0**: {(BASE-1, ..., BASE-1)}
/// - **Layer (BASE-1) * DIMENSION**: {(0, ..., 0)}
/// - **Layer T**: all points (x_1, ..., x_DIMENSION) such that
///   (BASE-1) * DIMENSION - sum_i x_i = T
///
/// This message hash maps into layers 0 to FINAL_LAYER (inclusive).
///
/// # Notes
///
/// - `PARAMETER_LEN`, `RAND_LEN`, `TWEAK_LEN_FE`, `MSG_LEN_FE`, and `HASH_LEN_FE`
///   are specified in **number of field elements**.
///
/// - `POS_OUTPUT_LEN_PER_INV_FE` specifies how many field elements we obtain
///   from each Poseidon2 invocation.
///
/// - `POS_INVOCATIONS` is the number of Poseidon2 invocations performed.
///
/// We then take the resulting `POS_INVOCATIONS * POS_OUTPUT_LEN_PER_INV_FE`
/// field elements and decode them into an element of the top layers.
///
/// # Constraints
///
/// - `POS_OUTPUT_LEN_FE` must be at most 15.
/// - `POS_INVOCATIONS` must be at most 2^8.
/// - `POS_OUTPUT_LEN_FE` must be equal to `POS_INVOCATIONS * POS_OUTPUT_LEN_PER_INV_FE`.
/// - `BASE` must be at most 2^8.
pub struct TopLevelPoseidonMessageHash<
    const POS_OUTPUT_LEN_PER_INV_FE: usize,
    const POS_INVOCATIONS: usize,
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
    const POS_OUTPUT_LEN_PER_INV_FE: usize,
    const POS_INVOCATIONS: usize,
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
        POS_OUTPUT_LEN_PER_INV_FE,
        POS_INVOCATIONS,
        POS_OUTPUT_LEN_FE,
        DIMENSION,
        BASE,
        FINAL_LAYER,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
        PARAMETER_LEN,
        RAND_LEN,
    >
where
    [F; PARAMETER_LEN]: Serialize + DeserializeOwned,
    [F; RAND_LEN]: Serialize + DeserializeOwned,
{
    type Parameter = [F; PARAMETER_LEN];

    type Randomness = [F; RAND_LEN];

    const DIMENSION: usize = DIMENSION;

    const BASE: usize = BASE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        rng.random()
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8> {
        let perm = poseidon2_24();

        // first, encode the message and the epoch as field elements
        let message_fe = encode_message::<MSG_LEN_FE>(message);
        let epoch_fe = encode_epoch::<TWEAK_LEN_FE>(epoch);

        // now, invoke Poseidon a few times, to get field elements
        let mut pos_outputs = [F::ZERO; POS_OUTPUT_LEN_FE];
        for i in 0..POS_INVOCATIONS {
            // iteration domain separator
            let iteration_index = [F::from_u8(i as u8)];

            // assemble input for this iteration
            let combined_input: Vec<F> = randomness
                .iter()
                .chain(parameter.iter())
                .chain(epoch_fe.iter())
                .chain(message_fe.iter())
                .chain(iteration_index.iter())
                .copied()
                .collect();

            let iteration_pos_output =
                poseidon_compress::<F, _, 24, POS_OUTPUT_LEN_PER_INV_FE>(&perm, &combined_input);

            pos_outputs[i * POS_OUTPUT_LEN_PER_INV_FE..(i + 1) * POS_OUTPUT_LEN_PER_INV_FE]
                .copy_from_slice(&iteration_pos_output);
        }

        // turn the field elements into an element in the part
        // of the hypercube that we care about.
        map_into_hypercube_part::<DIMENSION, BASE, FINAL_LAYER, POS_OUTPUT_LEN_FE>(&pos_outputs)
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        /// The width of the Poseidon2 permutation used.
        const POSEIDON_WIDTH: usize = 24;

        // Check that the combined input fits within the Poseidon width.
        assert!(
            RAND_LEN + PARAMETER_LEN + TWEAK_LEN_FE + MSG_LEN_FE < POSEIDON_WIDTH,
            "Top Level Poseidon Message Hash: Combined input length exceeds Poseidon width"
        );

        // POS_OUTPUT_LEN_FE must be equal to POS_INVOCATIONS * POS_OUTPUT_LEN_PER_INV_FE
        assert!(
            POS_OUTPUT_LEN_FE == POS_INVOCATIONS * POS_OUTPUT_LEN_PER_INV_FE,
            "Top Level Poseidon Message Hash: POS_OUTPUT_LEN_FE must be equal to POS_INVOCATIONS * POS_OUTPUT_LEN_PER_INV_FE"
        );

        // POS_OUTPUT_LEN_FE must be at most 15 (because capacity is 9)
        assert!(
            POS_OUTPUT_LEN_PER_INV_FE <= 15,
            "Top Level Poseidon Message Hash: POS_OUTPUT_LEN_PER_INV_FE must be at most 15"
        );

        // Number of invocations we require should fit in a field element
        // For simplicity we require at most 2^8 invocations, which is more than enough
        assert!(
            POS_INVOCATIONS <= 1 << 8,
            "Top Level Poseidon Message Hash: POS_INVOCATIONS must be at most 2^8"
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
        let bits_per_fe = f64::floor(f64::log2(F::ORDER_U64 as f64));

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
    use proptest::prelude::*;
    use rand::Rng;

    use crate::symmetric::message_hash::{
        MessageHash, top_level_poseidon::TopLevelPoseidonMessageHash,
    };

    #[test]
    fn test_apply() {
        const BASE: usize = 12;
        const DIMENSION: usize = 40;
        const FINAL_LAYER: usize = 175;

        type MH = TopLevelPoseidonMessageHash<8, 6, 48, DIMENSION, BASE, FINAL_LAYER, 3, 9, 4, 4>;

        let mut rng = rand::rng();

        let parameter = rng.random();

        let message = rng.random();

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

    proptest! {
        #[test]
        fn proptest_apply(
            epoch in 0u32..1000,
            message in any::<[u8; MESSAGE_LENGTH]>(),
        ) {
            const BASE: usize = 12;
            const DIMENSION: usize = 40;
            const FINAL_LAYER: usize = 175;

            type MH = TopLevelPoseidonMessageHash<8, 6, 48, DIMENSION, BASE, FINAL_LAYER, 3, 9, 4, 4>;

            let mut rng = rand::rng();

            let parameter = rng.random();
            let randomness = MH::rand(&mut rng);

            let hash = MH::apply(&parameter, epoch, &randomness, &message);

            // Length must match dimension
            prop_assert_eq!(hash.len(), DIMENSION);

            // Values are in range 0..BASE
            for &val in &hash {
                prop_assert!((val as usize) < BASE);
            }

            // Output is in correct hypercube part (layer range)
            let sum: usize = hash.iter().map(|&x| x as usize).sum();
            let lower_bound = (BASE - 1) * DIMENSION - FINAL_LAYER;
            prop_assert!(
                sum >= lower_bound,
                "Output hash lies outside allowed hypercube layer"
            );
        }
    }
}
