use num_bigint::BigUint;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField;
use p3_field::PrimeField64;
use serde::{Serialize, de::DeserializeOwned};

use super::MessageHash;
use crate::F;
use crate::MESSAGE_LENGTH;
use crate::TWEAK_SEPARATOR_FOR_MESSAGE_HASH;
use crate::poseidon2_24;
use crate::symmetric::tweak_hash::poseidon::poseidon_compress;

/// Function to encode a message as an array of field elements
pub fn encode_message<const MSG_LEN_FE: usize>(message: &[u8; MESSAGE_LENGTH]) -> [F; MSG_LEN_FE] {
    // Interpret message as a little-endian integer
    let mut acc = BigUint::from_bytes_le(message);

    // Perform base-p decomposition
    std::array::from_fn(|_| {
        let digit = &acc % F::ORDER_U64;
        acc /= F::ORDER_U64;
        F::from_u64(digit.try_into().unwrap())
    })
}

/// Encodes an epoch and a domain separator into an array of field elements.
///
/// This function combines the `u32` epoch and a constant 8-bit separator into a single
/// `u64` value. It then decomposes this value into its base-`p` representation,
/// where `p` is the field's order, to produce the output array.
///
/// ### Warning: Implementation Assumptions
///
/// This implementation is highly optimized and relies on two key assumptions about the field `F`:
///
/// 1.  **`u64`-Based Modulus:** It assumes the field's modulus fits within a `u64`. It is **not**
///     suitable for fields with larger moduli that require `BigUint` arithmetic.
///
/// 2.  **Sufficient Bit-Size:** The fast, two-step decomposition assumes the field is large
///     enough to hold a 40-bit value in at most two "digits". This requires the field's
///     prime to be **at least 20 bits wide**.
pub fn encode_epoch<const TWEAK_LEN_FE: usize>(epoch: u32) -> [F; TWEAK_LEN_FE] {
    // Combine epoch and domain separator into a single u64.
    let acc = ((epoch as u64) << 8) | (TWEAK_SEPARATOR_FOR_MESSAGE_HASH as u64);

    // Decompose the combined u64 value into field elements using base-p representation.
    //
    // This direct, two-step decomposition is an optimization that is only valid if
    // the field is large enough to represent a 40-bit number in at most two "digits".
    //
    // The condition is: ceil(40 / log2(p)) <= 2, which implies log2(p) >= 20.
    // This holds for 31 bit fields, but would fail for very small fields.
    //
    // We assume this function is only used with fields that satisfy this constraint.
    let mut result = [F::ZERO; TWEAK_LEN_FE];

    // The first "digit" of the base conversion.
    if TWEAK_LEN_FE > 0 {
        result[0] = F::from_u64(acc % F::ORDER_U64);
    }
    // The second "digit" of the base conversion.
    if TWEAK_LEN_FE > 1 {
        result[1] = F::from_u64(acc / F::ORDER_U64);
    }

    // Any subsequent elements (if TWEAK_LEN_FE > 2) remain zero.
    result
}

/// Function to decode a vector of field elements into
/// a vector of DIMENSION many chunks. One chunk is
/// between 0 and BASE - 1 (inclusive).
/// BASE and DIMENSION up to 2^8 (inclusive) are supported
fn decode_to_chunks<const DIMENSION: usize, const BASE: usize, const HASH_LEN_FE: usize>(
    field_elements: &[F; HASH_LEN_FE],
) -> [u8; DIMENSION] {
    // Combine field elements into one big integer
    let mut acc = BigUint::ZERO;
    for fe in field_elements {
        acc = &acc * F::ORDER_U64 + fe.as_canonical_biguint();
    }

    // Convert to base-BASE
    std::array::from_fn(|_| {
        let chunk = (&acc % BASE).try_into().unwrap();
        acc /= BASE;
        chunk
    })
}

/// A message hash implemented using Poseidon2
///
/// Note: PARAMETER_LEN, RAND_LEN, TWEAK_LEN_FE, MSG_LEN_FE, and HASH_LEN_FE
/// must be given in the unit "number of field elements".
///
/// HASH_LEN_FE specifies how many field elements the
/// hash output needs to be before it is decoded to chunks.
///
/// BASE and DIMENSION must be at most 2^8
pub struct PoseidonMessageHash<
    const PARAMETER_LEN: usize,
    const RAND_LEN_FE: usize,
    const HASH_LEN_FE: usize,
    const DIMENSION: usize,
    const BASE: usize,
    const TWEAK_LEN_FE: usize,
    const MSG_LEN_FE: usize,
>;

impl<
    const PARAMETER_LEN: usize,
    const RAND_LEN_FE: usize,
    const HASH_LEN_FE: usize,
    const DIMENSION: usize,
    const BASE: usize,
    const TWEAK_LEN_FE: usize,
    const MSG_LEN_FE: usize,
> MessageHash
    for PoseidonMessageHash<
        PARAMETER_LEN,
        RAND_LEN_FE,
        HASH_LEN_FE,
        DIMENSION,
        BASE,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
    >
where
    [F; PARAMETER_LEN]: Serialize + DeserializeOwned,
    [F; RAND_LEN_FE]: Serialize + DeserializeOwned,
{
    type Parameter = [F; PARAMETER_LEN];

    type Randomness = [F; RAND_LEN_FE];

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
        // Get the default, pre-configured Poseidon2 instance from Plonky3.
        let perm = poseidon2_24();

        // first, encode the message and the epoch as field elements
        let message_fe = encode_message::<MSG_LEN_FE>(message);
        let epoch_fe = encode_epoch::<TWEAK_LEN_FE>(epoch);

        // now, we hash randomness, parameters, epoch, message using PoseidonCompress
        let combined_input_vec: Vec<F> = randomness
            .iter()
            .chain(parameter.iter())
            .chain(epoch_fe.iter())
            .chain(message_fe.iter())
            .copied()
            .collect();

        let hash_fe = poseidon_compress::<F, _, 24, HASH_LEN_FE>(&perm, &combined_input_vec);

        // decode field elements into chunks and return them
        decode_to_chunks::<DIMENSION, BASE, HASH_LEN_FE>(&hash_fe).to_vec()
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // Check that Poseidon of width 24 is enough
        // Note: This block should be changed if we decide to support other Poseidon
        // instances. Currently we use state of width 24 and pad with 0s.

        assert!(
            PARAMETER_LEN + TWEAK_LEN_FE + RAND_LEN_FE + MSG_LEN_FE <= 24,
            "Poseidon of width 24 is not enough"
        );
        assert!(HASH_LEN_FE <= 24, "Poseidon of width 24 is not enough");

        // Base and dimension check
        assert!(
            Self::BASE <= 1 << 8,
            "Poseidon Message Hash: Base must be at most 2^8"
        );
        assert!(
            Self::DIMENSION <= 1 << 8,
            "Poseidon Message Hash: Dimension must be at most 2^8"
        );

        // how many bits can be represented by one field element
        let bits_per_fe = f64::floor(f64::log2(F::ORDER_U64 as f64));

        // Check that we have enough bits to encode message
        let message_fe_bits = bits_per_fe * f64::from(MSG_LEN_FE as u32);
        assert!(
            message_fe_bits >= f64::from((8_u32) * (MESSAGE_LENGTH as u32)),
            "Poseidon Message Hash: Parameter mismatch: not enough field elements to encode the message"
        );

        // Check that we have enough bits to encode tweak
        // Epoch is a u32, and we have one domain separator byte
        let tweak_fe_bits = bits_per_fe * f64::from(TWEAK_LEN_FE as u32);
        assert!(
            tweak_fe_bits >= f64::from(32 + 8_u32),
            "Poseidon Message Hash: Parameter mismatch: not enough field elements to encode the epoch tweak"
        );

        // Check that decoding from field elements to chunks can be done
        // injectively, i.e., we have enough chunks
        let hash_bits = bits_per_fe * f64::from(HASH_LEN_FE as u32);
        let chunk_size = f64::ceil(f64::log2(Self::BASE as f64)) as usize;
        assert!(
            hash_bits <= f64::from((DIMENSION * chunk_size) as u32),
            "Poseidon Message Hash: Parameter mismatch: not enough bits to decode the hash"
        );
    }
}

// Example instantiations
#[cfg(test)]
pub type PoseidonMessageHash445 = PoseidonMessageHash<4, 4, 5, 128, 4, 2, 9>;
#[cfg(test)]
pub type PoseidonMessageHashW1 = PoseidonMessageHash<5, 5, 5, 163, 2, 2, 9>;

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    use rand::Rng;
    use std::collections::HashMap;

    #[test]
    fn test_apply() {
        let mut rng = rand::rng();

        let parameter = rng.random();

        let message = rng.random();

        let epoch = 13;
        let randomness = PoseidonMessageHash445::rand(&mut rng);

        PoseidonMessageHash445::internal_consistency_check();
        PoseidonMessageHash445::apply(&parameter, epoch, &randomness, &message);
    }

    #[test]
    fn test_apply_w1() {
        let mut rng = rand::rng();

        let parameter = rng.random();

        let message = rng.random();

        let epoch = 13;
        let randomness = PoseidonMessageHashW1::rand(&mut rng);

        PoseidonMessageHashW1::internal_consistency_check();
        PoseidonMessageHashW1::apply(&parameter, epoch, &randomness, &message);
    }

    #[test]
    fn test_rand_not_all_same() {
        // Setup a number of trials
        const K: usize = 10;
        let mut rng = rand::rng();
        let mut all_same_count = 0;

        for _ in 0..K {
            let randomness = PoseidonMessageHash445::rand(&mut rng);

            // Check if all elements in `randomness` are identical
            let first = randomness[0];
            if randomness.iter().all(|&x| x == first) {
                all_same_count += 1;
            }
        }

        // If all K trials resulted in identical values, fail the test
        assert!(
            all_same_count < K,
            "rand generated identical elements in all {} trials",
            K
        );
    }

    #[test]
    fn test_encode_epoch_small_value() {
        let epoch = 42u32;
        let sep = TWEAK_SEPARATOR_FOR_MESSAGE_HASH;

        // Compute: (epoch << 8) + sep
        let epoch_bigint: BigUint = (BigUint::from(epoch) << 8) + sep;

        // Use the field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Compute field elements in base-p
        let expected = [
            F::from_u128((&epoch_bigint % &p).try_into().unwrap()),
            F::from_u128(((&epoch_bigint / &p) % &p).try_into().unwrap()),
            F::from_u128(((&epoch_bigint / (&p * &p)) % &p).try_into().unwrap()),
            F::from_u128(((&epoch_bigint / (&p * &p * &p)) % &p).try_into().unwrap()),
        ];

        let result = encode_epoch::<4>(epoch);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_epoch_zero() {
        let epoch = 0u32;
        let sep = TWEAK_SEPARATOR_FOR_MESSAGE_HASH;

        let epoch_bigint = BigUint::from(sep);
        let p = BigUint::from(F::ORDER_U64);

        let expected = [
            F::from_u64((&epoch_bigint % &p).try_into().unwrap()),
            F::from_u64(((&epoch_bigint / &p) % &p).try_into().unwrap()),
            F::from_u64(((&epoch_bigint / (&p * &p)) % &p).try_into().unwrap()),
            F::from_u64(((&epoch_bigint / (&p * &p * &p)) % &p).try_into().unwrap()),
        ];

        let result = encode_epoch::<4>(epoch);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_epoch_max_value() {
        let epoch = u32::MAX;
        let sep = TWEAK_SEPARATOR_FOR_MESSAGE_HASH;

        let epoch_bigint: BigUint = (BigUint::from(epoch) << 8) + sep;
        let p = BigUint::from(F::ORDER_U64);

        let expected = [
            F::from_u128((&epoch_bigint % &p).try_into().unwrap()),
            F::from_u128(((&epoch_bigint / &p) % &p).try_into().unwrap()),
            F::from_u128(((&epoch_bigint / (&p * &p)) % &p).try_into().unwrap()),
            F::from_u128(((&epoch_bigint / (&p * &p * &p)) % &p).try_into().unwrap()),
        ];

        let result = encode_epoch::<4>(epoch);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_epoch_injective() {
        // encoding an epoch must be injective
        // we test that by sampling random epochs and checking that they
        // do not produce the same encoding, unless they are the same

        let mut map = HashMap::new();
        let mut rng = rand::rng();

        for _ in 0..10_000 {
            let epoch: u32 = rng.random();
            let encoding = encode_epoch::<4>(epoch);
            if let Some(prev_epoch) = map.insert(encoding, epoch) {
                assert_eq!(
                    prev_epoch, epoch,
                    "Collision detected for epochs {} and {} with output {:?}",
                    prev_epoch, epoch, encoding
                );
            }
        }
    }

    #[test]
    fn test_encode_message_all_zeros() {
        // Message
        let message = [0u8; 32];

        // Expected = 9 zeros, as 9 * 31 >= 8 * 32
        let expected = [F::ZERO; 9];

        let computed = super::encode_message::<9>(&message);
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_encode_message_all_max() {
        // Message
        let message = [u8::MAX; 32];

        // Convert to bigint
        let message_bigint = BigUint::from_bytes_le(&message);

        // Field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Compute expected: base-p decomposition
        //
        // We compute this by hand to ensure that the test is correct.
        let expected = [
            F::from_u128((&message_bigint % &p).try_into().unwrap()),
            F::from_u128(((&message_bigint / &p) % &p).try_into().unwrap()),
            F::from_u128(((&message_bigint / (&p * &p)) % &p).try_into().unwrap()),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
        ];

        let computed = super::encode_message::<9>(&message);
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_encode_message_mixed_bytes() {
        // Alternating 0x00 and 0xFF
        let mut message = [0u8; 32];
        for (i, byte) in message.iter_mut().enumerate() {
            *byte = if i % 2 == 0 { 0x00 } else { 0xFF };
        }

        // Convert to bigint
        let message_bigint = BigUint::from_bytes_le(&message);

        // Field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Compute expected: base-p decomposition
        //
        // We compute this by hand to ensure that the test is correct.
        let expected = [
            F::from_u128((&message_bigint % &p).try_into().unwrap()),
            F::from_u128(((&message_bigint / &p) % &p).try_into().unwrap()),
            F::from_u128(((&message_bigint / (&p * &p)) % &p).try_into().unwrap()),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
            F::from_u128(
                ((&message_bigint / (&p * &p * &p * &p * &p * &p * &p * &p)) % &p)
                    .try_into()
                    .unwrap(),
            ),
        ];

        let computed = super::encode_message::<9>(&message);
        assert_eq!(computed, expected);
    }

    #[test]
    fn test_decode_to_chunks_all_zeros() {
        // All field elements are zero
        let field_elements = [F::ZERO; 5];

        // Should decode to all zero chunks
        let expected = [0u8; 8];
        let result = decode_to_chunks::<8, 16, 5>(&field_elements);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_decode_to_chunks_simple_value() {
        // Field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Create field elements
        let input = [F::from_u64(1u64), F::from_u64(2u64)];
        let input_uint = BigUint::from(2u64) * &p + BigUint::from(1u64);

        // CHUNK_SIZE = 4 => max value = 2^4 = 16
        // Split input_uint = 2p + 1 into base-16 digits (little endian)
        //
        // Example:
        //   input_uint = D_0 + 16*D_1 + 16^2*D_2 + ...
        //   We compute D_i = input_uint % 16, then divide by 16

        let mut acc = input_uint;
        let mut expected = [0; 4];
        for e in &mut expected {
            *e = (&acc % 16u8).try_into().unwrap();
            acc /= 16u8;
        }

        let result = decode_to_chunks::<4, 16, 2>(&input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_decode_to_chunks_max_value() {
        // Field modulus
        let p = BigUint::from(F::ORDER_U64);

        // Use all field elements set to p - 1
        let input = [F::from_u128((p.clone() - 1u32).try_into().unwrap()); 3];

        // Compute combined input_uint:
        //
        // input_uint = (p - 1) + (p - 1) * p + (p - 1) * p^2
        //           = (p^2 + p + 1) * (p - 1)
        //
        // We’ll expand it:
        // = (p - 1) * (p^2 + p + 1)
        // = p^3 - 1

        let p2 = &p * &p;
        let p3 = &p * &p2;
        let input_uint = &p3 - 1u32;

        // CHUNK_SIZE = 8 / BASE = 256
        let mut acc = input_uint;
        let mut expected = [0u8; 8];
        for e in &mut expected {
            *e = (&acc % 256u32).try_into().unwrap();
            acc /= 256u32;
        }

        let result = decode_to_chunks::<8, 256, 3>(&input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_decode_to_chunks_roundtrip_consistency() {
        const HASH_LEN_FE: usize = 4;
        const CHUNK_SIZE: usize = 4;
        const BASE: usize = 1 << CHUNK_SIZE; // 16
        const DIMENSION: usize = 32;

        let mut rng = rand::rng();
        let modulus = BigUint::from(F::ORDER_U64);

        // Generate random field elements
        let input_field_elements: [F; HASH_LEN_FE] = rng.random();

        // Reconstruct bigint from field elements using base-p
        let mut expected_bigint = BigUint::zero();
        for fe in &input_field_elements {
            expected_bigint = &expected_bigint * &modulus + fe.as_canonical_biguint();
        }

        // Decode to chunks
        let chunks = decode_to_chunks::<DIMENSION, BASE, HASH_LEN_FE>(&input_field_elements);

        // Assert that each chunk is between 0 and BASE - 1
        let base = BigUint::from(BASE);
        for &chunk in &chunks {
            assert!(
                BigUint::from(chunk) < base,
                "One of the chunks was too large."
            );
        }

        // Reconstruct bigint from chunks using little-endian base-(BASE)
        let mut reconstructed_bigint = BigUint::zero();
        for (i, &chunk) in chunks.iter().enumerate() {
            reconstructed_bigint += BigUint::from(chunk) * base.pow(i as u32);
        }

        // Assert equality
        assert_eq!(
            expected_bigint, reconstructed_bigint,
            "Reconstructed bigint from chunks does not match bigint from field elements"
        );
    }
}
