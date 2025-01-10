use num_bigint::BigUint;
use zkhash::ark_ff::MontConfig;
use zkhash::ark_ff::PrimeField;
use zkhash::ark_ff::UniformRand;
use zkhash::ark_ff::{One, Zero};
use zkhash::fields::babybear::FpBabyBear;
use zkhash::fields::babybear::FqConfig;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_babybear::POSEIDON2_BABYBEAR_24_PARAMS;

use super::MessageHash;
use crate::symmetric::tweak_hash::poseidon::poseidon_compress;
use crate::MESSAGE_LENGTH;
use crate::TWEAK_SEPARATOR_FOR_MESSAGE_HASH;

type F = FpBabyBear;

/// Function to encode a message as a vector of field elements
fn encode_message<const MSG_LEN_FE: usize>(message: &[u8; MESSAGE_LENGTH]) -> [F; MSG_LEN_FE] {
    // convert the bytes into a number
    let message_uint = BigUint::from_bytes_le(message);

    // now interpret the number in base-p
    let mut message_fe: [F; MSG_LEN_FE] = [F::zero(); MSG_LEN_FE];
    message_fe.iter_mut().fold(message_uint, |acc, item| {
        let tmp = acc.clone() % BigUint::from(FqConfig::MODULUS);
        *item = F::from(tmp.clone());
        (acc - tmp) / (BigUint::from(FqConfig::MODULUS))
    });
    message_fe
}

/// Function to encode an epoch (= tweak in the message hash)
/// as a vector of field elements.
fn encode_epoch<const TWEAK_LEN_FE: usize>(epoch: u32) -> [F; TWEAK_LEN_FE] {
    // convert the bytes (together with domain separator) into a number
    let epoch_uint: BigUint = (BigUint::from(epoch) << 8) + TWEAK_SEPARATOR_FOR_MESSAGE_HASH;

    // now interpret the number in base-p
    let mut tweak_fe: [F; TWEAK_LEN_FE] = [F::zero(); TWEAK_LEN_FE];
    tweak_fe.iter_mut().fold(epoch_uint, |acc, item| {
        let tmp = acc.clone() % BigUint::from(FqConfig::MODULUS);
        *item = F::from(tmp.clone());
        (acc - tmp) / (BigUint::from(FqConfig::MODULUS))
    });
    tweak_fe
}

/// Function to decode a vector of field elements into
/// a vector of NUM_CHUNKS many chunks. One chunk is
/// between 0 and 2^CHUNK_SIZE - 1 (inclusive).
/// CHUNK_SIZE up to 8 (inclusive) is supported
fn decode_to_chunks<const NUM_CHUNKS: usize, const CHUNK_SIZE: usize, const HASH_LEN_FE: usize>(
    field_elements: &[F; HASH_LEN_FE],
) -> Vec<u8> {
    // Turn field elements into a big integer
    let hash_uint = field_elements.iter().fold(BigUint::ZERO, |acc, &item| {
        acc * BigUint::from(FqConfig::MODULUS) + BigUint::from(item.into_bigint())
    });

    // Split the integer into chunks
    let max_chunk_len = (1 << CHUNK_SIZE) as u16;

    let mut hash_chunked: [u8; NUM_CHUNKS] = [0 as u8; NUM_CHUNKS];
    hash_chunked.iter_mut().fold(hash_uint, |acc, item| {
        *item = (acc.clone() % max_chunk_len).to_bytes_be()[0];
        (acc - *item) / max_chunk_len
    });
    Vec::from(hash_chunked)
}

/// A message hash implemented using Poseidon2
///
/// Note: PARAMETER_LEN, RAND_LEN, TWEAK_LEN_FE, MSG_LEN_FE, and HASH_LEN_FE
/// must be given in the unit "number of field elements".
///
/// HASH_LEN_FE specifies how many field elements the
/// hash output needs to be before it is decoded to chunks.
///
/// CHUNK_SIZE has to be 1,2,4, or 8.
pub struct PoseidonMessageHash<
    const PARAMETER_LEN: usize,
    const RAND_LEN: usize,
    const HASH_LEN_FE: usize,
    const NUM_CHUNKS: usize,
    const CHUNK_SIZE: usize,
    const TWEAK_LEN_FE: usize,
    const MSG_LEN_FE: usize,
>;

impl<
        const PARAMETER_LEN: usize,
        const RAND_LEN: usize,
        const HASH_LEN_FE: usize,
        const NUM_CHUNKS: usize,
        const CHUNK_SIZE: usize,
        const TWEAK_LEN_FE: usize,
        const MSG_LEN_FE: usize,
    > MessageHash
    for PoseidonMessageHash<
        PARAMETER_LEN,
        RAND_LEN,
        HASH_LEN_FE,
        NUM_CHUNKS,
        CHUNK_SIZE,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
    >
{
    type Parameter = [F; PARAMETER_LEN];

    type Randomness = [F; RAND_LEN];

    const NUM_CHUNKS: usize = NUM_CHUNKS;

    const CHUNK_SIZE: usize = CHUNK_SIZE;

    fn rand<R: rand::Rng>(rng: &mut R) -> Self::Randomness {
        let mut rnd = [F::one(); RAND_LEN];
        for i in 0..RAND_LEN {
            rnd[i] = F::rand(rng);
        }
        rnd
    }

    fn apply(
        parameter: &Self::Parameter,
        epoch: u32,
        randomness: &Self::Randomness,
        message: &[u8; MESSAGE_LENGTH],
    ) -> Vec<u8> {
        // We need a Poseidon instance

        // Note: This block should be changed if we decide to support other Poseidon
        // instances. Currently we use state of width 24 and pad with 0s.
        assert!(PARAMETER_LEN + TWEAK_LEN_FE + RAND_LEN + MSG_LEN_FE <= 24);
        let instance = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);

        // first, encode the message and the epoch as field elements
        let message_fe = encode_message::<MSG_LEN_FE>(message);
        let epoch_fe = encode_epoch::<TWEAK_LEN_FE>(epoch);

        // now, we hash randomness, parameters, epoch, message using PoseidonCompress
        let combined_input: Vec<F> = randomness
            .iter()
            .chain(epoch_fe.iter())
            .chain(message_fe.iter())
            .chain(parameter.iter())
            .cloned()
            .collect();
        let hash_fe = poseidon_compress::<HASH_LEN_FE>(&instance, &combined_input);

        // decode field elements into chunks and return them
        decode_to_chunks::<NUM_CHUNKS, CHUNK_SIZE, HASH_LEN_FE>(&hash_fe)
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        // message check
        let message_fe_bits = f64::log2(
            BigUint::from(FqConfig::MODULUS)
                .to_string()
                .parse()
                .unwrap(),
        ) * f64::from(MSG_LEN_FE as u32);
        assert!(
            message_fe_bits >= f64::from((8 as u32) * (MESSAGE_LENGTH as u32)),
            "Poseidon Message hash. Parameter mismatch: not enough field elements to encode the message"
        );

        // tweak check
        let tweak_fe_bits = f64::log2(
            BigUint::from(FqConfig::MODULUS)
                .to_string()
                .parse()
                .unwrap(),
        ) * f64::from(TWEAK_LEN_FE as u32);
        assert!(
            tweak_fe_bits >= f64::from(32 + 8 as u32),
            "Poseidon Message hash. Parameter mismatch: not enough field elements to encode the epoch tweak"
        );

        // decoding check
        let hash_bits = f64::log2(
            BigUint::from(FqConfig::MODULUS)
                .to_string()
                .parse()
                .unwrap(),
        ) * f64::from(HASH_LEN_FE as u32);
        assert!(
            hash_bits <= f64::from((NUM_CHUNKS * CHUNK_SIZE) as u32),
            "Poseidon Message hash. Parameter mismatch: not enough chunks to decode the hash"
        );
    }
}

// Example instantiations
pub type PoseidonMessageHash445 = PoseidonMessageHash<4, 4, 5, 128, 2, 2, 9>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use zkhash::ark_ff::UniformRand;

    #[test]
    fn test_apply() {
        let mut rng = thread_rng();

        let mut parameter = [F::one(); 4];
        for i in 0..4 {
            parameter[i] = F::rand(&mut rng);
        }

        let mut message = [0u8; MESSAGE_LENGTH];
        rng.fill(&mut message);

        let epoch = 13;
        let randomness = PoseidonMessageHash445::rand(&mut rng);

        PoseidonMessageHash445::internal_consistency_check();
        PoseidonMessageHash445::apply(&parameter, epoch, &randomness, &message);
    }
}
