use serde::{Serialize, de::DeserializeOwned};
use sha3::{Digest, Sha3_256};

use super::TweakableHash;
use crate::{TWEAK_SEPARATOR_FOR_CHAIN_HASH, TWEAK_SEPARATOR_FOR_TREE_HASH};

/// Enum to implement tweaks.
pub enum ShaTweak {
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

impl ShaTweak {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::TreeTweak {
                level,
                pos_in_level,
            } => {
                let mut bytes = Vec::new();
                // this is a tree tweak, so we start with a 0x00 byte
                bytes.push(TWEAK_SEPARATOR_FOR_TREE_HASH);
                // then we extend with the actual data
                bytes.extend(&level.to_be_bytes());
                bytes.extend(&pos_in_level.to_be_bytes());
                // Note: it is fine that both tweaks have different
                // lengths as the domain separator (0x00 or 0x01)
                // ensures that the length is known and we know when
                // the tweak ends.
                bytes
            }
            Self::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                let mut bytes = Vec::new();
                // this is a chain tweak, so we start with a 0x01 byte
                bytes.push(TWEAK_SEPARATOR_FOR_CHAIN_HASH);
                // then we extend with the actual data
                bytes.extend(&epoch.to_be_bytes());
                bytes.extend(&chain_index.to_be_bytes());
                bytes.extend(&pos_in_chain.to_be_bytes());
                bytes
            }
        }
    }
}

/// A tweakable hash function implemented using SHA3,
/// given a parameter length and the hash output length.
/// Both lengths must be given in Bytes.
/// Both lengths must be less than 255 bits.
pub struct ShaTweakHash<const PARAMETER_LEN: usize, const HASH_LEN: usize>;

impl<const PARAMETER_LEN: usize, const HASH_LEN: usize> TweakableHash
    for ShaTweakHash<PARAMETER_LEN, HASH_LEN>
where
    [u8; PARAMETER_LEN]: Serialize + DeserializeOwned,
    [u8; HASH_LEN]: Serialize + DeserializeOwned,
{
    type Parameter = [u8; PARAMETER_LEN];

    type Tweak = ShaTweak;

    type Domain = [u8; HASH_LEN];

    fn rand_parameter<R: rand::Rng>(rng: &mut R) -> Self::Parameter {
        let mut par = [0u8; PARAMETER_LEN];
        rng.fill_bytes(&mut par);
        par
    }

    fn rand_domain<R: rand::Rng>(rng: &mut R) -> Self::Domain {
        let mut dom = [0u8; HASH_LEN];
        rng.fill_bytes(&mut dom);
        dom
    }

    fn tree_tweak(level: u8, pos_in_level: u32) -> Self::Tweak {
        ShaTweak::TreeTweak {
            level,
            pos_in_level,
        }
    }

    fn chain_tweak(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self::Tweak {
        ShaTweak::ChainTweak {
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
        let mut hasher = Sha3_256::new();

        // add the parameter and tweak
        hasher.update(parameter);
        hasher.update(tweak.to_bytes());

        // now add the actual message to be hashed
        for m in message {
            hasher.update(m);
        }

        // finalize the hash, and take as many bytes as we need
        let result = hasher.finalize();
        result[0..HASH_LEN].try_into().unwrap()
    }

    #[cfg(test)]
    fn internal_consistency_check() {
        assert!(
            PARAMETER_LEN < 256 / 8,
            "SHA Tweak Hash: Parameter Length must be less than 256 bit"
        );
        assert!(
            HASH_LEN < 256 / 8,
            "SHA Tweak Hash: Hash Length must be less than 256 bit"
        );
    }
}

// Example instantiations
pub type ShaTweak128128 = ShaTweakHash<16, 16>;
pub type ShaTweak128192 = ShaTweakHash<16, 24>;
pub type ShaTweak192192 = ShaTweakHash<24, 24>;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand::Rng;

    use super::*;

    #[test]
    fn test_apply_128_128() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        ShaTweak128128::internal_consistency_check();

        // test that nothing is panicking
        let parameter = ShaTweak128128::rand_parameter(&mut rng);
        let message_one = ShaTweak128128::rand_domain(&mut rng);
        let message_two = ShaTweak128128::rand_domain(&mut rng);
        let tweak_tree = ShaTweak128128::tree_tweak(0, 3);
        ShaTweak128128::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = ShaTweak128128::rand_parameter(&mut rng);
        let message_one = ShaTweak128128::rand_domain(&mut rng);
        let message_two = ShaTweak128128::rand_domain(&mut rng);
        let tweak_chain = ShaTweak128128::chain_tweak(2, 3, 4);
        ShaTweak128128::apply(&parameter, &tweak_chain, &[message_one, message_two]);
    }

    #[test]
    fn test_apply_128_192() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        ShaTweak128192::internal_consistency_check();

        // test that nothing is panicking
        let parameter = ShaTweak128192::rand_parameter(&mut rng);
        let message_one = ShaTweak128192::rand_domain(&mut rng);
        let message_two = ShaTweak128192::rand_domain(&mut rng);
        let tweak_tree = ShaTweak128192::tree_tweak(0, 3);
        ShaTweak128192::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = ShaTweak128192::rand_parameter(&mut rng);
        let message_one = ShaTweak128192::rand_domain(&mut rng);
        let message_two = ShaTweak128192::rand_domain(&mut rng);
        let tweak_chain = ShaTweak128192::chain_tweak(2, 3, 4);
        ShaTweak128192::apply(&parameter, &tweak_chain, &[message_one, message_two]);
    }

    #[test]
    fn test_apply_192_192() {
        let mut rng = rand::rng();

        // make sure parameters make sense
        ShaTweak192192::internal_consistency_check();

        // test that nothing is panicking
        let parameter = ShaTweak192192::rand_parameter(&mut rng);
        let message_one = ShaTweak192192::rand_domain(&mut rng);
        let message_two = ShaTweak192192::rand_domain(&mut rng);
        let tweak_tree = ShaTweak192192::tree_tweak(0, 3);
        ShaTweak192192::apply(&parameter, &tweak_tree, &[message_one, message_two]);

        // test that nothing is panicking
        let parameter = ShaTweak192192::rand_parameter(&mut rng);
        let message_one = ShaTweak192192::rand_domain(&mut rng);
        let message_two = ShaTweak192192::rand_domain(&mut rng);
        let tweak_chain = ShaTweak192192::chain_tweak(2, 3, 4);
        ShaTweak192192::apply(&parameter, &tweak_chain, &[message_one, message_two]);
    }

    #[test]
    fn test_tree_tweak_injective() {
        let mut rng = rand::rng();

        // basic test to check that tree tweak maps from
        // parameters to byte array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let level = rng.random();
            let pos_in_level = rng.random();
            let tweak_encoding = ShaTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_bytes();

            if let Some((prev_level, prev_pos_in_level)) =
                map.insert(tweak_encoding.clone(), (level, pos_in_level))
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
            let tweak_encoding = ShaTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_bytes();

            if let Some(prev_pos_in_level) = map.insert(tweak_encoding.clone(), pos_in_level) {
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
            let tweak_encoding = ShaTweak::TreeTweak {
                level,
                pos_in_level,
            }
            .to_bytes();

            if let Some(prev_level) = map.insert(tweak_encoding.clone(), level) {
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
        // parameters to byte array injectively

        // random inputs
        let mut map = HashMap::new();
        for _ in 0..100_000 {
            let epoch = rng.random();
            let chain_index = rng.random();
            let pos_in_chain = rng.random();

            let input = (epoch, chain_index, pos_in_chain);

            let tweak_encoding = ShaTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_bytes();

            if let Some(prev_input) = map.insert(tweak_encoding.clone(), input) {
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

            let tweak_encoding = ShaTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_bytes();

            if let Some(prev_input) = map.insert(tweak_encoding.clone(), input) {
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

            let tweak_encoding = ShaTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_bytes();

            if let Some(prev_input) = map.insert(tweak_encoding.clone(), input) {
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

            let tweak_encoding = ShaTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            }
            .to_bytes();

            if let Some(prev_input) = map.insert(tweak_encoding.clone(), input) {
                assert_eq!(
                    prev_input, input,
                    "Collision detected for {prev_input:?} and {input:?} with output {tweak_encoding:?}"
                );
            }
        }
    }
}
