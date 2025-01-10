use sha3::{Digest, Sha3_256};

use super::TweakableHash;

/// Enum to implement tweaks.
pub enum ShaTweak {
    TreeTweak {
        level: u8,
        pos_in_level: u32,
    },
    ChainTweak {
        epoch: u32,
        chain_index: u16,
        pos_in_chain: u16,
    },
}

impl ShaTweak {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            ShaTweak::TreeTweak {
                level,
                pos_in_level,
            } => {
                let mut bytes = Vec::new();
                // this is a tree tweak, so we start with a 0x00 byte
                bytes.push(0x00);
                // then we extend with the actual data
                bytes.extend(&level.to_be_bytes());
                bytes.extend(&pos_in_level.to_be_bytes());
                // Note: it is fine that both tweaks have different
                // lengths as the domain separator (0x00 or 0x01)
                // ensures that the length is known and we know when
                // the tweak ends.
                bytes
            }
            ShaTweak::ChainTweak {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                let mut bytes = Vec::new();
                // this is a chain tweak, so we start with a 0x01 byte
                bytes.push(0x01);
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

    fn chain_tweak(epoch: u32, chain_index: u16, pos_in_chain: u16) -> Self::Tweak {
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

    fn consistency_check() -> bool {
        assert!(
            PARAMETER_LEN < 256 / 8,
            "SHA Tweak Hash: Parameter Length must be less than 256 bit"
        );
        assert!(
            HASH_LEN < 256 / 8,
            "SHA Tweak Hash: Hash Length must be less than 256 bit"
        );
        true
    }
}

// Example instantiations
pub type ShaTweak128128 = ShaTweakHash<16, 16>;
pub type ShaTweak128192 = ShaTweakHash<16, 24>;
pub type ShaTweak192192 = ShaTweakHash<24, 24>;

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_apply_128_128() {
        let mut rng = thread_rng();

        ShaTweak128128::consistency_check();

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
        let mut rng = thread_rng();

        ShaTweak128192::consistency_check();

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
        let mut rng = thread_rng();

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
}
