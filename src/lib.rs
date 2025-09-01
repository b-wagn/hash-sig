use p3_baby_bear::{
    BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16, default_babybear_poseidon2_24,
};
use std::sync::OnceLock;

/// Message length in bytes, for messages that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;

pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

type F = BabyBear;

pub mod hypercube;
pub mod inc_encoding;
pub mod signature;
pub mod symmetric;

/// Cached Poseidon2 permutations.
///
/// We cache the default Plonky3 Poseidon2 instances once and return a clone.
/// Returning by value preserves existing call sites that take `&perm`.
static POSEIDON2_24: OnceLock<Poseidon2BabyBear<24>> = OnceLock::new();
static POSEIDON2_16: OnceLock<Poseidon2BabyBear<16>> = OnceLock::new();

/// Poseidon2 permutation (width 24)
pub(crate) fn poseidon2_24() -> Poseidon2BabyBear<24> {
    POSEIDON2_24.get_or_init(default_babybear_poseidon2_24).clone()
}

/// Poseidon2 permutation (width 16)
pub(crate) fn poseidon2_16() -> Poseidon2BabyBear<16> {
    POSEIDON2_16.get_or_init(default_babybear_poseidon2_16).clone()
}
