use p3_field::Field;
use p3_koala_bear::{
    KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_24,
};
use std::sync::OnceLock;

/// Message length in bytes, for messages that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;

pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

type F = KoalaBear;
pub(crate) type PackedF = <F as Field>::Packing;

pub(crate) mod hypercube;
pub(crate) mod inc_encoding;
pub mod signature;
pub(crate) mod symmetric;

// Cached Poseidon2 permutations.
//
// We cache the default Plonky3 Poseidon2 instances once and return a clone.
// Returning by value preserves existing call sites that take `&perm`.

/// A lazily-initialized, thread-safe cache for the Poseidon2 permutation with a width of 24.
static POSEIDON2_24: OnceLock<Poseidon2KoalaBear<24>> = OnceLock::new();

/// A lazily-initialized, thread-safe cache for the Poseidon2 permutation with a width of 16.
static POSEIDON2_16: OnceLock<Poseidon2KoalaBear<16>> = OnceLock::new();

/// Poseidon2 permutation (width 24)
pub(crate) fn poseidon2_24() -> Poseidon2KoalaBear<24> {
    POSEIDON2_24
        .get_or_init(default_koalabear_poseidon2_24)
        .clone()
}

/// Poseidon2 permutation (width 16)
pub(crate) fn poseidon2_16() -> Poseidon2KoalaBear<16> {
    POSEIDON2_16
        .get_or_init(default_koalabear_poseidon2_16)
        .clone()
}
