/// Message length in bytes, for messages
/// that we want to sign.
pub const MESSAGE_LENGTH: usize = 32;
pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 2;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 1;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0;

pub mod inc_encoding;
pub mod signature;
pub mod symmetric;
