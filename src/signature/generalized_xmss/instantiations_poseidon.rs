/// Instantiations with Lifetime 2^18
pub mod lifetime_2_to_the_18 {
    /// Instantiations based on the Winternitz encoding
    pub mod winternitz {
        use p3_baby_bear::BabyBear;

        use crate::{
            inc_encoding::basic_winternitz::WinternitzEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::poseidon::PoseidonMessageHash, prf::shake_to_field::ShakePRFtoF,
                tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 5;
        const MSG_HASH_LEN_FE: usize = 5;
        const HASH_LEN_FE: usize = 7;
        const MSG_LEN_FE: usize = 9;
        const TWEAK_LEN_FE: usize = 2;
        const RAND_LEN: usize = 5;
        const CAPACITY: usize = 9;

        const CHUNK_SIZE_W1: usize = 1;
        const BASE_W1: usize = 2;
        const NUM_CHUNKS_W1: usize = 155;
        const NUM_CHUNKS_CHECKSUM_W1: usize = 8;
        const _CEIL_LOG_NUM_CHAINS_W1: usize = 8;
        type MHw1 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W1,
            BASE_W1,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw1 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W1>;
        type PRFw1 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw1 = WinternitzEncoding<MHw1, CHUNK_SIZE_W1, NUM_CHUNKS_CHECKSUM_W1>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 1
        pub type SIGWinternitzLifetime18W1 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const BASE_W2: usize = 4;
        const NUM_CHUNKS_W2: usize = 78;
        const NUM_CHUNKS_CHECKSUM_W2: usize = 4;
        const _CEIL_LOG_NUM_CHAINS_W2: usize = 7;
        type MHw2 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W2,
            BASE_W2,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw2 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W2>;
        type PRFw2 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw2 = WinternitzEncoding<MHw2, CHUNK_SIZE_W2, NUM_CHUNKS_CHECKSUM_W2>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 2
        pub type SIGWinternitzLifetime18W2 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const BASE_W4: usize = 16;
        const NUM_CHUNKS_W4: usize = 39;
        const NUM_CHUNKS_CHECKSUM_W4: usize = 3;
        const _CEIL_LOG_NUM_CHAINS_W4: usize = 6;
        type MHw4 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W4,
            BASE_W4,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw4 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W4>;
        type PRFw4 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw4 = WinternitzEncoding<MHw4, CHUNK_SIZE_W4, NUM_CHUNKS_CHECKSUM_W4>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 4
        pub type SIGWinternitzLifetime18W4 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4, THw4, LOG_LIFETIME>;

        const CHUNK_SIZE_W8: usize = 8;
        const BASE_W8: usize = 256;
        const NUM_CHUNKS_W8: usize = 20;
        const NUM_CHUNKS_CHECKSUM_W8: usize = 2;
        const _CEIL_LOG_NUM_CHAINS_W8: usize = 5;
        type MHw8 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W8,
            BASE_W8,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw8 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W8>;
        type PRFw8 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw8 = WinternitzEncoding<MHw8, CHUNK_SIZE_W8, NUM_CHUNKS_CHECKSUM_W8>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 8
        pub type SIGWinternitzLifetime18W8 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::test_signature_scheme_correctness;

            use super::{
                SIGWinternitzLifetime18W1, SIGWinternitzLifetime18W2, SIGWinternitzLifetime18W4,
                SIGWinternitzLifetime18W8,
            };

            #[test]
            pub fn test_w1_internal_consistency() {
                SIGWinternitzLifetime18W1::internal_consistency_check();
            }
            #[test]
            pub fn test_w2_internal_consistency() {
                SIGWinternitzLifetime18W2::internal_consistency_check();
            }
            #[test]
            pub fn test_w4_internal_consistency() {
                SIGWinternitzLifetime18W4::internal_consistency_check();
            }
            #[test]
            pub fn test_w8_internal_consistency() {
                SIGWinternitzLifetime18W8::internal_consistency_check();
            }

            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w1_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime18W1>(
                    1032,
                    0,
                    SIGWinternitzLifetime18W1::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime18W2>(
                    32,
                    0,
                    SIGWinternitzLifetime18W2::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime18W4>(
                    2032,
                    0,
                    SIGWinternitzLifetime18W4::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime18W8>(
                    2142,
                    0,
                    SIGWinternitzLifetime18W8::LIFETIME as usize,
                );
            }
        }
    }
    /// Instantiations based on the target sum encoding
    pub mod target_sum {
        use p3_baby_bear::BabyBear;

        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::poseidon::PoseidonMessageHash, prf::shake_to_field::ShakePRFtoF,
                tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 5;
        const MSG_HASH_LEN_FE: usize = 5;
        const HASH_LEN_FE: usize = 7;
        const MSG_LEN_FE: usize = 9;
        const TWEAK_LEN_FE: usize = 2;
        const RAND_LEN: usize = 6;
        const CAPACITY: usize = 9;

        const _CHUNK_SIZE_W1: usize = 1;
        const BASE_W1: usize = 2;
        const NUM_CHUNKS_W1: usize = 155;
        const _CEIL_LOG_NUM_CHAINS_W1: usize = 8;
        type MHw1 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W1,
            BASE_W1,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw1 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W1>;
        type PRFw1 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MHw1, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W1NoOff =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<78>, THw1, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W1Off10 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<86>, THw1, LOG_LIFETIME>;

        const _CHUNK_SIZE_W2: usize = 2;
        const BASE_W2: usize = 4;
        const NUM_CHUNKS_W2: usize = 78;
        const _CEIL_LOG_NUM_CHAINS_W2: usize = 7;
        type MHw2 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W2,
            BASE_W2,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw2 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W2>;
        type PRFw2 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MHw2, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W2NoOff =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<117>, THw2, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W2Off10 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<129>, THw2, LOG_LIFETIME>;

        const _CHUNK_SIZE_W4: usize = 4;
        const BASE_W4: usize = 16;
        const NUM_CHUNKS_W4: usize = 39;
        const _CEIL_LOG_NUM_CHAINS_W4: usize = 6;
        type MHw4 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W4,
            BASE_W4,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw4 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W4>;
        type PRFw4 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MHw4, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W4NoOff =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<293>, THw4, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W4Off10 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<322>, THw4, LOG_LIFETIME>;

        const _CHUNK_SIZE_W8: usize = 8;
        const BASE_W8: usize = 256;
        const NUM_CHUNKS_W8: usize = 20;
        const _CEIL_LOG_NUM_CHAINS_W8: usize = 5;
        type MHw8 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W8,
            BASE_W8,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw8 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W8>;
        type PRFw8 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MHw8, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at expectation
        ///
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8NoOff =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2550>, THw8, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at 1.1 * expectation (10% offset)
        ///
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8Off10 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2805>, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::test_signature_scheme_correctness;

            use super::{
                SIGTargetSumLifetime18W1NoOff, SIGTargetSumLifetime18W1Off10,
                SIGTargetSumLifetime18W2NoOff, SIGTargetSumLifetime18W2Off10,
                SIGTargetSumLifetime18W4NoOff, SIGTargetSumLifetime18W4Off10,
                SIGTargetSumLifetime18W8NoOff, SIGTargetSumLifetime18W8Off10,
            };

            #[test]
            pub fn test_w1_internal_consistency() {
                SIGTargetSumLifetime18W1NoOff::internal_consistency_check();
                SIGTargetSumLifetime18W1Off10::internal_consistency_check();
            }
            #[test]
            pub fn test_w2_internal_consistency() {
                SIGTargetSumLifetime18W2NoOff::internal_consistency_check();
                SIGTargetSumLifetime18W2Off10::internal_consistency_check();
            }
            #[test]
            pub fn test_w4_internal_consistency() {
                SIGTargetSumLifetime18W4NoOff::internal_consistency_check();
                SIGTargetSumLifetime18W4Off10::internal_consistency_check();
            }
            #[test]
            pub fn test_w8_internal_consistency() {
                SIGTargetSumLifetime18W8NoOff::internal_consistency_check();
                SIGTargetSumLifetime18W8Off10::internal_consistency_check();
            }

            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w1_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W1NoOff>(
                    1032,
                    0,
                    SIGTargetSumLifetime18W1NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W1Off10>(
                    32,
                    0,
                    SIGTargetSumLifetime18W1Off10::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W2NoOff>(
                    436,
                    0,
                    SIGTargetSumLifetime18W2NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W2Off10>(
                    312,
                    0,
                    SIGTargetSumLifetime18W2Off10::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W4NoOff>(
                    21,
                    0,
                    SIGTargetSumLifetime18W4NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W4Off10>(
                    3211,
                    0,
                    SIGTargetSumLifetime18W4Off10::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W8NoOff>(
                    32,
                    0,
                    SIGTargetSumLifetime18W8NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime18W8Off10>(
                    768,
                    0,
                    SIGTargetSumLifetime18W8Off10::LIFETIME as usize,
                );
            }
        }
    }
}

/// Instantiations with Lifetime 2^20
pub mod lifetime_2_to_the_20 {
    /// Instantiations based on the Winternitz encoding
    pub mod winternitz {
        use p3_baby_bear::BabyBear;

        use crate::{
            inc_encoding::basic_winternitz::WinternitzEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::poseidon::PoseidonMessageHash, prf::shake_to_field::ShakePRFtoF,
                tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 20;
        const PARAMETER_LEN: usize = 5;
        const MSG_HASH_LEN_FE: usize = 5;
        const HASH_LEN_FE: usize = 7;
        const MSG_LEN_FE: usize = 9;
        const TWEAK_LEN_FE: usize = 2;
        const RAND_LEN: usize = 6;
        const CAPACITY: usize = 9;

        const CHUNK_SIZE_W1: usize = 1;
        const BASE_W1: usize = 2;
        const NUM_CHUNKS_W1: usize = 155;
        const NUM_CHUNKS_CHECKSUM_W1: usize = 8;
        const _CEIL_LOG_NUM_CHAINS_W1: usize = 8;
        type MHw1 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W1,
            BASE_W1,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw1 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W1>;
        type PRFw1 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw1 = WinternitzEncoding<MHw1, CHUNK_SIZE_W1, NUM_CHUNKS_CHECKSUM_W1>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 1
        pub type SIGWinternitzLifetime20W1 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const BASE_W2: usize = 4;
        const NUM_CHUNKS_W2: usize = 78;
        const NUM_CHUNKS_CHECKSUM_W2: usize = 4;
        const _CEIL_LOG_NUM_CHAINS_W2: usize = 7;
        type MHw2 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W2,
            BASE_W2,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw2 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W2>;
        type PRFw2 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw2 = WinternitzEncoding<MHw2, CHUNK_SIZE_W2, NUM_CHUNKS_CHECKSUM_W2>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 2
        pub type SIGWinternitzLifetime20W2 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const BASE_W4: usize = 16;
        const NUM_CHUNKS_W4: usize = 39;
        const NUM_CHUNKS_CHECKSUM_W4: usize = 3;
        const _CEIL_LOG_NUM_CHAINS_W4: usize = 6;
        type MHw4 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W4,
            BASE_W4,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw4 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W4>;
        type PRFw4 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw4 = WinternitzEncoding<MHw4, CHUNK_SIZE_W4, NUM_CHUNKS_CHECKSUM_W4>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 4
        pub type SIGWinternitzLifetime20W4 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4, THw4, LOG_LIFETIME>;

        const HASH_LEN_FE_W8: usize = 8;
        const CHUNK_SIZE_W8: usize = 8;
        const BASE_W8: usize = 256;
        const NUM_CHUNKS_W8: usize = 20;
        const NUM_CHUNKS_CHECKSUM_W8: usize = 2;
        const _CEIL_LOG_NUM_CHAINS_W8: usize = 5;
        type MHw8 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W8,
            BASE_W8,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw8 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE_W8, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W8>;
        type PRFw8 = ShakePRFtoF<BabyBear, HASH_LEN_FE_W8>;
        type IEw8 = WinternitzEncoding<MHw8, CHUNK_SIZE_W8, NUM_CHUNKS_CHECKSUM_W8>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 8
        pub type SIGWinternitzLifetime20W8 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::test_signature_scheme_correctness;

            use super::{
                SIGWinternitzLifetime20W1, SIGWinternitzLifetime20W2, SIGWinternitzLifetime20W4,
                SIGWinternitzLifetime20W8,
            };

            #[test]
            pub fn test_w1_internal_consistency() {
                SIGWinternitzLifetime20W1::internal_consistency_check();
            }
            #[test]
            pub fn test_w2_internal_consistency() {
                SIGWinternitzLifetime20W2::internal_consistency_check();
            }
            #[test]
            pub fn test_w4_internal_consistency() {
                SIGWinternitzLifetime20W4::internal_consistency_check();
            }
            #[test]
            pub fn test_w8_internal_consistency() {
                SIGWinternitzLifetime20W8::internal_consistency_check();
            }

            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w1_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime20W1>(
                    1032,
                    0,
                    SIGWinternitzLifetime20W1::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime20W2>(
                    32,
                    0,
                    SIGWinternitzLifetime20W2::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime20W4>(
                    2032,
                    0,
                    SIGWinternitzLifetime20W4::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                test_signature_scheme_correctness::<SIGWinternitzLifetime20W8>(
                    2142,
                    0,
                    SIGWinternitzLifetime20W8::LIFETIME as usize,
                );
            }
        }
    }
    /// Instantiations based on the target sum encoding
    pub mod target_sum {
        use p3_baby_bear::BabyBear;

        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::poseidon::PoseidonMessageHash, prf::shake_to_field::ShakePRFtoF,
                tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 20;
        const PARAMETER_LEN: usize = 5;
        const HASH_LEN_FE: usize = 7;
        const MSG_HASH_LEN_FE: usize = 5;
        const MSG_LEN_FE: usize = 9;
        const TWEAK_LEN_FE: usize = 2;
        const RAND_LEN: usize = 6;
        const CAPACITY: usize = 9;

        const _CHUNK_SIZE_W1: usize = 1;
        const BASE_W1: usize = 2;
        const NUM_CHUNKS_W1: usize = 155;
        const _CEIL_LOG_NUM_CHAINS_W1: usize = 8;
        type MHw1 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W1,
            BASE_W1,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw1 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W1>;
        type PRFw1 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MHw1, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 1,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W1NoOff =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<78>, THw1, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 1,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W1Off10 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<86>, THw1, LOG_LIFETIME>;

        const _CHUNK_SIZE_W2: usize = 2;
        const BASE_W2: usize = 4;
        const NUM_CHUNKS_W2: usize = 78;
        const _CEIL_LOG_NUM_CHAINS_W2: usize = 7;
        type MHw2 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W2,
            BASE_W2,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw2 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W2>;
        type PRFw2 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MHw2, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 2,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W2NoOff =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<117>, THw2, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 2,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W2Off10 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<129>, THw2, LOG_LIFETIME>;

        const _CHUNK_SIZE_W4: usize = 4;
        const BASE_W4: usize = 16;
        const NUM_CHUNKS_W4: usize = 39;
        const _CEIL_LOG_NUM_CHAINS_W4: usize = 6;
        type MHw4 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W4,
            BASE_W4,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw4 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W4>;
        type PRFw4 = ShakePRFtoF<BabyBear, HASH_LEN_FE>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MHw4, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 4,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W4NoOff =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<293>, THw4, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 4,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W4Off10 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<322>, THw4, LOG_LIFETIME>;

        const HASH_LEN_FE_W8: usize = 8;
        const _CHUNK_SIZE_W8: usize = 8;
        const BASE_W8: usize = 256;
        const NUM_CHUNKS_W8: usize = 20;
        const _CEIL_LOG_NUM_CHAINS_W8: usize = 5;
        type MHw8 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            MSG_HASH_LEN_FE,
            NUM_CHUNKS_W8,
            BASE_W8,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw8 =
            PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE_W8, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W8>;
        type PRFw8 = ShakePRFtoF<BabyBear, HASH_LEN_FE_W8>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MHw8, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 8,
        /// and target sum set at expectation
        ///
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime20W8NoOff =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2550>, THw8, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 8,
        /// and target sum set at 1.1 * expectation (10% offset)
        ///
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime20W8Off10 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2805>, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::test_signature_scheme_correctness;

            use super::{
                SIGTargetSumLifetime20W1NoOff, SIGTargetSumLifetime20W1Off10,
                SIGTargetSumLifetime20W2NoOff, SIGTargetSumLifetime20W2Off10,
                SIGTargetSumLifetime20W4NoOff, SIGTargetSumLifetime20W4Off10,
                SIGTargetSumLifetime20W8NoOff, SIGTargetSumLifetime20W8Off10,
            };

            #[test]
            pub fn test_w1_internal_consistency() {
                SIGTargetSumLifetime20W1NoOff::internal_consistency_check();
                SIGTargetSumLifetime20W1Off10::internal_consistency_check();
            }
            #[test]
            pub fn test_w2_internal_consistency() {
                SIGTargetSumLifetime20W2NoOff::internal_consistency_check();
                SIGTargetSumLifetime20W2Off10::internal_consistency_check();
            }
            #[test]
            pub fn test_w4_internal_consistency() {
                SIGTargetSumLifetime20W4NoOff::internal_consistency_check();
                SIGTargetSumLifetime20W4Off10::internal_consistency_check();
            }
            #[test]
            pub fn test_w8_internal_consistency() {
                SIGTargetSumLifetime20W8NoOff::internal_consistency_check();
                SIGTargetSumLifetime20W8Off10::internal_consistency_check();
            }

            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w1_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W1NoOff>(
                    1032,
                    0,
                    SIGTargetSumLifetime20W1NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W1Off10>(
                    32,
                    0,
                    SIGTargetSumLifetime20W1Off10::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W2NoOff>(
                    436,
                    0,
                    SIGTargetSumLifetime20W2NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W2Off10>(
                    312,
                    0,
                    SIGTargetSumLifetime20W2Off10::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W4NoOff>(
                    21,
                    0,
                    SIGTargetSumLifetime20W4NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W4Off10>(
                    3211,
                    0,
                    SIGTargetSumLifetime20W4Off10::LIFETIME as usize,
                );
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W8NoOff>(
                    32,
                    0,
                    SIGTargetSumLifetime20W8NoOff::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTargetSumLifetime20W8Off10>(
                    768,
                    0,
                    SIGTargetSumLifetime20W8Off10::LIFETIME as usize,
                );
            }
        }
    }
}
