/// Instantiations with Lifetime 2^18
pub mod lifetime_2_to_the_18 {
    /// Instantiations based on the Winternitz encoding
    pub mod winternitz {
        use crate::{
            inc_encoding::basic_winternitz::WinternitzEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::ShaMessageHash, prf::sha::ShaPRF, tweak_hash::sha::ShaTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 20;

        const CHUNK_SIZE_W1: usize = 1;
        const NUM_CHUNKS_W1: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W1;
        type MHw1 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W1, CHUNK_SIZE_W1>;
        const HASH_LEN_W1: usize = 25;
        type THw1 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = ShaPRF<HASH_LEN_W1>;
        type IEw1 = WinternitzEncoding<MHw1, CHUNK_SIZE_W1, 8>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 1
        pub type SIGWinternitzLifetime18W1 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const NUM_CHUNKS_W2: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W2;
        type MHw2 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W2, CHUNK_SIZE_W2>;
        const HASH_LEN_W2: usize = 25;
        type THw2 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = ShaPRF<HASH_LEN_W2>;
        type IEw2 = WinternitzEncoding<MHw2, CHUNK_SIZE_W2, 4>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 2
        pub type SIGWinternitzLifetime18W2 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const NUM_CHUNKS_W4: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W4;
        type MHw4 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W4, CHUNK_SIZE_W4>;
        const HASH_LEN_W4: usize = 26;
        type THw4 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = ShaPRF<HASH_LEN_W4>;
        type IEw4 = WinternitzEncoding<MHw4, CHUNK_SIZE_W4, 3>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 4
        pub type SIGWinternitzLifetime18W4 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4, THw4, LOG_LIFETIME>;

        const CHUNK_SIZE_W8: usize = 8;
        const NUM_CHUNKS_W8: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W8;
        type MHw8 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W8, CHUNK_SIZE_W8>;
        const HASH_LEN_W8: usize = 28;
        type THw8 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = ShaPRF<HASH_LEN_W8>;
        type IEw8 = WinternitzEncoding<MHw8, CHUNK_SIZE_W8, 2>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 8
        pub type SIGWinternitzLifetime18W8 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::_test_signature_scheme_correctness;

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
                _test_signature_scheme_correctness::<SIGWinternitzLifetime18W1>(1032);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                _test_signature_scheme_correctness::<SIGWinternitzLifetime18W2>(32);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                _test_signature_scheme_correctness::<SIGWinternitzLifetime18W4>(2032);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                _test_signature_scheme_correctness::<SIGWinternitzLifetime18W8>(2142);
            }
        }
    }
    /// Instantiations based on the target sum encoding
    pub mod target_sum {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::ShaMessageHash, prf::sha::ShaPRF, tweak_hash::sha::ShaTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 23;

        const CHUNK_SIZE_W1: usize = 1;
        const NUM_CHUNKS_W1: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W1;
        type MHw1 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W1, CHUNK_SIZE_W1>;
        const HASH_LEN_W1: usize = 25;
        type THw1 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = ShaPRF<HASH_LEN_W1>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MHw1, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W1NoOff =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<72>, THw1, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W1Off10 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<80>, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const NUM_CHUNKS_W2: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W2;
        type MHw2 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W2, CHUNK_SIZE_W2>;
        const HASH_LEN_W2: usize = 25;
        type THw2 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = ShaPRF<HASH_LEN_W2>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MHw2, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W2NoOff =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<108>, THw2, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W2Off10 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<119>, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const NUM_CHUNKS_W4: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W4;
        type MHw4 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W4, CHUNK_SIZE_W4>;
        const HASH_LEN_W4: usize = 26;
        type THw4 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = ShaPRF<HASH_LEN_W4>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MHw4, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W4NoOff =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<270>, THw4, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W4Off10 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<297>, THw4, LOG_LIFETIME>;

        const CHUNK_SIZE_W8: usize = 8;
        const NUM_CHUNKS_W8: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W8;
        type MHw8 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W8, CHUNK_SIZE_W8>;
        const HASH_LEN_W8: usize = 28;
        type THw8 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = ShaPRF<HASH_LEN_W8>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MHw8, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at expectation
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8NoOff =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2295>, THw8, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at 1.1 * expectation (10% offset)
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8Off10 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2525>, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::_test_signature_scheme_correctness;

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
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W1NoOff>(1032);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W1Off10>(32);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W2NoOff>(436);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W2Off10>(312);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W4NoOff>(21);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W4Off10>(3211);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W8NoOff>(32);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime18W8Off10>(768);
            }
        }
    }
}

/// Instantiations with Lifetime 2^20
pub mod lifetime_2_to_the_20 {

    /// Instantiations based on the Winternitz encoding
    pub mod winternitz {
        use crate::{
            inc_encoding::basic_winternitz::WinternitzEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::ShaMessageHash, prf::sha::ShaPRF, tweak_hash::sha::ShaTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 20;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 20;

        const CHUNK_SIZE_W1: usize = 1;
        const NUM_CHUNKS_W1: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W1;
        type MHw1 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W1, CHUNK_SIZE_W1>;
        const HASH_LEN_W1: usize = 25;
        type THw1 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = ShaPRF<HASH_LEN_W1>;
        type IEw1 = WinternitzEncoding<MHw1, CHUNK_SIZE_W1, 8>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 1
        pub type SIGWinternitzLifetime20W1 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const NUM_CHUNKS_W2: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W2;
        type MHw2 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W2, CHUNK_SIZE_W2>;
        const HASH_LEN_W2: usize = 26;
        type THw2 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = ShaPRF<HASH_LEN_W2>;
        type IEw2 = WinternitzEncoding<MHw2, CHUNK_SIZE_W2, 4>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 2
        pub type SIGWinternitzLifetime20W2 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const NUM_CHUNKS_W4: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W4;
        type MHw4 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W4, CHUNK_SIZE_W4>;
        const HASH_LEN_W4: usize = 26;
        type THw4 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = ShaPRF<HASH_LEN_W4>;
        type IEw4 = WinternitzEncoding<MHw4, CHUNK_SIZE_W4, 3>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 4
        pub type SIGWinternitzLifetime20W4 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4, THw4, LOG_LIFETIME>;

        const CHUNK_SIZE_W8: usize = 8;
        const NUM_CHUNKS_W8: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W8;
        type MHw8 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W8, CHUNK_SIZE_W8>;
        const HASH_LEN_W8: usize = 28;
        type THw8 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = ShaPRF<HASH_LEN_W8>;
        type IEw8 = WinternitzEncoding<MHw8, CHUNK_SIZE_W8, 2>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 8
        pub type SIGWinternitzLifetime20W8 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::_test_signature_scheme_correctness;

            use crate::signature::SignatureScheme;

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
                _test_signature_scheme_correctness::<SIGWinternitzLifetime20W1>(1032);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                _test_signature_scheme_correctness::<SIGWinternitzLifetime20W2>(32);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                _test_signature_scheme_correctness::<SIGWinternitzLifetime20W4>(2032);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                _test_signature_scheme_correctness::<SIGWinternitzLifetime20W8>(2142);
            }
        }
    }

    /// Instantiations based on the target sum encoding
    pub mod target_sum {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::ShaMessageHash, prf::sha::ShaPRF, tweak_hash::sha::ShaTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 20;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 23;

        const CHUNK_SIZE_W1: usize = 1;
        const NUM_CHUNKS_W1: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W1;
        type MHw1 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W1, CHUNK_SIZE_W1>;
        const HASH_LEN_W1: usize = 25;
        type THw1 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = ShaPRF<HASH_LEN_W1>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MHw1, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 1,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W1NoOff =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<72>, THw1, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 1,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W1Off10 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<80>, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const NUM_CHUNKS_W2: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W2;
        type MHw2 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W2, CHUNK_SIZE_W2>;
        const HASH_LEN_W2: usize = 26;
        type THw2 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = ShaPRF<HASH_LEN_W2>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MHw2, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 2,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W2NoOff =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<108>, THw2, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 2,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W2Off10 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<119>, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const NUM_CHUNKS_W4: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W4;
        type MHw4 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W4, CHUNK_SIZE_W4>;
        const HASH_LEN_W4: usize = 26;
        type THw4 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = ShaPRF<HASH_LEN_W4>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MHw4, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 4,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W4NoOff =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<270>, THw4, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 4,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W4Off10 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<297>, THw4, LOG_LIFETIME>;

        const CHUNK_SIZE_W8: usize = 8;
        const NUM_CHUNKS_W8: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE_W8;
        type MHw8 = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS_W8, CHUNK_SIZE_W8>;
        const HASH_LEN_W8: usize = 28;
        type THw8 = ShaTweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = ShaPRF<HASH_LEN_W8>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MHw8, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 8,
        /// and target sum set at expectation
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime20W8NoOff =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2295>, THw8, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 8,
        /// and target sum set at 1.1 * expectation (10% offset)
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime20W8Off10 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2525>, THw8, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {
            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::_test_signature_scheme_correctness;

            use crate::signature::SignatureScheme;

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
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W1NoOff>(932);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W1Off10>(321);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w2_correctness() {
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W2NoOff>(54);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W2Off10>(435);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w4_correctness() {
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W4NoOff>(3435);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W4Off10>(3424);
            }
            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_w8_correctness() {
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W8NoOff>(3241);
                _test_signature_scheme_correctness::<SIGTargetSumLifetime20W8Off10>(34);
            }
        }
    }
}
