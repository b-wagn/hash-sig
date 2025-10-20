/// Instantiations with Lifetime 2^18
pub mod lifetime_2_to_the_18 {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
        symmetric::{
            message_hash::top_level_poseidon::TopLevelPoseidonMessageHash,
            prf::shake_to_field::ShakePRFtoF, tweak_hash::poseidon::PoseidonTweakHash,
        },
    };
    const LOG_LIFETIME: usize = 18;

    const DIMENSION: usize = 64;
    const BASE: usize = 8;
    const FINAL_LAYER: usize = 77;
    const TARGET_SUM: usize = 375;

    const PARAMETER_LEN: usize = 5;
    const TWEAK_LEN_FE: usize = 2;
    const MSG_LEN_FE: usize = 9;
    const RAND_LEN_FE: usize = 6;
    const HASH_LEN_FE: usize = 7;

    const CAPACITY: usize = 9;

    const POS_OUTPUT_LEN_PER_INV_FE: usize = 15;
    const POS_INVOCATIONS: usize = 1;
    const POS_OUTPUT_LEN_FE: usize = POS_OUTPUT_LEN_PER_INV_FE * POS_INVOCATIONS;

    type MH = TopLevelPoseidonMessageHash<
        POS_OUTPUT_LEN_PER_INV_FE,
        POS_INVOCATIONS,
        POS_OUTPUT_LEN_FE,
        DIMENSION,
        BASE,
        FINAL_LAYER,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
        PARAMETER_LEN,
        RAND_LEN_FE,
    >;
    type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;
    type PRF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;
    type IE = TargetSumEncoding<MH, TARGET_SUM>;

    pub type SIGTopLevelTargetSumLifetime18Dim64Base8 =
        GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

    #[cfg(test)]
    mod test {

        use crate::signature::{
            SignatureScheme,
            generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8,
        };

        #[cfg(feature = "slow-tests")]
        use crate::signature::test_templates::test_signature_scheme_correctness;

        #[test]
        pub fn test_internal_consistency() {
            SIGTopLevelTargetSumLifetime18Dim64Base8::internal_consistency_check();
        }

        #[test]
        #[cfg(feature = "slow-tests")]
        pub fn test_correctness() {
            test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime18Dim64Base8>(
                213,
                0,
                SIGTopLevelTargetSumLifetime18Dim64Base8::LIFETIME as usize,
            );
            test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime18Dim64Base8>(
                4,
                0,
                SIGTopLevelTargetSumLifetime18Dim64Base8::LIFETIME as usize,
            );
        }
    }
}

/// Instantiations with Lifetime 2^32
pub mod lifetime_2_to_the_32 {
    /// Instantiation optimized for verification hashing
    pub mod hashing_optimized {

        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::top_level_poseidon::TopLevelPoseidonMessageHash,
                prf::shake_to_field::ShakePRFtoF, tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 32;

        const DIMENSION: usize = 64;
        const BASE: usize = 8;
        const FINAL_LAYER: usize = 77;
        const TARGET_SUM: usize = 375;

        const PARAMETER_LEN: usize = 5;
        const TWEAK_LEN_FE: usize = 2;
        const MSG_LEN_FE: usize = 9;
        const RAND_LEN_FE: usize = 7;
        const HASH_LEN_FE: usize = 8;

        const CAPACITY: usize = 9;

        const POS_OUTPUT_LEN_PER_INV_FE: usize = 15;
        const POS_INVOCATIONS: usize = 1;
        const POS_OUTPUT_LEN_FE: usize = POS_OUTPUT_LEN_PER_INV_FE * POS_INVOCATIONS;

        type MH = TopLevelPoseidonMessageHash<
            POS_OUTPUT_LEN_PER_INV_FE,
            POS_INVOCATIONS,
            POS_OUTPUT_LEN_FE,
            DIMENSION,
            BASE,
            FINAL_LAYER,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
            PARAMETER_LEN,
            RAND_LEN_FE,
        >;
        type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;
        type PRF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;

        pub type SIGTopLevelTargetSumLifetime32Dim64Base8 =
            GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {

            use super::*;
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::test_signature_scheme_correctness;

            #[test]
            pub fn test_internal_consistency() {
                SIGTopLevelTargetSumLifetime32Dim64Base8::internal_consistency_check();
            }

            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_correctness() {
                test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime32Dim64Base8>(
                    213,
                    0,
                    SIGTopLevelTargetSumLifetime32Dim64Base8::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime32Dim64Base8>(
                    4,
                    0,
                    SIGTopLevelTargetSumLifetime32Dim64Base8::LIFETIME as usize,
                );
            }
        }
    }

    /// Instantiation that provides a trade-off between hashing and size
    pub mod tradeoff {

        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::top_level_poseidon::TopLevelPoseidonMessageHash,
                prf::shake_to_field::ShakePRFtoF, tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 32;

        const DIMENSION: usize = 48;
        const BASE: usize = 10;
        const FINAL_LAYER: usize = 112;
        const TARGET_SUM: usize = 326;

        const PARAMETER_LEN: usize = 5;
        const TWEAK_LEN_FE: usize = 2;
        const MSG_LEN_FE: usize = 9;
        const RAND_LEN_FE: usize = 7;
        const HASH_LEN_FE: usize = 8;

        const CAPACITY: usize = 9;

        const POS_OUTPUT_LEN_PER_INV_FE: usize = 15;
        const POS_INVOCATIONS: usize = 1;
        const POS_OUTPUT_LEN_FE: usize = POS_OUTPUT_LEN_PER_INV_FE * POS_INVOCATIONS;

        type MH = TopLevelPoseidonMessageHash<
            POS_OUTPUT_LEN_PER_INV_FE,
            POS_INVOCATIONS,
            POS_OUTPUT_LEN_FE,
            DIMENSION,
            BASE,
            FINAL_LAYER,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
            PARAMETER_LEN,
            RAND_LEN_FE,
        >;
        type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;
        type PRF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;

        pub type SIGTopLevelTargetSumLifetime32Dim48Base10 =
            GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {

            use super::*;
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::test_signature_scheme_correctness;

            #[test]
            pub fn test_internal_consistency() {
                SIGTopLevelTargetSumLifetime32Dim48Base10::internal_consistency_check();
            }

            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_correctness() {
                test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime32Dim48Base10>(
                    213,
                    0,
                    SIGTopLevelTargetSumLifetime32Dim48Base10::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime32Dim48Base10>(
                    4,
                    0,
                    SIGTopLevelTargetSumLifetime32Dim48Base10::LIFETIME as usize,
                );
            }
        }
    }

    /// Instantiation optimized for signature size
    pub mod size_optimized {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::top_level_poseidon::TopLevelPoseidonMessageHash,
                prf::shake_to_field::ShakePRFtoF, tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 32;

        const DIMENSION: usize = 32;
        const BASE: usize = 26;
        const FINAL_LAYER: usize = 231;
        const TARGET_SUM: usize = 579;

        const PARAMETER_LEN: usize = 5;
        const TWEAK_LEN_FE: usize = 2;
        const MSG_LEN_FE: usize = 9;
        const RAND_LEN_FE: usize = 7;
        const HASH_LEN_FE: usize = 8;

        const CAPACITY: usize = 9;

        const POS_OUTPUT_LEN_PER_INV_FE: usize = 15;
        const POS_INVOCATIONS: usize = 1;
        const POS_OUTPUT_LEN_FE: usize = POS_OUTPUT_LEN_PER_INV_FE * POS_INVOCATIONS;

        type MH = TopLevelPoseidonMessageHash<
            POS_OUTPUT_LEN_PER_INV_FE,
            POS_INVOCATIONS,
            POS_OUTPUT_LEN_FE,
            DIMENSION,
            BASE,
            FINAL_LAYER,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
            PARAMETER_LEN,
            RAND_LEN_FE,
        >;
        type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;
        type PRF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;
        type IE = TargetSumEncoding<MH, TARGET_SUM>;

        pub type SIGTopLevelTargetSumLifetime32Dim32Base26 =
            GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

        #[cfg(test)]
        mod test {

            use super::*;
            use crate::signature::SignatureScheme;

            #[cfg(feature = "slow-tests")]
            use crate::signature::test_templates::test_signature_scheme_correctness;

            #[test]
            pub fn test_internal_consistency() {
                SIGTopLevelTargetSumLifetime32Dim32Base26::internal_consistency_check();
            }

            #[test]
            #[cfg(feature = "slow-tests")]
            pub fn test_correctness() {
                test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime32Dim32Base26>(
                    213,
                    0,
                    SIGTopLevelTargetSumLifetime32Dim32Base26::LIFETIME as usize,
                );
                test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime32Dim32Base26>(
                    4,
                    0,
                    SIGTopLevelTargetSumLifetime32Dim32Base26::LIFETIME as usize,
                );
            }
        }
    }
}

/// Instantiations with Lifetime 2^8. This is for testing purposes only.
///
/// Warning: Should not be used in production environments.
pub mod lifetime_2_to_the_8 {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
        symmetric::{
            message_hash::top_level_poseidon::TopLevelPoseidonMessageHash,
            prf::shake_to_field::ShakePRFtoF, tweak_hash::poseidon::PoseidonTweakHash,
        },
    };

    const LOG_LIFETIME: usize = 8;

    const DIMENSION: usize = 64;
    const BASE: usize = 8;
    const FINAL_LAYER: usize = 77;
    const TARGET_SUM: usize = 375;

    const PARAMETER_LEN: usize = 5;
    const TWEAK_LEN_FE: usize = 2;
    const MSG_LEN_FE: usize = 9;
    const RAND_LEN_FE: usize = 7;
    const HASH_LEN_FE: usize = 8;

    const CAPACITY: usize = 9;

    const POS_OUTPUT_LEN_PER_INV_FE: usize = 15;
    const POS_INVOCATIONS: usize = 1;
    const POS_OUTPUT_LEN_FE: usize = POS_OUTPUT_LEN_PER_INV_FE * POS_INVOCATIONS;

    type MH = TopLevelPoseidonMessageHash<
        POS_OUTPUT_LEN_PER_INV_FE,
        POS_INVOCATIONS,
        POS_OUTPUT_LEN_FE,
        DIMENSION,
        BASE,
        FINAL_LAYER,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
        PARAMETER_LEN,
        RAND_LEN_FE,
    >;
    type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, DIMENSION>;

    type PRF = ShakePRFtoF<HASH_LEN_FE, RAND_LEN_FE>;

    type IE = TargetSumEncoding<MH, TARGET_SUM>;

    pub type SIGTopLevelTargetSumLifetime8Dim64Base8 =
        GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

    #[cfg(test)]
    mod test {

        use crate::signature::SignatureScheme;

        #[cfg(feature = "slow-tests")]
        use crate::signature::test_templates::test_signature_scheme_correctness;

        use super::SIGTopLevelTargetSumLifetime8Dim64Base8;

        #[test]
        pub fn test_internal_consistency() {
            SIGTopLevelTargetSumLifetime8Dim64Base8::internal_consistency_check();
        }

        #[cfg(feature = "slow-tests")]
        #[test]
        pub fn test_correctness() {
            test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime8Dim64Base8>(
                213,
                0,
                SIGTopLevelTargetSumLifetime8Dim64Base8::LIFETIME as usize,
            );
            test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime8Dim64Base8>(
                4,
                0,
                SIGTopLevelTargetSumLifetime8Dim64Base8::LIFETIME as usize,
            );
        }
    }
}
