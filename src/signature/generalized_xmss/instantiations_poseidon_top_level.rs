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

    const DIMENSION: usize = 40;
    const BASE: usize = 12;
    const FINAL_LAYER: usize = 160;
    const TARGET_SUM: usize = 289;

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
    type PRF = ShakePRFtoF<HASH_LEN_FE>;
    type IE = TargetSumEncoding<MH, TARGET_SUM>;

    pub type SIGTopLevelTargetSumLifetime18Dim40Base12 =
        GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

    #[cfg(test)]
    mod test {
        #[cfg(feature = "slow-tests")]
        use crate::signature::test_templates::_test_signature_scheme_correctness;
        use crate::signature::{
            generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim40Base12,
            SignatureScheme,
        };

        #[test]
        pub fn test_internal_consistency() {
            SIGTopLevelTargetSumLifetime18Dim40Base12::internal_consistency_check();
        }

        #[test]
        #[cfg(feature = "slow-tests")]
        pub fn test_correctness() {
            _test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime18Dim40Base12>(213);
            _test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime18Dim40Base12>(4);
        }
    }
}

/// Instantiations with Lifetime 2^26
pub mod lifetime_2_to_the_26 {
    use crate::{
        inc_encoding::target_sum::TargetSumEncoding,
        signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
        symmetric::{
            message_hash::top_level_poseidon::TopLevelPoseidonMessageHash,
            prf::shake_to_field::ShakePRFtoF, tweak_hash::poseidon::PoseidonTweakHash,
        },
    };

    const LOG_LIFETIME: usize = 26;

    const DIMENSION: usize = 64;
    const BASE: usize = 8;
    const FINAL_LAYER: usize = 80;
    const TARGET_SUM: usize = 372;

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
    type PRF = ShakePRFtoF<HASH_LEN_FE>;
    type IE = TargetSumEncoding<MH, TARGET_SUM>;

    pub type SIGTopLevelTargetSumLifetime26Dim64Base8 =
        GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;

    #[cfg(test)]
    mod test {
        #[cfg(feature = "slow-tests")]
        use crate::signature::test_templates::_test_signature_scheme_correctness;
        use crate::signature::{
            generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_26::SIGTopLevelTargetSumLifetime26Dim64Base8,
            SignatureScheme,
        };

        #[test]
        pub fn test_internal_consistency() {
            SIGTopLevelTargetSumLifetime26Dim64Base8::internal_consistency_check();
        }

        #[test]
        #[cfg(feature = "slow-tests")]
        pub fn test_correctness() {
            _test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime26Dim64Base8>(213);
            _test_signature_scheme_correctness::<SIGTopLevelTargetSumLifetime26Dim64Base8>(4);
        }
    }
}
