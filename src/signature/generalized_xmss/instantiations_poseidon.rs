/// Instantiations with Lifetime 2^18
pub mod lifetime_2_to_the_18 {
    /// Instantiations based on the Winternitz encoding
    pub mod winternitz {
        use crate::{
            inc_encoding::basic_winternitz::WinternitzEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::poseidon::PoseidonMessageHash, prf::sha::ShaPRFtoF,
                tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 5;
        const HASH_LEN_FE: usize = 5;
        const MSG_LEN_FE: usize = 9;
        const TWEAK_LEN_FE: usize = 2;
        const RAND_LEN: usize = 5;
        const CAPACITY: usize = 9;

        const CHUNK_SIZE_W1: usize = 1;
        const NUM_CHUNKS_W1: usize = 155;
        const NUM_CHUNKS_CHECKSUM_W1: usize = 8;
        const CEIL_LOG_NUM_CHAINS_W1: usize = 8;
        type MHw1 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W1,
            CHUNK_SIZE_W1,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw1 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W1,
            CHUNK_SIZE_W1,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W1,
        >;
        type PRFw1 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw1 = WinternitzEncoding<MHw1, NUM_CHUNKS_CHECKSUM_W1>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 1
        pub type SIGWinternitzLifetime18W1 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const NUM_CHUNKS_W2: usize = 78;
        const NUM_CHUNKS_CHECKSUM_W2: usize = 4;
        const CEIL_LOG_NUM_CHAINS_W2: usize = 7;
        type MHw2 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W2,
            CHUNK_SIZE_W2,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw2 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W2,
            CHUNK_SIZE_W2,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W2,
        >;
        type PRFw2 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw2 = WinternitzEncoding<MHw2, NUM_CHUNKS_CHECKSUM_W2>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 2
        pub type SIGWinternitzLifetime18W2 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const NUM_CHUNKS_W4: usize = 39;
        const NUM_CHUNKS_CHECKSUM_W4: usize = 3;
        const CEIL_LOG_NUM_CHAINS_W4: usize = 6;
        type MHw4 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W4,
            CHUNK_SIZE_W4,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw4 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W4,
            CHUNK_SIZE_W4,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W4,
        >;
        type PRFw4 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw4 = WinternitzEncoding<MHw4, NUM_CHUNKS_CHECKSUM_W4>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 4
        pub type SIGWinternitzLifetime18W4 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4, THw4, LOG_LIFETIME>;

        const CHUNK_SIZE_W8: usize = 8;
        const NUM_CHUNKS_W8: usize = 20;
        const NUM_CHUNKS_CHECKSUM_W8: usize = 2;
        const CEIL_LOG_NUM_CHAINS_W8: usize = 5;
        type MHw8 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W8,
            CHUNK_SIZE_W8,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw8 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W8,
            CHUNK_SIZE_W8,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W8,
        >;
        type PRFw8 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw8 = WinternitzEncoding<MHw8, 2>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 8
        pub type SIGWinternitzLifetime18W8 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;
    }
    /// Instantiations based on the target sum encoding
    pub mod target_sum {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::poseidon::PoseidonMessageHash, prf::sha::ShaPRFtoF,
                tweak_hash::poseidon::PoseidonTweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 5;
        const HASH_LEN_FE: usize = 5;
        const MSG_LEN_FE: usize = 9;
        const TWEAK_LEN_FE: usize = 2;
        const RAND_LEN: usize = 6;
        const CAPACITY: usize = 9;

        const CHUNK_SIZE_W1: usize = 1;
        const NUM_CHUNKS_W1: usize = 155;
        const CEIL_LOG_NUM_CHAINS_W1: usize = 8;
        type MHw1 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W1,
            CHUNK_SIZE_W1,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw1 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W1,
            CHUNK_SIZE_W1,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W1,
        >;
        type PRFw1 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MHw1, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W1NoOff =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<78>, THw1, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W1Off10 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<86>, THw1, LOG_LIFETIME>;

        const CHUNK_SIZE_W2: usize = 2;
        const NUM_CHUNKS_W2: usize = 78;
        const CEIL_LOG_NUM_CHAINS_W2: usize = 7;
        type MHw2 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W2,
            CHUNK_SIZE_W2,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw2 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W2,
            CHUNK_SIZE_W2,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W2,
        >;
        type PRFw2 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MHw2, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W2NoOff =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<117>, THw2, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W2Off10 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<129>, THw2, LOG_LIFETIME>;

        const CHUNK_SIZE_W4: usize = 4;
        const NUM_CHUNKS_W4: usize = 39;
        const CEIL_LOG_NUM_CHAINS_W4: usize = 6;
        type MHw4 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W4,
            CHUNK_SIZE_W4,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw4 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W4,
            CHUNK_SIZE_W4,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W4,
        >;
        type PRFw4 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MHw4, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W4NoOff =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<293>, THw4, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W4Off10 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<322>, THw4, LOG_LIFETIME>;

        const CHUNK_SIZE_W8: usize = 8;
        const NUM_CHUNKS_W8: usize = 20;
        const CEIL_LOG_NUM_CHAINS_W8: usize = 5;
        type MHw8 = PoseidonMessageHash<
            PARAMETER_LEN,
            RAND_LEN,
            HASH_LEN_FE,
            NUM_CHUNKS_W8,
            CHUNK_SIZE_W8,
            TWEAK_LEN_FE,
            MSG_LEN_FE,
        >;
        type THw8 = PoseidonTweakHash<
            LOG_LIFETIME,
            CEIL_LOG_NUM_CHAINS_W8,
            CHUNK_SIZE_W8,
            PARAMETER_LEN,
            HASH_LEN_FE,
            TWEAK_LEN_FE,
            CAPACITY,
            NUM_CHUNKS_W8,
        >;
        type PRFw8 = ShaPRFtoF<HASH_LEN_FE>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MHw8, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at expectation
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8NoOff =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2550>, THw8, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at 1.1 * expectation (10% offset)
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8Off10 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2805>, THw8, LOG_LIFETIME>;
    }
}
