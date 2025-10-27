use std::{cmp::min, hint::black_box};

use criterion::{Criterion, SamplingMode};
use rand::Rng;

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_poseidon_top_level::{
            lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8,
            lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8,
            lifetime_2_to_the_32::{
                hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8,
                size_optimized::SIGTopLevelTargetSumLifetime32Dim32Base26,
                tradeoff::SIGTopLevelTargetSumLifetime32Dim48Base10,
            },
        },
    },
};

/// We will benchmark with actual lifetime min(LIFETIME, 1 << MAX_LOG_ACTIVATION_DURATION)
/// to keep key generation time within reasonable limits.
const MAX_LOG_ACTIVATION_DURATION: usize = 18;

/// A template for benchmarking signature schemes (key gen, signing, verification)
pub fn benchmark_signature_scheme<S: SignatureScheme>(c: &mut Criterion, description: &str) {
    let mut group = c.benchmark_group(format!("Poseidon: {description}"));

    // activation duration = actual lifetime
    let activation_duration = min(1 << MAX_LOG_ACTIVATION_DURATION, S::LIFETIME as usize);

    // key gen takes long, so don't do that many repetitions
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    let mut rng = rand::rng();

    // Note: benchmarking key generation takes long, so it is
    // commented out for now. You can enable it here.

    #[cfg(feature = "with-gen-benches-poseidon-top-level")]
    group.bench_function("- gen", |b| {
        b.iter(|| {
            // Benchmark key generation
            let _ = S::key_gen(black_box(&mut rng), 0, activation_duration);
        });
    });

    group.sample_size(100);

    let (pk, sk) = S::key_gen(&mut rng, 0, activation_duration);

    // Get the prepared epoch interval to ensure we only sign at valid epochs
    let prepared_interval = sk.get_prepared_interval();

    group.bench_function("- sign", |b| {
        b.iter(|| {
            // Sample random test message
            let message = rng.random();

            // Sample random epoch within the prepared interval
            let epoch =
                rng.random_range(prepared_interval.start as u32..prepared_interval.end as u32);

            // Benchmark signing
            let _ = S::sign(black_box(&sk), black_box(epoch), black_box(&message));
        });
    });

    // Pre-generate messages, epochs, and signatures for verification
    let precomputed: Vec<(u32, [u8; MESSAGE_LENGTH], S::Signature)> = (0..2000)
        .map(|_| {
            let message = rng.random();
            // Use epochs within the prepared interval
            let epoch =
                rng.random_range(prepared_interval.start as u32..prepared_interval.end as u32);

            let signature = S::sign(&sk, epoch, &message).expect("Signing should succeed");
            (epoch, message, signature)
        })
        .collect();

    // Verification benchmark
    group.bench_function("- verify", |b| {
        b.iter(|| {
            // Randomly pick a precomputed signature to verify
            let (epoch, message, signature) =
                black_box(&precomputed[rng.random_range(0..precomputed.len())]);
            let _ = S::verify(
                black_box(&pk),
                *epoch,
                black_box(message),
                black_box(signature),
            );
        });
    });

    group.finish();
}

pub fn bench_function_poseidon_top_level(c: &mut Criterion) {
    // benchmarking lifetime 2^8
    benchmark_signature_scheme::<SIGTopLevelTargetSumLifetime8Dim64Base8>(
        c,
        &format!(
            "Top Level TS, Lifetime 2^8, Activation 2^{MAX_LOG_ACTIVATION_DURATION}, Dimension 64, Base 8"
        ),
    );

    // benchmarking lifetime 2^18
    benchmark_signature_scheme::<SIGTopLevelTargetSumLifetime18Dim64Base8>(
        c,
        &format!(
            "Top Level TS, Lifetime 2^18, Activation 2^{MAX_LOG_ACTIVATION_DURATION}, Dimension 64, Base 8"
        ),
    );

    // benchmarking lifetime 2^32 - hashing optimized
    benchmark_signature_scheme::<SIGTopLevelTargetSumLifetime32Dim64Base8>(
        c,
        &format!(
            "Top Level TS, Lifetime 2^32, Activation 2^{MAX_LOG_ACTIVATION_DURATION}, Dimension 64, Base 8 (Hashing Optimized)"
        ),
    );

    // benchmarking lifetime 2^32 - trade-off
    benchmark_signature_scheme::<SIGTopLevelTargetSumLifetime32Dim48Base10>(
        c,
        &format!(
            "Top Level TS, Lifetime 2^32, Activation 2^{MAX_LOG_ACTIVATION_DURATION}, Dimension 48, Base 10 (Trade-off)"
        ),
    );

    // benchmarking lifetime 2^32 - size optimized
    benchmark_signature_scheme::<SIGTopLevelTargetSumLifetime32Dim32Base26>(
        c,
        &format!(
            "Top Level TS, Lifetime 2^32, Activation 2^{MAX_LOG_ACTIVATION_DURATION}, Dimension 32, Base 26 (Size Optimized)"
        ),
    );
}
