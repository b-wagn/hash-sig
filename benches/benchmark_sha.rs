use std::hint::black_box;

use criterion::{Criterion, SamplingMode};
use rand::Rng;

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme, SignatureSchemeSecretKey,
        generalized_xmss::instantiations_sha::{
            lifetime_2_to_the_18::{
                target_sum::{
                    SIGTargetSumLifetime18W1NoOff, SIGTargetSumLifetime18W1Off10,
                    SIGTargetSumLifetime18W2NoOff, SIGTargetSumLifetime18W2Off10,
                    SIGTargetSumLifetime18W4NoOff, SIGTargetSumLifetime18W4Off10,
                    SIGTargetSumLifetime18W8NoOff, SIGTargetSumLifetime18W8Off10,
                },
                winternitz::{
                    SIGWinternitzLifetime18W1, SIGWinternitzLifetime18W2,
                    SIGWinternitzLifetime18W4, SIGWinternitzLifetime18W8,
                },
            },
            lifetime_2_to_the_20::{
                target_sum::{
                    SIGTargetSumLifetime20W1NoOff, SIGTargetSumLifetime20W1Off10,
                    SIGTargetSumLifetime20W2NoOff, SIGTargetSumLifetime20W2Off10,
                    SIGTargetSumLifetime20W4NoOff, SIGTargetSumLifetime20W4Off10,
                    SIGTargetSumLifetime20W8NoOff, SIGTargetSumLifetime20W8Off10,
                },
                winternitz::{
                    SIGWinternitzLifetime20W1, SIGWinternitzLifetime20W2,
                    SIGWinternitzLifetime20W4, SIGWinternitzLifetime20W8,
                },
            },
        },
    },
};

/// A template for benchmarking signature schemes (key gen, signing, verification)
pub fn benchmark_signature_scheme<S: SignatureScheme>(c: &mut Criterion, description: &str) {
    let mut group = c.benchmark_group(format!("SHA: {description}"));

    // key gen takes long, so don't do that many repetitions
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    let mut rng = rand::rng();

    // Note: benchmarking key generation takes long, so it is
    // commented out for now. You can enable it here.

    #[cfg(feature = "with-gen-benches-sha")]
    group.bench_function("- gen", |b| {
        b.iter(|| {
            // Benchmark key generation
            let _ = S::key_gen(black_box(&mut rng), 0, S::LIFETIME as usize);
        });
    });

    group.sample_size(100);

    let (pk, sk) = S::key_gen(&mut rng, 0, S::LIFETIME as usize);

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

/// Benchmarking Lifetime 2^18 for Winternitz Encoding
fn bench_lifetime18_winternitz(c: &mut Criterion) {
    benchmark_signature_scheme::<SIGWinternitzLifetime18W1>(c, "Winternitz, Lifetime 2^18, w = 1");
    benchmark_signature_scheme::<SIGWinternitzLifetime18W2>(c, "Winternitz, Lifetime 2^18, w = 2");
    benchmark_signature_scheme::<SIGWinternitzLifetime18W4>(c, "Winternitz, Lifetime 2^18, w = 4");
    benchmark_signature_scheme::<SIGWinternitzLifetime18W8>(c, "Winternitz, Lifetime 2^18, w = 8");
}

/// Benchmarking Lifetime 2^20 for Winternitz Encoding
fn bench_lifetime20_winternitz(c: &mut Criterion) {
    benchmark_signature_scheme::<SIGWinternitzLifetime20W1>(c, "Winternitz, Lifetime 2^20, w = 1");
    benchmark_signature_scheme::<SIGWinternitzLifetime20W2>(c, "Winternitz, Lifetime 2^20, w = 2");
    benchmark_signature_scheme::<SIGWinternitzLifetime20W4>(c, "Winternitz, Lifetime 2^20, w = 4");
    benchmark_signature_scheme::<SIGWinternitzLifetime20W8>(c, "Winternitz, Lifetime 2^20, w = 8");
}

/// Benchmarking Lifetime 2^18 for Target Sum Encoding
fn bench_lifetime18_target_sum(c: &mut Criterion) {
    benchmark_signature_scheme::<SIGTargetSumLifetime18W1NoOff>(
        c,
        "Target Sum, Lifetime 2^18, w = 1, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime18W1Off10>(
        c,
        "Target Sum, Lifetime 2^18, w = 1, 10% offset",
    );

    benchmark_signature_scheme::<SIGTargetSumLifetime18W2NoOff>(
        c,
        "Target Sum, Lifetime 2^18, w = 2, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime18W2Off10>(
        c,
        "Target Sum, Lifetime 2^18, w = 2, 10% offset",
    );

    benchmark_signature_scheme::<SIGTargetSumLifetime18W4NoOff>(
        c,
        "Target Sum, Lifetime 2^18, w = 4, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime18W4Off10>(
        c,
        "Target Sum, Lifetime 2^18, w = 4, 10% offset",
    );

    benchmark_signature_scheme::<SIGTargetSumLifetime18W8NoOff>(
        c,
        "Target Sum, Lifetime 2^18, w = 8, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime18W8Off10>(
        c,
        "Target Sum, Lifetime 2^18, w = 8, 10% offset",
    );
}

/// Benchmarking Lifetime 2^20 for Target Sum Encoding
fn bench_lifetime20_target_sum(c: &mut Criterion) {
    benchmark_signature_scheme::<SIGTargetSumLifetime20W1NoOff>(
        c,
        "Target Sum, Lifetime 2^20, w = 1, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime20W1Off10>(
        c,
        "Target Sum, Lifetime 2^20, w = 1, 10% offset",
    );

    benchmark_signature_scheme::<SIGTargetSumLifetime20W2NoOff>(
        c,
        "Target Sum, Lifetime 2^20, w = 2, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime20W2Off10>(
        c,
        "Target Sum, Lifetime 2^20, w = 2, 10% offset",
    );

    benchmark_signature_scheme::<SIGTargetSumLifetime20W4NoOff>(
        c,
        "Target Sum, Lifetime 2^20, w = 4, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime20W4Off10>(
        c,
        "Target Sum, Lifetime 2^20, w = 4, 10% offset",
    );

    benchmark_signature_scheme::<SIGTargetSumLifetime20W8NoOff>(
        c,
        "Target Sum, Lifetime 2^20, w = 8, no offset",
    );
    benchmark_signature_scheme::<SIGTargetSumLifetime20W8Off10>(
        c,
        "Target Sum, Lifetime 2^20, w = 8, 10% offset",
    );
}

pub fn bench_function_sha(c: &mut Criterion) {
    // benchmarking lifetime 2^18 - Winternitz
    bench_lifetime18_winternitz(c);

    // benchmarking lifetime 2^18 - Target Sum
    bench_lifetime18_target_sum(c);

    // benchmarking lifetime 2^20 - Winternitz
    bench_lifetime20_winternitz(c);

    // benchmarking lifetime 2^20 - Target Sum
    bench_lifetime20_target_sum(c);
}
