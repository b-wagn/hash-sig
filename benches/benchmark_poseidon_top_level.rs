use criterion::{black_box, Criterion, SamplingMode};
use rand::{thread_rng, Rng};

use hashsig::{
    signature::{
        generalized_xmss::instantiations_poseidon_top_level::{
            lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim40Base12,
            lifetime_2_to_the_26::SIGTopLevelTargetSumLifetime26Dim64Base8,
        },
        SignatureScheme,
    },
    MESSAGE_LENGTH,
};

/// A template for benchmarking signature schemes (key gen, signing, verification)
pub fn benchmark_signature_scheme<S: SignatureScheme>(c: &mut Criterion, description: &str) {
    let mut group = c.benchmark_group(format!("Poseidon - Scheme: {}", description));

    // key gen takes long, so don't do that many repetitions
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    let mut rng = thread_rng();

    // Note: benchmarking key generation takes long, so it is
    // commented out for now. You can enable it here.

    #[cfg(feature = "with-gen-benches-poseidon-top-level")]
    group.bench_function(format!("- gen"), |b| {
        b.iter(|| {
            // Benchmark key generation
            let _ = S::gen(black_box(&mut rng), 0, S::LIFETIME as usize);
        });
    });

    group.sample_size(100);

    let (pk, sk) = S::gen(&mut rng, 0, S::LIFETIME as usize);

    group.bench_function(format!("- sign"), |b| {
        b.iter(|| {
            // Sample random test message
            let mut message = [0u8; MESSAGE_LENGTH];
            rng.fill(&mut message);

            // Sample random epoch
            let epoch = rng.gen_range(0..S::LIFETIME) as u32;

            // Benchmark signing
            let _ = S::sign(
                black_box(&mut rng),
                black_box(&sk),
                black_box(epoch),
                black_box(&message),
            );
        });
    });

    // Pre-generate messages, epochs, and signatures for verification
    let precomputed: Vec<(u32, [u8; MESSAGE_LENGTH], S::Signature)> = (0..2000)
        .map(|_| {
            let mut message = [0u8; MESSAGE_LENGTH];
            rng.fill(&mut message);
            let epoch = rng.gen_range(0..S::LIFETIME) as u32;
            let signature =
                S::sign(&mut rng, &sk, epoch, &message).expect("Signing should succeed");
            (epoch, message, signature)
        })
        .collect();

    // Verification benchmark
    group.bench_function(format!("- verify"), |b| {
        b.iter(|| {
            // Randomly pick a precomputed signature to verify
            let (epoch, message, signature) =
                black_box(&precomputed[rng.gen_range(0..precomputed.len())]);
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
    // benchmarking lifetime 2^18
    benchmark_signature_scheme::<SIGTopLevelTargetSumLifetime18Dim40Base12>(
        c,
        "Top Level Target Sum, Lifetime 2^18, Dimension 40, Base 12",
    );

    // benchmarking lifetime 2^26
    benchmark_signature_scheme::<SIGTopLevelTargetSumLifetime26Dim64Base8>(
        c,
        "Top Level Target Sum, Lifetime 2^26, Dimension 64, Base 8",
    );
}
