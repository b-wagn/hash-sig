use criterion::{criterion_group, criterion_main};

mod benchmark_hashtree;
mod benchmark_poseidon;
mod benchmark_poseidon_top_level;
// mod benchmark_sha;

use benchmark_hashtree::bench_function_hashtree;
use benchmark_poseidon::bench_function_poseidon;
use benchmark_poseidon_top_level::bench_function_poseidon_top_level;
// use benchmark_sha::bench_function_sha;

criterion_group!(
    benches,
    // bench_function_poseidon_top_level,
    // bench_function_sha,
    // bench_function_poseidon
    bench_function_hashtree // Uncomment to run hashtree benchmarks
);
criterion_main!(benches);
