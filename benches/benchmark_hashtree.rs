use criterion::{BenchmarkId, Criterion};
use hashsig::symmetric::{
    tweak_hash::TweakableHash, tweak_hash::poseidon::PoseidonTweakHash, tweak_hash_tree::HashTree,
};
use p3_koala_bear::{KoalaBear, PackedKoalaBearNeon};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::hint::black_box;

type F = KoalaBear;
type P = PackedKoalaBearNeon;
type TestTH = PoseidonTweakHash<4, 4, 3, 9, 128>;
const HASH_LEN: usize = 4;
const TWEAK_LEN: usize = 3;

/// Benchmark HashTree::new vs new_packed across various challenging dimensions.
pub fn bench_function_hashtree(c: &mut Criterion) {
    let mut group = c.benchmark_group("HashTree: new vs new_packed");

    // Challenging configurations: (depth, num_leafs, start_index, description)
    let configs = [
        (16, 65536, 0, "large_dense"),
        (18, 10000, 100000, "sparse_high_offset"),
        (14, 12345, 1000, "medium_irregular"),
    ];

    for (depth, num_leafs, start_index, description) in configs {
        let seed = [42u8; 32];
        let parameter = TestTH::rand_parameter(&mut StdRng::from_seed(seed));

        // Generate leaf hashes
        let leafs_hashes: Vec<[F; HASH_LEN]> = (0..num_leafs)
            .map(|i| {
                let leaf = vec![TestTH::rand_domain(&mut StdRng::from_seed([i as u8; 32]))];
                TestTH::apply(
                    &parameter,
                    &TestTH::tree_tweak(0, (start_index + i) as u32),
                    &leaf,
                )
            })
            .collect();

        // // Benchmark scalar version
        // group.bench_function(BenchmarkId::new("scalar", description), |b| {
        //     b.iter(|| {
        //         let mut rng = StdRng::from_seed(seed);
        //         let tree = HashTree::<TestTH>::new(
        //             black_box(&mut rng),
        //             black_box(depth),
        //             black_box(start_index),
        //             black_box(&parameter),
        //             black_box(leafs_hashes.clone()),
        //         );
        //         black_box(tree);
        //     });
        // });

        // Benchmark packed (SIMD) version
        group.bench_function(BenchmarkId::new("packed", description), |b| {
            b.iter(|| {
                let mut rng = StdRng::from_seed(seed);

                // let tree = HashTree::<TestTH>::new(
                //     black_box(&mut rng),
                //     black_box(depth),
                //     black_box(start_index),
                //     black_box(&parameter),
                //     black_box(leafs_hashes.clone()),
                // );
                // black_box(tree);

                let tree = HashTree::<TestTH>::new_packed::<_, HASH_LEN, TWEAK_LEN>(
                    black_box(&mut rng),
                    black_box(depth),
                    black_box(start_index),
                    black_box(&parameter),
                    black_box(leafs_hashes.clone()),
                );
                black_box(tree);
            });
        });
    }

    group.finish();
}
