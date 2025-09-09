use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use num_bigint::BigUint;
use num_traits::One;
use num_traits::ToPrimitive;
use num_traits::Zero;
use std::cmp::min;
use std::ops::RangeInclusive;
use std::sync::LazyLock;

/// Max dimension precomputed for layer sizes.
const MAX_DIMENSION: usize = 100;

/// Holds the sizes of each layer and their cumulative sums (prefix sums).
///
/// This structure is precomputed and cached to accelerate lookups.
#[derive(Clone, Default)]
struct LayerInfo {
    /// The number of vertices in each layer `d`.
    sizes: Vec<BigUint>,
    /// The cumulative number of vertices up to and including layer `d`.
    ///
    /// `prefix_sums[d] = sizes[0] + ... + sizes[d]`.
    prefix_sums: Vec<BigUint>,
}

impl LayerInfo {
    /// Sum of `sizes` in inclusive `range`, calculated by subtraction of
    /// `prefix_sums`.
    ///
    /// Equal to `sizes[range].iter().sum()`.
    fn sizes_sum_in_range(&self, range: RangeInclusive<usize>) -> BigUint {
        if *range.start() == 0 {
            self.prefix_sums[*range.end()].clone()
        } else {
            &self.prefix_sums[*range.end()] - &self.prefix_sums[range.start() - 1]
        }
    }
}

/// A vector of `LayerInfo`, indexed by the dimension `v`.
/// This is meant to be used for a fixed base `w`.
type AllLayerInfoForBase = Vec<LayerInfo>;

/// Global cache for layer info (sizes and prefix sums) for each base `w`.
static ALL_LAYER_INFO_OF_BASE: LazyLock<DashMap<usize, AllLayerInfoForBase>> =
    LazyLock::new(DashMap::new);

/// Provides thread-safe, on-demand access to the cached layer data for a given base `w`.
///
/// It ensures that the expensive computation to prepare layer info is only run once per `w`.
struct AllLayerData<'a>(Ref<'a, usize, AllLayerInfoForBase>);

impl AllLayerData<'_> {
    fn new(w: usize) -> Self {
        // Atomically get or compute the layer info for the given base `w`.
        ALL_LAYER_INFO_OF_BASE
            .entry(w)
            .or_insert_with(|| prepare_layer_info(w));
        Self(ALL_LAYER_INFO_OF_BASE.get(&w).unwrap())
    }

    /// Gets the `LayerInfo` of dimension `v`.
    #[allow(dead_code)]
    fn layer_info_for_dimension(&self, v: usize) -> &LayerInfo {
        &self.0[v]
    }

    /// Gets the raw layer sizes for dimension `v`.
    fn sizes(&self, v: usize) -> &Vec<BigUint> {
        &self.0[v].sizes
    }

    /// Gets the precomputed prefix sums for dimension `v`.
    fn prefix_sums(&self, v: usize) -> &Vec<BigUint> {
        &self.0[v].prefix_sums
    }
}

/// Computes layer sizes and prefix sums for hypercubes [0, w-1]^v for all
/// v up to `MAX_DIMENSION` by Lemma 8 in eprint 2025/889.
/// This is the main precomputation step.
fn prepare_layer_info(w: usize) -> AllLayerInfoForBase {
    let v_max = MAX_DIMENSION;
    // Initialize with empty LayerInfo. Index 0 is unused for convenience.
    let mut all_info = vec![LayerInfo::default(); v_max + 1];

    // Base case: dimension v = 1
    let dim1_sizes = vec![BigUint::one(); w];
    // Compute prefix sums for v=1, which is just [1, 2, 3, ... w].
    let dim1_prefix_sums = (1..=w).map(BigUint::from).collect();
    all_info[1] = LayerInfo {
        sizes: dim1_sizes,
        prefix_sums: dim1_prefix_sums,
    };

    // Inductive step: compute for dimensions v = 2 to v_max
    for v in 2..=v_max {
        let max_d = (w - 1) * v;

        // Compute the sizes for the current dimension `v`.
        let current_sizes: Vec<BigUint> = (0..=max_d)
            .map(|d| {
                let a_i_start = (w.saturating_sub(d)).max(1);
                let a_i_end = min(w, w + (w - 1) * (v - 1) - d);

                // If the summation range is invalid, the layer size is zero.
                if a_i_start > a_i_end {
                    return BigUint::zero();
                }

                // Map the range for `a_i` to a range for `d'` in the previous dimension.
                let d_prime_start = d - (w - a_i_start);
                let d_prime_end = d - (w - a_i_end);

                // Sum over the relevant slice of the previous dimension's layer sizes.
                all_info[v - 1].sizes_sum_in_range(d_prime_start..=d_prime_end)
            })
            .collect();

        // Compute prefix sums from the newly calculated sizes.
        let mut current_prefix_sums = Vec::with_capacity(max_d + 1);
        let mut current_sum = BigUint::zero();
        for size in &current_sizes {
            current_sum += size;
            current_prefix_sums.push(current_sum.clone());
        }

        // Store both sizes and prefix sums in our final structure.
        all_info[v] = LayerInfo {
            sizes: current_sizes,
            prefix_sums: current_prefix_sums,
        };
    }

    all_info
}

/// Map an integer x in [0, layer_size(v, d)) to a vertex in layer d
/// of the hypercube [0, w-1]^v.
///
/// The vector that is returned has length v.
///
/// # Panics
///
/// Panics if `d` is not a valid layer. Valid layer means `0 <= d <= v * (w-1)`
/// Panics if `x` is larger than hypercube's size: `x >= w^v`.
#[must_use]
pub fn map_to_vertex(w: usize, v: usize, d: usize, x: BigUint) -> Vec<u8> {
    let mut x_curr = x;
    let mut out = Vec::with_capacity(v);
    let mut d_curr = d;

    let layer_data = AllLayerData::new(w);
    assert!(x_curr < layer_data.sizes(v)[d]);

    for i in 1..v {
        let mut ji = usize::MAX;
        let range_start = d_curr.saturating_sub((w - 1) * (v - i));

        for j in range_start..=min(w - 1, d_curr) {
            let count = &layer_data.sizes(v - i)[d_curr - j];
            if x_curr >= *count {
                x_curr -= count;
            } else {
                ji = j;
                break;
            }
        }
        assert!(ji < w);
        let ai = w - ji - 1;
        out.push(ai as u8);
        d_curr -= w - 1 - ai;
    }

    // layer_data no longer used beyond this point
    drop(layer_data);

    let x_curr = x_curr.to_usize().unwrap();
    assert!(x_curr + d_curr < w);
    out.push((w - 1 - x_curr - d_curr) as u8);
    out
}

/// Map a vertex `a` in layer `d` to its index x in [0, layer_size(v, d)).
///
/// # Panics
///
/// Panics if `d` is not a valid layer. Valid layer means`0 <= d <= v * (w-1)`,
/// Panics if `a` is not on layer `d`.
#[allow(dead_code)]
pub fn map_to_integer(w: usize, v: usize, d: usize, a: &[u8]) -> BigUint {
    assert_eq!(a.len(), v);
    let mut x_curr = BigUint::zero();
    let mut d_curr = w - 1 - a[v - 1] as usize;

    // Use only once and drop immediately after loop
    {
        let layer_data = AllLayerData::new(w);

        for i in (0..v - 1).rev() {
            let ji = w - 1 - a[i] as usize;
            d_curr += ji;
            let j_start = d_curr.saturating_sub((w - 1) * (v - i - 1));
            x_curr += layer_data
                .layer_info_for_dimension(v - i - 1)
                .sizes_sum_in_range(d_curr - ji + 1..=d_curr - j_start);
        }
    }

    assert_eq!(d_curr, d);
    x_curr
}

/// Returns the total size of layers 0 to d (inclusive) in hypercube [0, w-1]^v.
///
/// # Panics
///
/// Panics if `d` is not a valid layer. Valid layer means `0 <= d <= v * (w-1)`.
#[must_use]
pub fn hypercube_part_size(w: usize, v: usize, d: usize) -> BigUint {
    // With precomputed prefix sums, this is an efficient O(1) lookup.
    AllLayerData::new(w).prefix_sums(v)[d].clone()
}

/// Finds maximal d such that the total size L_<d of layers 0 to d-1 (inclusive) in hypercube [0, w-1]^v
/// is not bigger than x
///
/// Returns d and x-L_<d
///
/// # Panics
///
/// Panics if `x` is larger than hypercube's size: `x >= w^v`.
#[must_use]
pub fn hypercube_find_layer(w: usize, v: usize, x: BigUint) -> (usize, BigUint) {
    // Construct layer data once to avoid duplicate locking.
    let layer_data = AllLayerData::new(w);

    // Use it for both the assertion and the prefix sums access.
    let prefix_sums = layer_data.prefix_sums(v).clone();
    assert!(&x < prefix_sums.last().unwrap());

    // `partition_point` efficiently finds the index of the first element `p` for which `p > x`.
    // This index is the layer `d` where our value `x` resides.
    let d = prefix_sums.partition_point(|p| p <= &x);

    // Drop layer_data early to release lock, since it's no longer needed
    drop(layer_data);

    if d == 0 {
        // `x` is in the very first layer (d=0). The remainder is `x` itself,
        // as the cumulative size of preceding layers is zero.
        (0, x)
    } else {
        // The cumulative size of all layers up to `d-1` is at `prefix_sums[d - 1]`.
        // The remainder is `x` minus this cumulative size.
        let remainder = x - &prefix_sums[d - 1];
        (d, remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, BigUint};
    use num_traits::FromPrimitive;
    use num_traits::ToPrimitive;
    use num_traits::Zero;
    use proptest::prelude::*;
    use std::sync::Mutex;

    // Reference implementation for testing purposes
    fn prepare_layer_sizes_by_binom(w: usize) -> Vec<Vec<BigUint>> {
        /// Caches for binomial coefficients.
        static BINOMS: LazyLock<Mutex<Vec<Vec<BigUint>>>> = LazyLock::new(|| Mutex::new(vec![]));

        /// Precompute binomials n choose k for n up to v + (w-1)v
        fn precompute_binoms(v: usize, w: usize) {
            let max_distance = (w - 1) * v;
            let size = max_distance + v;
            let mut binoms = BINOMS.lock().unwrap();
            for n in binoms.len()..size {
                binoms.push(vec![BigUint::zero(); n + 1]);
                binoms[n][0] = BigUint::one();
                for k in 1..n {
                    binoms[n][k] = &binoms[n - 1][k - 1] + &binoms[n - 1][k];
                }
                binoms[n][n] = BigUint::one();
            }
        }

        /// Outputs the binomial coefficient binom(n, k) (n choose k)
        fn binom(n: usize, k: usize) -> BigUint {
            if k > n {
                return BigUint::zero();
            }
            let binoms = BINOMS.lock().unwrap();
            assert!(
                binoms.len() > n,
                "BINOMS cache is empty. Call precompute_local before calling binom."
            );
            binoms[n][k].clone()
        }

        /// Compute the number of integer vectors of dimension `n`,
        /// with entries in [0, m], that sum to `k`.
        /// Equivalent to coefficient of x^k in (1 + x + x^2 + ... + x^m)^n.
        ///
        /// This uses precomputed values if possible.
        fn nb(k: usize, m: usize, n: usize) -> BigUint {
            let mut sum = BigInt::zero();
            for s in 0..=k / (m + 1) {
                let part = binom(n, s) * binom(k - s * (m + 1) + n - 1, n - 1);
                let part = BigInt::from(part);
                if s % 2 == 0 {
                    sum += part;
                } else {
                    sum -= part;
                }
            }
            sum.to_biguint()
                .expect("nb result negative — check parameters")
        }

        let v_max = MAX_DIMENSION;
        precompute_binoms(v_max, w);

        let mut all_layers = vec![vec![]; v_max + 1];
        #[allow(clippy::needless_range_loop)]
        for v in 1..=v_max {
            let max_distance = (w - 1) * v;
            all_layers[v] = vec![BigUint::zero(); max_distance + 1];
            for d in 0..=max_distance {
                all_layers[v][d] = nb(d, w - 1, v);
            }
        }
        all_layers
    }

    #[test]
    fn test_prepare_layer_sizes() {
        for w in 2..13 {
            let expected_sizes = prepare_layer_sizes_by_binom(w);
            // Get the actual info from our new implementation.
            let actual_info = prepare_layer_info(w);
            // Compare just the `sizes` field against the reference implementation.
            for v in 1..=MAX_DIMENSION {
                assert_eq!(expected_sizes[v], actual_info[v].sizes);
            }
        }
    }

    #[test]
    fn test_maps() {
        let w = 4;
        let v = 8;
        let d = 20;
        let max_x = AllLayerData::new(w).sizes(v)[d]
            .clone()
            .to_usize()
            .expect("Conversion failed in test_maps");
        for x_usize in 0..max_x {
            let x = BigUint::from(x_usize);
            let a = map_to_vertex(w, v, d, x.clone());
            let layer: usize = a.iter().map(|&x| x as usize).sum();
            assert_eq!((w - 1) * v - layer, d);
            let y = map_to_integer(w, v, d, &a);
            let b = map_to_vertex(w, v, d, y.clone());
            assert_eq!(x, y);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_big_map() {
        let w = 12;
        let v = 40;
        let d = 174;
        let dec_string = b"21790506781852242898091207809690042074412";
        let x = BigUint::parse_bytes(dec_string, 10).expect("Invalid input");
        let a = map_to_vertex(w, v, d, x.clone());
        let y = map_to_integer(w, v, d, &a);
        let b = map_to_vertex(w, v, d, y.clone());
        assert_eq!(x, y);
        assert_eq!(a, b);
    }

    #[test]
    fn test_hypercube_part_size() {
        // Case 1: w = 2, v = 1
        //
        // All vectors are in [0,1]^1 = { [0], [1] }
        // Sum of coordinates:
        //   [1] has sum 1 ⇒ d = 0   (since d = (w-1)*v - sum)
        //   [0] has sum 0 ⇒ d = 1
        //
        // So:
        //   layer 0 (d = 0): [1] ⇒ size 1
        //   layer 1 (d = 1): [0] ⇒ size 1
        //
        // Total size up to d = 0: only [1]
        assert_eq!(hypercube_part_size(2, 1, 0), BigUint::from_u32(1).unwrap());

        // Total size up to d = 1: [1], [0]
        assert_eq!(hypercube_part_size(2, 1, 1), BigUint::from_u32(2).unwrap());

        // Case 2: w = 3, v = 2
        //
        // Vectors are in [0,2]^2, i.e. 9 total:
        //   [0,0]                  sum = 0 ⇒ d = 4
        //   [0,1], [1,0]           sum = 1 ⇒ d = 3
        //   [0,2], [1,1], [2,0]    sum = 2 ⇒ d = 2
        //   [1,2], [2,1]           sum = 3 ⇒ d = 1
        //   [2,2]                  sum = 4 ⇒ d = 0
        //
        // So:
        //   d = 0: 1 vec
        //   d = 1: 2 vecs
        //   d = 2: 3 vecs
        //   d = 3: 2 vecs
        //   d = 4: 1 vec
        //
        // Cumulative sizes:
        //   d = 0: 1
        //   d = 1: 1+2 = 3
        //   d = 2: 3+3 = 6
        //   d = 3: 6+2 = 8
        //   d = 4: 8+1 = 9
        assert_eq!(hypercube_part_size(3, 2, 0), BigUint::from_u32(1).unwrap());
        assert_eq!(hypercube_part_size(3, 2, 1), BigUint::from_u32(3).unwrap());
        assert_eq!(hypercube_part_size(3, 2, 2), BigUint::from_u32(6).unwrap());
        assert_eq!(hypercube_part_size(3, 2, 3), BigUint::from_u32(8).unwrap());
        assert_eq!(hypercube_part_size(3, 2, 4), BigUint::from_u32(9).unwrap());

        // Case 3: w = 4, v = 1
        //
        // [0], [1], [2], [3] → sums = 0..3, so d = 3..0
        //   d=0: [3]         → size = 1
        //   d=1: [2]         → size = 1
        //   d=2: [1]         → size = 1
        //   d=3: [0]         → size = 1
        //
        // Cumulative:
        //   d=0: 1
        //   d=1: 2
        //   d=2: 3
        //   d=3: 4
        assert_eq!(hypercube_part_size(4, 1, 0), BigUint::from_u32(1).unwrap());
        assert_eq!(hypercube_part_size(4, 1, 1), BigUint::from_u32(2).unwrap());
        assert_eq!(hypercube_part_size(4, 1, 2), BigUint::from_u32(3).unwrap());
        assert_eq!(hypercube_part_size(4, 1, 3), BigUint::from_u32(4).unwrap());

        // Case 4: w = 2, v = 3
        //
        // Vectors in [0,1]^3 = 8 total
        // Layer d = 3 - sum of entries
        //
        //   d = 0: [1,1,1]                          → 1 vector
        //   d = 1: [0,1,1], [1,0,1], [1,1,0]        → 3 vectors
        //   d = 2: [0,0,1], [0,1,0], [1,0,0]        → 3 vectors
        //   d = 3: [0,0,0]                          → 1 vector
        //
        // Cumulative:
        //   d = 0: 1
        //   d = 1: 1 + 3 = 4
        //   d = 2: 4 + 3 = 7
        //   d = 3: 7 + 1 = 8
        assert_eq!(hypercube_part_size(2, 3, 0), BigUint::from_u32(1).unwrap());
        assert_eq!(hypercube_part_size(2, 3, 1), BigUint::from_u32(4).unwrap());
        assert_eq!(hypercube_part_size(2, 3, 2), BigUint::from_u32(7).unwrap());
        assert_eq!(hypercube_part_size(2, 3, 3), BigUint::from_u32(8).unwrap());
    }

    #[test]
    fn test_find_layer_boundaries_small_fast() {
        let w = 3;
        let v = 2;

        // Case: x = 0 → should be in layer 0
        let (d0, rem0) = hypercube_find_layer(w, v, BigUint::zero());
        assert_eq!(d0, 0);
        assert_eq!(rem0, BigUint::zero());

        // Case: x = 1 → second vector overall, first in layer 1
        let (d1, rem1) = hypercube_find_layer(w, v, BigUint::from(1u32));
        assert_eq!(d1, 1);
        assert_eq!(rem1, BigUint::zero());

        // Case: x = 2 → second in layer 1
        let (d1b, rem1b) = hypercube_find_layer(w, v, BigUint::from(2u32));
        assert_eq!(d1b, 1);
        assert_eq!(rem1b, BigUint::from(1u32));

        // Case: x = 3 → first in layer 2
        let (d2, rem2) = hypercube_find_layer(w, v, BigUint::from(3u32));
        assert_eq!(d2, 2);
        assert_eq!(rem2, BigUint::zero());

        // Case: x = 5 → third (last) in layer 2
        let (d2b, rem2b) = hypercube_find_layer(w, v, BigUint::from(5u32));
        assert_eq!(d2b, 2);
        assert_eq!(rem2b, BigUint::from(2u32));

        // Case: x = 6 → first in layer 3
        let (d3, rem3) = hypercube_find_layer(w, v, BigUint::from(6u32));
        assert_eq!(d3, 3);
        assert_eq!(rem3, BigUint::zero());

        // Case: x = 8 → final vector (layer 4 has 1 element)
        let (d4, rem4) = hypercube_find_layer(w, v, BigUint::from(8u32));
        assert_eq!(d4, 4);
        assert_eq!(rem4, BigUint::zero());
    }

    proptest! {
        #[test]
        fn prop_map_vertex_roundtrip(
            w in 2usize..8,
            v in 1usize..16,
            x in 0u64..100_000,
        ) {
            // Compute the total number of vertices in the hypercube [0, w-1]^v
            let total_size = BigUint::from(w).pow(v as u32);

            // Convert the sampled integer x to BigUint
            let x_big = BigUint::from(x);

            // Skip values that exceed the total number of vertices in the hypercube
            prop_assume!(x_big < total_size);

            // Given a global index x, determine which layer it belongs to
            // and its offset within that layer.
            let (d, rem) = hypercube_find_layer(w, v, x_big);

            // Convert the offset `rem` in layer `d` to an actual vertex in [0, w-1]^v.
            let a = map_to_vertex(w, v, d, rem.clone());

            // Check that a lies in layer d
            let sum: usize = a.iter().map(|&ai| ai as usize).sum();
            prop_assert_eq!((w - 1) * v - sum, d);

            // Convert the vertex back to its local index in layer `d`.
            let y = map_to_integer(w, v, d, &a);

            // Double-check by mapping y back to the same vertex.
            let b = map_to_vertex(w, v, d, y.clone());

            // The index returned by `map_to_integer` should equal the original remainder.
            prop_assert_eq!(rem, y);

            // The vertex should be unchanged after round-tripping.
            prop_assert_eq!(a, b);
        }
    }
}
