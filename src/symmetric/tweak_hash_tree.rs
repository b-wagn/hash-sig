use crate::{
    F, P,
    symmetric::tweak_hash::{PackedTweakableHash, TweakableHash},
};
use core::array;
use p3_field::PackedValue;
use p3_field::PrimeCharacteristicRing;
use p3_field::{Field, PackedField};
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::any::{Any, TypeId};

/// A single layer of a sparse Hash-Tree
/// based on tweakable hash function
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
struct HashTreeLayer<TH: TweakableHash> {
    start_index: usize,
    nodes: Vec<TH::Domain>,
}

impl<TH: TweakableHash> HashTreeLayer<TH> {
    /// Construct a layer from a contiguous run of nodes and pad it so that:
    /// - the layer starts at an even index (a left child), and
    /// - the layer ends at an odd index (a right child).
    ///
    /// Input interpretation:
    /// - `nodes` conceptually occupy tree indices
    ///   `[start_index, start_index + nodes.len() - 1]` (inclusive).
    ///
    /// Padding rules:
    /// - If `start_index` is odd, we insert one random node in front and shift
    ///   the effective start to the previous even index.
    /// - If the end index is even, we append one random node at the back so the
    ///   final index is odd.
    ///
    /// Why this matters:
    /// - With this alignment every parent is formed from exactly two children,
    ///   so upper layers can be built with exact size-2 chunks, with no edge cases.
    #[inline]
    fn padded<R: Rng>(rng: &mut R, nodes: Vec<TH::Domain>, start_index: usize) -> Self {
        // End index of the provided contiguous run (inclusive).
        let end_index = start_index + nodes.len() - 1;

        // Do we need a front pad? Start must be even.
        let needs_front = (start_index & 1) == 1;

        // Do we need a back pad? End must be odd.
        let needs_back = (end_index & 1) == 0;

        // The effective start index after optional front padding (always even).
        let actual_start_index = start_index - (needs_front as usize);

        // Reserve exactly the space we may need: original nodes plus up to two pads.
        let mut out =
            Vec::with_capacity(nodes.len() + (needs_front as usize) + (needs_back as usize));

        // Optional front padding to align to an even start index.
        if needs_front {
            out.push(TH::rand_domain(rng));
        }

        // Insert the actual content in order.
        out.extend(nodes);

        // Optional back padding to ensure we end on an odd index.
        if needs_back {
            out.push(TH::rand_domain(rng));
        }

        // Return the padded layer with the corrected start index.
        Self {
            start_index: actual_start_index,
            nodes: out,
        }
    }
}

/// Sparse Hash-Tree based on a tweakable hash function.
/// We consider hash trees in which each leaf is first
/// hashed individually.
///
/// The tree can be sparse in the following sense:
/// There is a contiguous range of leafs that exist,
/// and the tree is built on top of that.
///
/// For instance, we may consider a tree of depth 32,
/// but only 2^{26} leafs really exist.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HashTree<TH: TweakableHash> {
    /// Depth of the tree. The tree can have at most
    /// 1 << depth many leafs. It has depth + 1 many layers
    depth: usize,
    /// Layers of the hash tree, starting with the
    /// bottom layer. The leafs are not included: the
    /// bottom layer is the list of hashes of all leafs
    layers: Vec<HashTreeLayer<TH>>,
}

/// Opening in a hash-tree: a co-path, without the leaf
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HashTreeOpening<TH: TweakableHash> {
    /// The co-path needed to verify
    /// If the tree has depth h, i.e, 2^h leafs
    /// the co-path should have size D
    co_path: Vec<TH::Domain>,
}

impl<TH> HashTree<TH>
where
    TH: TweakableHash,
{
    /// Function to compute a hash-tree given the leaf hashes as input.
    /// The tree will have the given depth, which bounds the number of leafs.
    /// It can have at most `1 << depth` many leafs. It has `depth + 1` layers.
    ///
    /// The leafs start at the given start index, namely, the leafs that exist
    /// are leafs `start, start + 1, ... start + leafs_hashes.len() - 1`
    ///
    /// Caller must ensure that there is enough space for the leaf hashes, i.e.,
    /// `start_index + leaf_hashes.len() <= 1 << depth`
    ///
    pub fn new<R: Rng>(
        rng: &mut R,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        leafs_hashes: Vec<TH::Domain>,
    ) -> Self {
        // check that number of leafs is a power of two
        assert!(
            start_index + leafs_hashes.len() <= 1 << depth,
            "Hash-Tree new: Not enough space for leafs. Consider changing start_index or number of leaf hashes"
        );

        // we build the tree from the leaf layer to the root,
        // while building the tree, we ensure that the following two invariants hold via appropriate padding:
        // 1. the layer starts at an even index, i.e., a left child
        // 2. the layer ends at an odd index, i.e., a right child (does not hold for the root layer)
        // In this way, we can ensure that we can always hash two siblings to get their parent
        // The padding is ensured using the helper function `get_padded_layer`.

        let mut layers = Vec::with_capacity(depth + 1);

        // start with the leaf layer, padded accordingly
        layers.push(HashTreeLayer::padded(rng, leafs_hashes, start_index));

        // now, build the tree layer by layer
        for level in 0..depth {
            // Previous layer (already padded so len is even and start_index is even)
            let prev = &layers[level];

            // Parent layer starts at half the previous start index
            let parent_start = prev.start_index >> 1;

            // Compute all parents in parallel, pairing children two-by-two
            //
            // We do exact chunks of two children, no remainder.
            let parents = prev
                .nodes
                .par_chunks_exact(2)
                .enumerate()
                .map(|(i, children)| {
                    // Parent index in this layer
                    let parent_pos = (parent_start + i) as u32;
                    // Hash children into their parent using the tweak
                    TH::apply(
                        parameter,
                        &TH::tree_tweak((level as u8) + 1, parent_pos),
                        children,
                    )
                })
                .collect();

            // Add the new layer with padding so next iteration also has even start and length
            layers.push(HashTreeLayer::padded(rng, parents, parent_start));
        }

        Self { depth, layers }
    }

    pub fn new_packed<R, const HASH_LEN: usize, const TWEAK_LEN: usize>(
        rng: &mut R,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        leafs_hashes: Vec<TH::Domain>,
    ) -> Self
    where
        R: Rng,
        TH: PackedTweakableHash<P, F>,
        TH::Domain: Copy + Default + AsRef<[F]> + AsMut<[F]>,
        [F; HASH_LEN]: Copy,
    {
        // check that number of leafs is a power of two
        assert!(
            start_index + leafs_hashes.len() <= 1 << depth,
            "Hash-Tree new_packed: Not enough space for leafs"
        );

        let mut layers = Vec::with_capacity(depth + 1);
        layers.push(HashTreeLayer::padded(rng, leafs_hashes, start_index));

        for level in 0..depth {
            // Previous layer (already padded so len is even and start_index is even)
            let prev = &layers[level];

            // Parent layer starts at half the previous start index
            let parent_start = prev.start_index >> 1;
            let num_parents = prev.nodes.len() / 2;

            // Initialize with default values
            let mut parents = vec![TH::Domain::default(); num_parents];

            // Process in chunks.
            parents.par_chunks_exact_mut(P::WIDTH).enumerate().for_each(
                |(chunk_idx, parent_chunk)| {
                    let first_parent_idx = chunk_idx * P::WIDTH;
                    let first_child_idx = 2 * first_parent_idx;

                    // Pack left children.
                    let left_packed: [P; HASH_LEN] = array::from_fn(|h_idx| {
                        P::from_fn(|lane_idx| {
                            <TH::Domain as AsRef<[F]>>::as_ref(
                                &prev.nodes[first_child_idx + 2 * lane_idx],
                            )[h_idx]
                        })
                    });

                    // Pack right children.
                    let right_packed: [P; HASH_LEN] = array::from_fn(|h_idx| {
                        P::from_fn(|lane_idx| {
                            <TH::Domain as AsRef<[F]>>::as_ref(
                                &prev.nodes[first_child_idx + 2 * lane_idx + 1],
                            )[h_idx]
                        })
                    });

                    // Pack parent positions
                    let positions_packed = P::from_fn(|lane_idx| {
                        F::from_u64((parent_start + first_parent_idx + lane_idx) as u64)
                    });

                    // Generate packed tweaks
                    let tweak_packed =
                        TH::tree_tweak_packed::<TWEAK_LEN>((level as u8) + 1, positions_packed);

                    // Compute packed parent hashes
                    let parent_hashes_packed = TH::apply_packed::<HASH_LEN, TWEAK_LEN>(
                        parameter,
                        tweak_packed,
                        left_packed,
                        right_packed,
                    );

                    // Unpack results back to scalar arrays
                    for (lane_idx, parent_domain) in parent_chunk.iter_mut().enumerate() {
                        let parent_arr = parent_domain.as_mut();
                        for h_idx in 0..HASH_LEN {
                            parent_arr[h_idx] = parent_hashes_packed[h_idx].as_slice()[lane_idx];
                        }
                    }
                },
            );

            // Handle remainder with scalar code
            let remainder_start = (num_parents / P::WIDTH) * P::WIDTH;
            for i in remainder_start..num_parents {
                let children = [prev.nodes[2 * i], prev.nodes[2 * i + 1]];
                let parent_pos = (parent_start + i) as u32;
                let tweak = TH::tree_tweak((level as u8) + 1, parent_pos);
                parents[i] = TH::apply(parameter, &tweak, &children);
            }
            layers.push(HashTreeLayer::padded(rng, parents, parent_start));
        }

        Self { depth, layers }
    }

    /// Function to get a root from a tree. The tree must have at least one layer.
    /// A root is just an output of the tweakable hash.
    #[must_use]
    pub fn root(&self) -> TH::Domain {
        self.layers
            .last()
            .expect("Hash-Tree must have at least one layer")
            .nodes[0]
    }

    /// Function to compute the Merkle authentication path
    /// from a tree and the position of the leaf. It is assumed
    /// that the tree is well-formed, i.e., each layer is half
    /// the size of the previous layer, and the final layer has
    /// size 1.
    #[must_use]
    pub fn path(&self, position: u32) -> HashTreeOpening<TH> {
        assert!(
            !self.layers.is_empty(),
            "Hash-Tree path: Need at least one layer"
        );
        assert!(
            (position as u64) >= (self.layers[0].start_index as u64),
            "Hash-Tree path: Invalid position, position before start index"
        );
        assert!(
            (position as u64)
                < (self.layers[0].start_index as u64 + self.layers[0].nodes.len() as u64),
            "Hash-Tree path: Invalid position, position too large"
        );

        // in our co-path, we will have one node per layer
        // except the final layer (which is just the root)
        let mut co_path = Vec::with_capacity(self.depth);
        let mut current_position = position;
        for l in 0..self.depth {
            // position of the sibling that we want to include
            let sibling_position = current_position ^ 0x01;
            let sibling_position_in_vec = sibling_position - self.layers[l].start_index as u32;
            // add to the co-path
            let sibling = self.layers[l].nodes[sibling_position_in_vec as usize];
            co_path.push(sibling);
            // new position in next layer
            current_position >>= 1;
        }

        HashTreeOpening { co_path }
    }
}

/// Function to verify an Merkle authentication path
/// with respect to a root, a position, and a leaf.
///
/// Note: this function expects the leaf to be a list of hashes,
/// whereas `build_tree` expects each leaf to be a single hash,
/// which should be the hash of this list of hashes.
pub fn hash_tree_verify<TH: TweakableHash>(
    parameter: &TH::Parameter,
    root: &TH::Domain,
    position: u32,
    leaf: &[TH::Domain],
    opening: &HashTreeOpening<TH>,
) -> bool {
    // given the length of the path, we know how
    // large the tree was. So we can check if the
    // position makes sense.
    let depth = opening.co_path.len();
    let num_leafs: u64 = 1 << depth;

    assert!(
        depth <= 32,
        "Hash-Tree verify: Tree depth must be at most 32"
    );

    assert!(
        (position as u64) < num_leafs,
        "Hash-Tree verify: Position and Path Length not compatible"
    );

    // first hash the leaf to get the node in the bottom layer
    let tweak = TH::tree_tweak(0, position);
    let mut current_node = TH::apply(parameter, &tweak, leaf);

    // now reconstruct the root using the co-path
    let mut current_position = position;
    for l in 0..depth {
        // Need to distinguish two cases, depending on
        // if current is a left child or a right child
        let children = if current_position.is_multiple_of(2) {
            // left child, so co-path contains the right sibling
            [current_node, opening.co_path[l]]
        } else {
            // right child, so co-path contains the left sibling
            [opening.co_path[l], current_node]
        };

        // determine new position, which is position of the parent
        current_position >>= 1;

        // now hash to get the parent
        let tweak = TH::tree_tweak((l + 1) as u8, current_position);
        current_node = TH::apply(parameter, &tweak, &children);
    }

    // Finally, check that recomputed root matches given root
    current_node == *root
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;

    use crate::symmetric::tweak_hash::sha::ShaTweak128192;

    use super::*;

    type TestTH = ShaTweak128192;

    /// We test that the following honest procedure succeeds:
    /// (1) build the Merkle tree to get the root,
    /// (2) build an authentication path for the leaf,
    /// (3) verify the authentication path with respect to leaf and root
    fn test_commit_open_helper(
        num_leafs: usize,
        depth: usize,
        start_index: usize,
        leaf_len: usize,
    ) {
        let mut rng = rand::rng();
        // sample a random parameter and leafs
        let parameter = TestTH::rand_parameter(&mut rng);

        let mut leafs = Vec::new();
        for _ in 0..num_leafs {
            let mut leaf = Vec::new();
            for _ in 0..leaf_len {
                leaf.push(TestTH::rand_domain(&mut rng));
            }
            leafs.push(leaf);
        }

        let leafs_hashes: Vec<_> = leafs
            .iter()
            .enumerate()
            .map(|(i, v)| {
                TestTH::apply(
                    &parameter,
                    &TestTH::tree_tweak(0, (i + start_index) as u32),
                    v.as_slice(),
                )
            })
            .collect();

        // Build the hash tree using the random parameter and leaves
        let tree = HashTree::<TestTH>::new(&mut rng, depth, start_index, &parameter, leafs_hashes);

        // now compute a commitment, i.e., Merkle root
        let root = tree.root();

        // now check that opening and verification works as expected
        for (offset, leaf) in leafs.iter().enumerate().take(num_leafs) {
            // calculate the position
            let position = start_index as u32 + offset as u32;
            // first get the opening
            let path = tree.path(position);
            // now assert that it verifies
            assert!(hash_tree_verify(&parameter, &root, position, leaf, &path));
        }
    }

    #[test]
    fn test_commit_open_verify_full_tree() {
        let num_leafs = 1024;
        let depth = 10;
        let start_index: usize = 0;
        let leaf_len = 3;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_left() {
        let num_leafs = 512;
        let depth = 10;
        let start_index: usize = 0;
        let leaf_len = 5;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_large() {
        let num_leafs = 512;
        let depth = 10;
        let start_index: usize = 512;
        let leaf_len = 10;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_small() {
        let num_leafs = 2;
        let depth = 2;
        let start_index: usize = 2;
        let leaf_len = 6;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    #[test]
    fn test_commit_open_verify_sparse_non_aligned() {
        let num_leafs = 213;
        let depth = 10;
        let start_index: usize = 217;
        let leaf_len = 3;

        test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
    }

    proptest! {
        #[test]
        fn proptest_commit_open_verify(
            // Test with up to 32 leaf nodes (fast but nontrivial)
            num_leafs in 1usize..32,

            // Tree depth capped at 6 → supports up to 64 leaves
            depth in 3usize..7,

            // Start index limited to 0–64 (sparse trees, padded trees)
            start_index in 0usize..64,

            // Leaves with up to 5 elements (non-scalar values)
            leaf_len in 1usize..5,
        ) {
            // Make sure the leaves actually fit in the tree
            prop_assume!(start_index + num_leafs <= 1 << depth);

            test_commit_open_helper(num_leafs, depth, start_index, leaf_len);
        }
    }

    // Tests to verify that new and new_packed produce identical results
    mod packed_equivalence {
        use super::*;
        use crate::F;
        use crate::P; // PackedKoalaBearNeon
        use crate::symmetric::tweak_hash::poseidon::PoseidonTweak44; // KoalaBear

        type TestTH = PoseidonTweak44;
        const HASH_LEN: usize = 4;
        const TWEAK_LEN: usize = 3;

        /// Helper to compare two trees for equality
        fn trees_equal(tree1: &HashTree<TestTH>, tree2: &HashTree<TestTH>) -> bool {
            if tree1.depth != tree2.depth {
                return false;
            }
            if tree1.layers.len() != tree2.layers.len() {
                return false;
            }
            for (layer1, layer2) in tree1.layers.iter().zip(tree2.layers.iter()) {
                if layer1.start_index != layer2.start_index {
                    return false;
                }
                if layer1.nodes.len() != layer2.nodes.len() {
                    return false;
                }
                for (node1, node2) in layer1.nodes.iter().zip(layer2.nodes.iter()) {
                    if node1 != node2 {
                        return false;
                    }
                }
            }
            true
        }

        #[test]
        fn test_new_vs_new_packed_small_tree() {
            use rand::SeedableRng;
            use rand::rngs::StdRng;

            let seed = [42u8; 32];
            let parameter = TestTH::rand_parameter(&mut StdRng::from_seed(seed));

            let num_leafs = 16;
            let depth = 4;
            let start_index = 0;

            // Generate leaf hashes (deterministic, no RNG needed)
            let leafs_hashes: Vec<_> = (0..num_leafs)
                .map(|i| {
                    let leaf = vec![TestTH::rand_domain(&mut StdRng::from_seed([i as u8; 32]))];
                    TestTH::apply(
                        &parameter,
                        &TestTH::tree_tweak(0, (start_index + i) as u32),
                        &leaf,
                    )
                })
                .collect();

            // Build tree using scalar version (with fresh RNG for padding)
            let tree_scalar = HashTree::<TestTH>::new(
                &mut StdRng::from_seed(seed),
                depth,
                start_index,
                &parameter,
                leafs_hashes.clone(),
            );

            // Build tree using packed SIMD version (with same fresh RNG for padding)
            let tree_packed = HashTree::<TestTH>::new_packed::<_, HASH_LEN, TWEAK_LEN>(
                &mut StdRng::from_seed(seed),
                depth,
                start_index,
                &parameter,
                leafs_hashes,
            );

            // Verify they produce the same root
            assert_eq!(
                tree_scalar.root(),
                tree_packed.root(),
                "Roots should be identical"
            );

            // Verify entire tree structure is identical
            assert!(
                trees_equal(&tree_scalar, &tree_packed),
                "Trees should be identical"
            );
        }

        #[test]
        fn test_new_vs_new_packed_sparse_tree() {
            use rand::SeedableRng;
            use rand::rngs::StdRng;

            let seed = [43u8; 32];
            let parameter = TestTH::rand_parameter(&mut StdRng::from_seed(seed));

            let num_leafs = 50;
            let depth = 8;
            let start_index = 100;

            // Generate leaf hashes (deterministic)
            let leafs_hashes: Vec<_> = (0..num_leafs)
                .map(|i| {
                    let leaf = vec![TestTH::rand_domain(&mut StdRng::from_seed([i as u8; 32]))];
                    TestTH::apply(
                        &parameter,
                        &TestTH::tree_tweak(0, (start_index + i) as u32),
                        &leaf,
                    )
                })
                .collect();

            // Build tree using scalar version (with fresh RNG for padding)
            let tree_scalar = HashTree::<TestTH>::new(
                &mut StdRng::from_seed(seed),
                depth,
                start_index,
                &parameter,
                leafs_hashes.clone(),
            );

            // Build tree using packed SIMD version (with same fresh RNG for padding)
            let tree_packed = HashTree::<TestTH>::new_packed::<_, HASH_LEN, TWEAK_LEN>(
                &mut StdRng::from_seed(seed),
                depth,
                start_index,
                &parameter,
                leafs_hashes,
            );

            // Verify they produce the same root
            assert_eq!(
                tree_scalar.root(),
                tree_packed.root(),
                "Roots should be identical"
            );

            // Verify entire tree structure is identical
            assert!(
                trees_equal(&tree_scalar, &tree_packed),
                "Trees should be identical"
            );
        }

        #[test]
        fn test_new_vs_new_packed_paths_match() {
            use rand::SeedableRng;
            use rand::rngs::StdRng;

            let seed = [44u8; 32];
            let parameter = TestTH::rand_parameter(&mut StdRng::from_seed(seed));

            let num_leafs = 32;
            let depth = 5;
            let start_index = 0;

            // Generate leafs and their hashes (deterministic)
            let leafs: Vec<_> = (0..num_leafs)
                .map(|i| vec![TestTH::rand_domain(&mut StdRng::from_seed([i as u8; 32]))])
                .collect();

            let leafs_hashes: Vec<_> = leafs
                .iter()
                .enumerate()
                .map(|(i, leaf)| {
                    TestTH::apply(
                        &parameter,
                        &TestTH::tree_tweak(0, (start_index + i) as u32),
                        leaf,
                    )
                })
                .collect();

            // Build both trees (with fresh RNG for padding)
            let tree_scalar = HashTree::<TestTH>::new(
                &mut StdRng::from_seed(seed),
                depth,
                start_index,
                &parameter,
                leafs_hashes.clone(),
            );

            let tree_packed = HashTree::<TestTH>::new_packed::<_, HASH_LEN, TWEAK_LEN>(
                &mut StdRng::from_seed(seed),
                depth,
                start_index,
                &parameter,
                leafs_hashes,
            );

            // Verify authentication paths match for all leaves
            for (offset, leaf) in leafs.iter().enumerate() {
                let position = start_index as u32 + offset as u32;

                let path_scalar = tree_scalar.path(position);
                let path_packed = tree_packed.path(position);

                // Both paths should verify against their respective roots
                assert!(
                    hash_tree_verify(
                        &parameter,
                        &tree_scalar.root(),
                        position,
                        leaf,
                        &path_scalar
                    ),
                    "Scalar path should verify"
                );
                assert!(
                    hash_tree_verify(
                        &parameter,
                        &tree_packed.root(),
                        position,
                        leaf,
                        &path_packed
                    ),
                    "Packed path should verify"
                );

                // Paths should be identical
                assert_eq!(
                    path_scalar.co_path, path_packed.co_path,
                    "Co-paths should be identical for position {}",
                    position
                );
            }
        }

        proptest! {
            #[test]
            fn proptest_new_vs_new_packed(
                // Number of leaves (limited to keep tests fast)
                num_leafs in 8usize..64,

                // Tree depth (must be sufficient for the leaves)
                depth in 4usize..8,

                // Start index for sparse trees
                start_index in 0usize..32,

                // Random seed for deterministic generation
                seed in prop::array::uniform32(prop::num::u8::ANY),
            ) {
                use rand::SeedableRng;
                use rand::rngs::StdRng;

                // Make sure the leaves actually fit in the tree
                prop_assume!(start_index + num_leafs <= 1 << depth);

                let parameter = TestTH::rand_parameter(&mut StdRng::from_seed(seed));

                // Generate leaf hashes (deterministic based on index)
                let leafs_hashes: Vec<_> = (0..num_leafs)
                    .map(|i| {
                        let leaf = vec![TestTH::rand_domain(&mut StdRng::from_seed([i as u8; 32]))];
                        TestTH::apply(&parameter, &TestTH::tree_tweak(0, (start_index + i) as u32), &leaf)
                    })
                    .collect();

                // Build both trees (with same fresh RNG for padding)
                let tree_scalar = HashTree::<TestTH>::new(
                    &mut StdRng::from_seed(seed),
                    depth,
                    start_index,
                    &parameter,
                    leafs_hashes.clone(),
                );

                let tree_packed = HashTree::<TestTH>::new_packed::<_, HASH_LEN, TWEAK_LEN>(
                    &mut StdRng::from_seed(seed),
                    depth,
                    start_index,
                    &parameter,
                    leafs_hashes,
                );

                // Verify roots match
                prop_assert_eq!(tree_scalar.root(), tree_packed.root());

                // Verify trees are structurally identical
                prop_assert!(trees_equal(&tree_scalar, &tree_packed));
            }
        }
    }
}
