use crate::symmetric::tweak_hash::TweakableHash;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

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

/// Sub-tree of a sparse Hash-Tree based on a tweakable hashes.
/// We consider hash trees in which each leaf is first
/// hashed individually.
///
/// The tree can be sparse in the following sense:
/// There is a contiguous range of leafs that exist,
/// and the tree is built on top of that.
/// For instance, we may consider a tree of depth 32,
/// but only 2^{26} leafs really exist.
///
/// This struct may represent only a subtree of the full tree,
/// which may only contain the top layers of the tree.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct HashSubTree<TH: TweakableHash> {
    /// Depth of the full tree. The tree can have at most
    /// 1 << depth many leafs. The full tree has depth + 1
    /// many layers, whereas the sub-tree can have less.
    depth: usize,

    /// The lowest layer of the sub-tree. If this represents the
    /// full tree, then lowest_layer = 0.
    lowest_layer: usize,

    /// Layers of the hash tree, starting with the
    /// lowest_level. That is, layers[i] contains the nodes
    /// in level i + lowest_level of the tree. For the full tree
    /// (lowest_layer = 0), the leafs are not included: the
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

impl<TH> HashSubTree<TH>
where
    TH: TweakableHash,
{
    /// Function to compute a (sub-tree of a) hash-tree, which contains the top layers
    /// of a hash tree. The function takes the nodes in layer `lowest_layer` as input.
    /// They correspond to the (hashes of) the leafs if `lowest_layer = 0`.
    /// The full tree is assumed to have depth `depth`. Consequently, the full tree
    /// can have at most `1 << depth` many leafs and it has `depth + 1` layers.
    ///
    /// For the sub-tree that is generated, the number of `lowest_layer_nodes` cannot
    /// be more than `1 << (depth - lowest_layer)`.
    ///
    /// The lowest_layer nodes start at the given start index, namely, the nodes that
    /// exist in this layer are `start, start + 1, ... start + leafs.len() - 1`
    ///
    /// Caller must ensure that there is enough space for the leafs, i.e.,
    /// `start_index + leafs.len() <= 1 << (depth - lowest_layer)`
    ///
    /// Important: if this is used for the full tree (lowest_layer = 0), the leafs are
    /// expected to already be hashes. This is in to contrast to hash_tree_verify.
    ///
    /// Note: The RNG is used for generating nodes used for padding in the case of
    /// sparse trees. They could as well be fixed, and hence the RNG does not need
    /// to be cryptographically secure for this function.
    pub fn new_subtree<R: Rng>(
        rng: &mut R,
        lowest_layer: usize,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        lowest_layer_nodes: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            lowest_layer < depth,
            "Hash-Tree new: lowest_layer exceeds depth. Ensure that it is between 0 and depth - 1."
        );

        assert!(
            start_index + lowest_layer_nodes.len() <= 1 << (depth - lowest_layer),
            "Hash-Tree new: Not enough space for lowest layer nodes. Consider changing start_index or number of lowest layer nodes."
        );

        // we build the tree from the lowest layer to the root,
        // while building the tree, we ensure that the following two invariants hold via appropriate padding:
        // 1. the layer starts at an even index, i.e., a left child
        // 2. the layer ends at an odd index, i.e., a right child (does not hold for the root layer)
        // In this way, we can ensure that we can always hash two siblings to get their parent
        // The padding is ensured using the helper function `get_padded_layer`.

        let mut layers = Vec::with_capacity(depth + 1 - lowest_layer);

        // start with the lowest layer, padded accordingly
        layers.push(HashTreeLayer::padded(rng, lowest_layer_nodes, start_index));

        // now, build the tree layer by layer
        for level in lowest_layer..depth {
            // Previous layer (already padded so len is even and start_index is even)
            let prev = &layers[level - lowest_layer];

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

        Self {
            depth,
            lowest_layer,
            layers,
        }
    }

    /// Function to compute a top sub-tree of a tree of even depth.
    /// The top tree contains only the top layers, starting with layer
    /// depth / 2, and ending with the root of the full tree, which is layer depth + 1.
    ///
    /// It takes as input the roots of all 2^{depth/2} bottom trees. Note that these are
    /// exactly the nodes in layer depth / 2. The `start_index` indicates which bottom tree
    /// is the first that is given. It be in [0, 2^{depth/2}).
    pub fn new_top_tree<R: Rng>(
        rng: &mut R,
        depth: usize,
        start_index: usize,
        parameter: &TH::Parameter,
        roots_of_bottom_trees: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            depth.is_multiple_of(2),
            "Hash-Tree new top tree: Depth must be even."
        );

        // the top tree is just the sub-tree that starts at layer depth / 2, and contains
        // the roots of the bottom trees in the lowest layer.
        let lowest_layer = depth / 2;
        let lowest_layer_nodes = roots_of_bottom_trees;
        Self::new_subtree(
            rng,
            lowest_layer,
            depth,
            start_index,
            parameter,
            lowest_layer_nodes,
        )
    }

    /// Function to compute a bottom sub-tree of a tree of even depth.
    /// This is a tree containing 2^{depth/2} leafs, which are at positions
    /// bottom_tree_index * 2^{depth/2}, ... (bottom_tree_index + 1) * 2^{depth/2} - 1
    pub fn new_bottom_tree(
        depth: usize,
        bottom_tree_index: usize,
        parameter: &TH::Parameter,
        leafs: Vec<TH::Domain>,
    ) -> Self {
        assert!(
            depth > 2 && depth.is_multiple_of(2),
            "Hash-Tree new bottom tree: Depth must be even and more than 2."
        );

        assert!(
            leafs.len() == 1 << (depth / 2),
            "Hash-Tree new bottom tree: Bottom trees must be full, not sparse."
        );

        // note that this bottom tree will have no padding due to the previous
        // assert this means we can instantiate the RNG used in new_subtree with some
        // dummy RNG, because it will never be used. More precisely, all padding nodes
        // that will be generated in new_subtree will be removed below.
        //
        // Also, even if there were dummy nodes, it is not critical for security
        // that they are generated by a good PRG, they could be fixed as well.
        let mut dummy_rng = StdRng::seed_from_u64(0);

        // we first compute the bottom tree as if it was a sparse tree, i.e.,
        // as if we were to compute the full tree but only this bottom tree part was filled.
        let leafs_per_bottom_tree = 1 << (depth / 2);
        let lowest_layer = 0;
        let lowest_layer_nodes = leafs;
        let start_index = bottom_tree_index * leafs_per_bottom_tree;
        let mut bottom_tree = Self::new_subtree(
            &mut dummy_rng,
            lowest_layer,
            depth,
            start_index,
            parameter,
            lowest_layer_nodes,
        );

        // Now, note that the bottom_tree contains dummy nodes for the top depth/2 + 1 layers,
        // These notes are incompatible with the other bottom trees, so we need to make sure that we remove
        // them. We also make sure the root is alone in its layer so that the root() function works.
        let bottom_tree_root = bottom_tree.layers[depth / 2].nodes[bottom_tree_index % 2];
        bottom_tree.layers.truncate(depth / 2);
        bottom_tree.layers.push(HashTreeLayer {
            start_index: bottom_tree_index,
            nodes: vec![bottom_tree_root],
        });

        bottom_tree
    }

    /// Function to get a sub-tree root from a sub-tree.
    /// The tree must have at least one layer.
    #[must_use]
    pub fn root(&self) -> TH::Domain {
        self.layers
            .last()
            .expect("Hash-Tree must have at least one layer")
            .nodes[0]
    }

    /// Function to compute the Merkle authentication path
    /// from a sub-tree and the position of the node in the lowest layer.
    /// It is assumed that the tree is well-formed, i.e., each layer is half
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
        for l in 0..(self.depth - self.lowest_layer) {
            // if we are already at the root, we can stop (this is a special case for bottom trees)
            if self.layers[l].nodes.len() <= 1 {
                break;
            }
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

/// Function to compute a Merkle authentication path from a tree that is
/// splitted into top tree and bottom trees.
pub fn combined_path<TH: TweakableHash>(
    top_tree: &HashSubTree<TH>,
    bottom_tree: &HashSubTree<TH>,
    position: u32,
) -> HashTreeOpening<TH> {
    assert!(
        bottom_tree.depth == top_tree.depth,
        "Hash-Tree combined path: Bottom tree and top tree must have the same depth."
    );

    assert!(
        bottom_tree.depth.is_multiple_of(2),
        "Hash-Tree combined path: Tree depth must be even."
    );
    let depth = bottom_tree.depth;
    assert!(
        bottom_tree.layers[0]
            .start_index
            .is_multiple_of(1 << (depth / 2)),
        "Hash-Tree combined path: Bottom tree start index must be multiple of 1 << depth/2."
    );
    let bottom_tree_index = bottom_tree.layers[0].start_index / (1 << (depth / 2));

    // Note: other asserts are in path.

    // First, we compute the path for the bottom tree. Note that this contains
    // dummy elements in the top layers. We will remove them below.
    let bottom_opening = bottom_tree.path(position);

    // Now, we compute the path for the top tree. Intuitively, this authenticates
    // the root of the bottom tree.
    let top_opening = top_tree.path(bottom_tree_index as u32);

    // Finally, we combine them.
    let co_path = [bottom_opening.co_path, top_opening.co_path].concat();

    HashTreeOpening { co_path }
}

/// Function to verify an Merkle authentication path
/// with respect to a root, a position, and a leaf.
///
/// Note: this function expects the leaf to be a list of hashes,
/// whereas `new` expects each leaf to be a single hash,
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
        let tree = HashSubTree::<TestTH>::new_subtree(
            &mut rng,
            0,
            depth,
            start_index,
            &parameter,
            leafs_hashes,
        );

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

    /// We test that the following honest procedure succeeds:
    /// (1) build the Merkle tree to get the root,
    /// (2) build an authentication path for the leaf,
    /// (3) verify the authentication path with respect to leaf and root
    ///
    /// This is tested for the approach that first builds all bottom trees,
    /// and then the top tree on top of that. And it computes the Merkle
    /// authentication paths using the combined path function.
    fn test_commit_open_helper_top_bottom(
        num_bottom_trees: usize,
        depth: usize,
        start_bottom_tree_index: usize,
        leaf_len: usize,
    ) {
        // sample a random parameter and leafs
        let mut rng = rand::rng();
        let parameter = TestTH::rand_parameter(&mut rng);

        let leafs_per_bottom_tree = 1 << (depth / 2);
        let num_leafs = num_bottom_trees * leafs_per_bottom_tree;
        let start_index = start_bottom_tree_index * leafs_per_bottom_tree;
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

        // Now, we build the hash tree. To this end, we first build all bottom trees.
        let mut bottom_trees = Vec::with_capacity(num_bottom_trees);
        let mut roots_of_bottom_trees = Vec::with_capacity(num_bottom_trees);
        for bottom_tree_index in
            start_bottom_tree_index..(start_bottom_tree_index + num_bottom_trees)
        {
            // compute a bottom tree, which is for 1 << depth/2 many leafs
            let leafs_start = (bottom_tree_index - start_bottom_tree_index) * leafs_per_bottom_tree;
            let leafs_end = leafs_start + leafs_per_bottom_tree;
            let bottom_tree = HashSubTree::<TestTH>::new_bottom_tree(
                depth,
                bottom_tree_index,
                &parameter,
                leafs_hashes[leafs_start..leafs_end].to_vec(),
            );
            roots_of_bottom_trees.push(bottom_tree.root());
            bottom_trees.push(bottom_tree);
        }
        // We now build the top tree using the roots of the bottom trees
        let top_tree = HashSubTree::<TestTH>::new_top_tree(
            &mut rng,
            depth,
            start_bottom_tree_index,
            &parameter,
            roots_of_bottom_trees,
        );

        // now compute a commitment, i.e., Merkle root of the top tree
        let root = top_tree.root();

        // now check that opening and verification works as expected. We iterate over each bottom tree, and
        // over each leaf in that bottom tree. Then, we compute an authentication path and verify it.
        for bottom_tree_index in
            start_bottom_tree_index..(start_bottom_tree_index + num_bottom_trees)
        {
            let leafs_start = (bottom_tree_index - start_bottom_tree_index) * leafs_per_bottom_tree;
            let bottom_tree = &bottom_trees[bottom_tree_index - start_bottom_tree_index];

            for l in 0..leafs_per_bottom_tree {
                // calculate the position and get the leaf
                let offset = leafs_start + l;
                let leaf = leafs[offset].clone();
                let position = start_index as u32 + offset as u32;
                // compute the path using the combined_path function
                let path = combined_path(&top_tree, bottom_tree, position);
                // assert that the path verifies
                assert!(hash_tree_verify(&parameter, &root, position, &leaf, &path));
            }
        }
    }

    #[test]
    fn test_commit_open_verify_full_tree_top_bottom() {
        let num_bottom_trees = 4;
        let depth = 4;
        let start_bottom_tree_index: usize = 0;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_half_tree_left_top_bottom() {
        let num_bottom_trees = 8;
        let depth = 8;
        let start_bottom_tree_index: usize = 0;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_half_tree_right_top_bottom() {
        let num_bottom_trees = 8;
        let depth = 8;
        let start_bottom_tree_index: usize = 8;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }

    #[test]
    fn test_commit_open_verify_middle_tree_right_top_bottom() {
        let num_bottom_trees = 7;
        let depth = 8;
        let start_bottom_tree_index: usize = 4;
        let leaf_len = 3;
        test_commit_open_helper_top_bottom(
            num_bottom_trees,
            depth,
            start_bottom_tree_index,
            leaf_len,
        );
    }
}
