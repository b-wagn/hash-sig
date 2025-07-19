use crate::symmetric::tweak_hash::TweakableHash;
use rand::Rng;
use rayon::prelude::*;

/// A single layer of a sparse Hash-Tree
/// based on tweakable hash function
struct HashTreeLayer<TH: TweakableHash> {
    start_index: usize,
    nodes: Vec<TH::Domain>,
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
pub struct HashTreeOpening<TH: TweakableHash> {
    /// The co-path needed to verify
    /// If the tree has depth h, i.e, 2^h leafs
    /// the co-path should have size D
    co_path: Vec<TH::Domain>,
}

/// Helper function. Computes a padded layer from the meaningful entries of the layer.
/// These meaningful entries are assumed to range from start_index to start_index + nodes.len() - 1 (both inclusive).
fn get_padded_layer<R: Rng, TH: TweakableHash>(
    rng: &mut R,
    nodes: Vec<TH::Domain>,
    start_index: usize,
) -> HashTreeLayer<TH> {
    let end_index = start_index + nodes.len() - 1;

    let mut nodes_with_padding = vec![];

    // padding in front if start_index is not even
    if start_index % 2 == 1 {
        nodes_with_padding.push(TH::rand_domain(rng));
    }
    let actual_start_index = start_index - (start_index % 2);

    // now add the actual content
    nodes_with_padding.extend(nodes);

    // add padding if end_index is not odd
    if end_index % 2 == 0 {
        nodes_with_padding.push(TH::rand_domain(rng));
    }

    HashTreeLayer {
        start_index: actual_start_index,
        nodes: nodes_with_padding,
    }
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

        let mut layers: Vec<HashTreeLayer<TH>> = Vec::with_capacity(depth + 1);

        // start with the leaf layer, padded accordingly
        layers.push(get_padded_layer(rng, leafs_hashes, start_index));

        // now, build the tree layer by layer
        for level in 0..depth {
            // build layer `level + 1` from layer `level`

            // for that, we first build the parents of the previous layer and then
            // add a padding if needed. We build the parents in parallel.
            // assert!(layers[level].nodes.len()% 2 == 0);
            let parents: Vec<_> = layers[level]
                .nodes
                .par_chunks(2)
                .enumerate()
                .map(|(i, children)| {
                    assert!(
                        children.len() == 2,
                        "Unpaired children, padding logic broken"
                    );
                    let position_of_left_child = layers[level].start_index + 2 * i;
                    let parent_pos = position_of_left_child / 2;
                    let tweak = TH::tree_tweak((level + 1) as u8, parent_pos as u32);
                    TH::apply(parameter, &tweak, children)
                })
                .collect();

            let start_index = layers[level].start_index / 2;
            layers.push(get_padded_layer(rng, parents, start_index));
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
        let children = if current_position % 2 == 0 {
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
}
