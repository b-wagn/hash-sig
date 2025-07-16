use crate::symmetric::tweak_hash::TweakableHash;
use rayon::prelude::*;

/// Hash-Tree based on a tweakable hash function
/// We consider hash trees in which each leaf is first
/// hashed individually.
pub struct HashTree<TH: TweakableHash> {
    /// Layers of the hash tree, starting with the
    /// bottom layer. The leafs are not included: the
    /// bottom layer is the list of hashes of all leafs
    layers: Vec<Vec<TH::Domain>>,
}

impl<TH> HashTree<TH>
where
    TH: TweakableHash,
{
    /// Function to compute a hash-tree given the leaf hashes as input.
    /// The number of leaf hashes must be a power of two.
    pub fn new(parameter: &TH::Parameter, leafs_hashes: Vec<TH::Domain>) -> Self {
        // check that number of leafs is a power of two
        assert!(
            leafs_hashes.len().is_power_of_two(),
            "Hash-Tree build_tree: Number of leafs should be power of two"
        );

        let mut layer_size = leafs_hashes.len();
        let mut layers: Vec<Vec<TH::Domain>> = Vec::with_capacity(layer_size.ilog2() as usize + 1);

        // the bottom layer contains the individual hashes of all leafs
        layers.push(leafs_hashes);

        // now, we build each layer by hashing pairs in the previous layer
        let mut level: u8 = 1;
        while layer_size >= 2 {
            // this new layer will have half the size
            layer_size /= 2;
            // parallelize the two to one compressions
            layers.push(
                (0..layer_size)
                    .into_par_iter()
                    .map(|i| {
                        let left_idx = 2 * i;
                        let right_idx = 2 * i + 1;
                        let tweak = TH::tree_tweak(level, i as u32);
                        let children = &layers[(level - 1) as usize][left_idx..=right_idx];
                        TH::apply(parameter, &tweak, children)
                    })
                    .collect(),
            );
            level += 1;
        }

        Self { layers }
    }

    /// Function to get a root from a tree. The tree must have at least one layer.
    /// A root is just an output of the tweakable hash.
    pub fn root(&self) -> TH::Domain {
        self.layers
            .last()
            .expect("Hash-Tree must have at least one layer")[0]
    }

    /// Function to compute the Merkle authentication path
    /// from a tree and the position of the leaf. It is assumed
    /// that the tree is well-formed, i.e., each layer is half
    /// the size of the previous layer, and the final layer has
    /// size 1.
    pub fn path(&self, position: u32) -> HashTreeOpening<TH> {
        assert!(
            !self.layers.is_empty(),
            "Hash-Tree hash tree path: Need at least one layer"
        );
        assert!(
            (position as u64) < (self.layers[0].len() as u64),
            "Hash-Tree hash tree path: Invalid position"
        );

        let depth = self.layers.len() - 1;

        assert!(
            depth <= 64,
            "Hash-Tree hash tree path: Tree depth must be at most 64"
        );

        // in our co-path, we will have one node per layer
        // except the final layer (which is just the root)
        let mut co_path = Vec::with_capacity(depth);
        let mut current_position = position;
        for l in 0..depth {
            // position of the sibling that we want to include
            let sibling_position = current_position ^ 0x01;
            // add to the co-path
            let sibling = self.layers[l][sibling_position as usize];
            co_path.push(sibling);
            // new position in next layer
            current_position >>= 1;
        }

        HashTreeOpening { co_path }
    }
}

/// Opening in a hash-tree: a co-path, without the leaf
pub struct HashTreeOpening<TH: TweakableHash> {
    /// The co-path needed to verify
    /// If the tree has depth h, i.e, 2^h leafs
    /// the co-path should have size D
    co_path: Vec<TH::Domain>,
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
        depth <= 64,
        "Hash-Tree hash tree verify: Tree depth must be at most 64"
    );

    assert!(
        (position as u64) < num_leafs,
        "Hash-Tree hash tree verify: Position and Path Length not compatible"
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

    use rand::thread_rng;

    use crate::symmetric::tweak_hash::sha::ShaTweak128192;

    use super::*;

    type TestTH = ShaTweak128192;

    #[test]
    fn test_commit_open_verify() {
        let mut rng = thread_rng();
        let num_leafs = 1024;
        let leaf_len = 3;

        // We test that the following honest procedure succeeds:
        // (1) build the Merkle tree to get the root,
        // (2) build an authentication path for the leaf,
        // (3) verify the authentication path with respect to leaf and root

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
            .map(|(i, v)| TestTH::apply(&parameter, &TestTH::tree_tweak(0, i as u32), v.as_slice()))
            .collect();

        // Build the hash tree using the random parameter and leaves
        let tree = HashTree::<TestTH>::new(&parameter, leafs_hashes);

        // now compute a commitment, i.e., Merkle root
        let root = tree.root();

        // now check that opening and verification works as expected
        for position in 0..num_leafs {
            // first get the opening
            let path = tree.path(position);
            // now assert that it verifies
            let leaf = leafs[position as usize].as_slice();
            assert!(hash_tree_verify(&parameter, &root, position, leaf, &path));
        }
    }
}
