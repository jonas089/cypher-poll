use kairos_delta_tree::{KairosDeltaTree, crypto::hash_bytes};

/// In production, this would live on a Blockchain
/// a derivation of the tornadocash merkle tree
/// to include nullifiers on-chain efficiently
use crypto::identity::{self, Identity, Nullifier};
pub type TreeRoot = Vec<u8>;

pub struct InMemoryTreeState{
    root_history: Vec<TreeRoot>,
    used_nullifiers: Vec<Nullifier>,
    delta_tree: KairosDeltaTree,
    leafs: Vec<Identity>
}

impl InMemoryTreeState{
    pub fn new(&self, root_history: Vec<TreeRoot>, used_nullifiers: Vec<Nullifier>, leafs: Vec<Identity>) -> InMemoryTreeState{

        // todo: initialize fixed-size delta tree
        let mut delta_tree: KairosDeltaTree = KairosDeltaTree{
            zero_node: hash_bytes(vec![0;32]),
            zero_levels: Vec::new(),
            // size must equal tree depth
            filled: vec![vec![];5],
            root: None,
            index: 0,
            // the maximum amount of identities this tree can store
            // is 2^depth (depth:5 => max_identity_count:32)
            depth: 5
        };
        delta_tree.calculate_zero_levels();

        InMemoryTreeState{
            root_history,
            used_nullifiers,
            delta_tree,
            leafs
        }
    }

    pub fn insert_nullifier(&mut self, identity: Identity) -> KairosDeltaTree{
        // take a snapshot of the Tree before insertion
        let snapshot = self.delta_tree.clone();
        // append the real tree by a new identity
        self.delta_tree.add_leaf(identity.clone());
        // store the new identity
        self.leafs.push(identity);
        // store the new root in state
        self.root_history.push(self.delta_tree.root.clone().expect("Tree has no root"));
        // return the snapshot -> this will be used when generating the merkle proof
        snapshot
    }
}