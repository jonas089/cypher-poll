use crypto::{hash, CryptoHasherSha256};
use voting_tree::VotingTree;

/// In production, this would live on a Blockchain
/// a derivation of the tornadocash merkle tree
/// to include nullifiers on-chain efficiently
use crypto::identity::{Identity, Nullifier};
pub type TreeRoot = Vec<u8>;
pub type Snapshot = VotingTree;

#[derive(Clone)]
pub struct InMemoryTreeState {
    pub root_history: Vec<TreeRoot>,
    pub used_nullifiers: Vec<Nullifier>,
    pub voting_tree: VotingTree,
    pub leafs: Vec<Identity>,
}

impl InMemoryTreeState {
    pub fn new(
        root_history: Vec<TreeRoot>,
        used_nullifiers: Vec<Nullifier>,
        leafs: Vec<Identity>,
    ) -> InMemoryTreeState {
        let mut voting_tree: VotingTree = VotingTree {
            zero_node: hash(CryptoHasherSha256, &vec![0; 32]),
            zero_levels: Vec::new(),
            // size must equal tree depth
            filled: vec![vec![]; 5],
            root: None,
            index: 0,
            // the maximum amount of identities this tree can store
            // is 2^depth (depth:5 => max_identity_count:32)
            depth: 5,
        };
        voting_tree.calculate_zero_levels();

        InMemoryTreeState {
            root_history,
            used_nullifiers,
            voting_tree,
            leafs,
        }
    }

    pub fn insert_nullifier(&mut self, identity: Identity) -> Snapshot {
        // take a snapshot of the Tree before insertion
        let snapshot = self.voting_tree.clone();
        // append the real tree by a new identity
        self.voting_tree.add_leaf(identity.clone());
        // store the new identity
        self.leafs.push(identity);
        // store the new root in state
        self.root_history
            .push(self.voting_tree.root.clone().expect("Tree has no root"));
        // return the snapshot -> this will be used when generating the merkle proof
        snapshot
    }
}
