// responsible for maintaining state
// accepts proof payloads (Routes)
// verifies proofs
use client::storage::InMemoryTreeState;
use voting_tree::{crypto::hash_bytes, VotingTree};
fn main() {
    let mut voting_tree: VotingTree = VotingTree {
        zero_node: hash_bytes(vec![0; 32]),
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

    let mut tree_state: InMemoryTreeState = InMemoryTreeState {
        root_history: Vec::new(),
        used_nullifiers: Vec::new(),
        voting_tree,
        leafs: Vec::new(),
    };

    // todo: initialize stateful Rest Server
}
