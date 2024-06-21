// responsible for maintaining state
// accepts proof payloads (Routes)
// verifies proofs

use std::collections::HashSet;
// registers voters / inserts new identities into the tree
// if the signature is valid
// if the account is unique
// if the public key corresponds to the associated github keys
// for the user
use client::{
    storage::{InMemoryTreeState, Snapshot},
};
use crypto::identity::{Identity, Nullifier};
use risc0_zkvm::Receipt;
use voting_tree::{crypto::hash_bytes, VotingTree};

type GitHubUser = String;

struct ServiceState {
    github_users: HashSet<GitHubUser>,
}
impl ServiceState {
    // register a voter, takes a risc0 receipt as input (currently not prover-generic)
    // todo: check that the GPG key is actually in the list of the GitHub User's associated Keys
    // using the GitHub API
    fn process_registration_request(
        &mut self,
        proof: Receipt,
        identity: Identity,
        username: GitHubUser,
        tree_state: &mut InMemoryTreeState,
    ) -> Snapshot {
        if self.github_users.get(&username).is_some() {
            panic!("GitHubUser is not unique")
        };
        self.github_users.insert(username);
        tree_state.insert_nullifier(identity)
    }
}

fn default_tree_state() -> InMemoryTreeState {
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

    InMemoryTreeState {
        root_history: Vec::new(),
        used_nullifiers: Vec::new(),
        voting_tree,
        leafs: Vec::new(),
    }
}

fn main() {
    let mut tree_state: InMemoryTreeState =
        InMemoryTreeState::new(Vec::new(), Vec::new(), Vec::new());
    // todo: initialize stateful Rest Server
}

#[test]
fn submit_zk_vote() {
    // initialize tree_state and service_state
    // process a registration request using the default keypair in ~/resources/test/
    // generate a vote proof
    // verify the vote proof and apply the vote to tree_state
}
