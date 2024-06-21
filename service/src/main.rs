// responsible for maintaining state
// accepts proof payloads (Routes)
// verifies proofs

use std::{collections::HashSet, fs, path::{Path, PathBuf}};
// registers voters / inserts new identities into the tree
// if the signature is valid
// if the account is unique
// if the public key corresponds to the associated github keys
// for the user
use client::{
    storage::{InMemoryTreeState, Snapshot},
};
use crypto::{gpg::GpgSigner, identity::{self, Identity, Nullifier, UniqueIdentity}};
use pgp::{types::Mpi, SignedPublicKey};
use risc0_prover::{prover::prove_default, verifier::verify_vote};
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
        signature: Vec<Mpi>,
        data: Vec<u8>,
        public_key: PathBuf,
        identity: Identity,
        username: GitHubUser,
        tree_state: &mut InMemoryTreeState,
    ) -> Snapshot {
        let mut signer = GpgSigner {
            secret_key_asc_path: None,
            public_key_asc_path: Some(public_key),
            signed_secret_key: None,
            signed_public_key: None,
        };
        signer.init_verifier();
        assert!(signer.is_valid_signature(signature, &data));

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
    use risc0_prover::{prover, verifier};
    use risc0_types::{CircuitInputs, CircuitOutputs};
    // initialize tree_state and service_state
    // process a registration request using the default keypair in ~/resources/test/
    // generate a vote proof
    // verify the vote proof and apply the vote to tree_state
    let mut tree_state: InMemoryTreeState = default_tree_state();
    let mut service_state: ServiceState = ServiceState{
        github_users: HashSet::new()
    };
    let mut identity: UniqueIdentity = UniqueIdentity{
        identity: None,
        nullifier: None
    };
    identity.generate_nullifier("I am a random seed, radnom!".to_string());

    let private_key_path_str = "/Users/chef/Desktop/cypher-poll/resources/test/key.sec.asc";
    let public_key_path_str = "/Users/chef/Desktop/cypher-poll/resources/test/key.asc";
    
    /*let public_key_string: String = fs::read_to_string(
        public_key_path
    )
    .expect("Failed to read public key");*/

    let mut signer = GpgSigner {
        secret_key_asc_path: Some(PathBuf::from(
            private_key_path_str,
        )),
        public_key_asc_path: Some(PathBuf::from(
            public_key_path_str
        )),
        signed_secret_key: None,
        signed_public_key: None,
    };
    let public_key_path: PathBuf = signer.public_key_asc_path.clone().expect("Missing public key path");
    signer.init();
    let data: Vec<u8> = vec![0u8];
    let signature: Vec<Mpi> = signer.sign_bytes(&data);
    assert!(signer.is_valid_signature(signature.clone(), &data));
    // record snapshot
    let snapshot: VotingTree = tree_state.voting_tree.clone();
    identity.compute_public_identity(signer.signed_public_key.unwrap());
    // register the voter    
    service_state.process_registration_request(signature, data, public_key_path.clone(), identity.identity.expect("Missing identity"), "jonas089".to_string(), &mut tree_state);

    
    // generate a proof -> redeem the nullifier
    let proof: Receipt = prove_default(CircuitInputs{
        root_history: tree_state.root_history.clone(),
        snapshot,
        nullifier: identity.nullifier.clone().expect("Missing Nullifier"),
        public_key_path
    });
    
    let is_valid = verify_vote(proof, tree_state.root_history.clone());
    assert!(is_valid)
}
