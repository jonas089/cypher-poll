use std::path::PathBuf;

use voting_tree::VotingTree;
use serde::{Serialize, Deserialize};
#[derive(Serialize, Deserialize)]
pub struct CircuitInputs {
    pub root_history: Vec<Vec<u8>>,
    pub snapshot: VotingTree,
    pub nullifier: Vec<u8>,
    pub public_key_string: String, // todo: serialize / deserialize pgp public key
}

#[derive(Serialize, Deserialize)]
pub struct CircuitOutputs {
    pub nullifier: Vec<u8>,
    pub root_history: Vec<Vec<u8>>,
}