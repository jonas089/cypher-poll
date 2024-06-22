use serde::{Deserialize, Serialize};
use voting_tree::VotingTree;
#[derive(Serialize, Deserialize)]
pub struct CircuitInputs {
    pub root_history: Vec<Vec<u8>>,
    pub snapshot: VotingTree,
    pub nullifier: Vec<u8>,
    pub vote: String,
    pub public_key_string: String, // todo: serialize / deserialize pgp public key
}

#[derive(Serialize, Deserialize)]
pub struct CircuitOutputs {
    pub nullifier: Vec<u8>,
    pub root_history: Vec<Vec<u8>>,
    pub vote: String
}
