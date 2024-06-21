use crypto::identity::Identity;
use pgp::types::Mpi;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct IdentityPayload {
    pub data_serialized: Vec<u8>,
    pub signature_serialized: Vec<Vec<u8>>,
    // string since this is a PGP key
    pub public_key_string: String,
    pub identity: Identity,
    pub username: String,
}

// note: the vote payload is just a serialized risc0 Receipt
