// compute a zero knowledge proof
// that Sha256(nullifier, public_key) is a leaf 
// that the merkle proof of that leaf is valid for one of the roots in a given list

// private inputs: tree snapshot, public key
// public inputs/outputs: list of roots
// public outputs: nullifier
use crypto::identity::{Identity, Nullifier, UniqueIdentity};
use kairos_delta_tree::KairosDeltaTree;
use pgp::SignedPublicKey;
use crate::storage::TreeRoot;
use serde::{Serialize, Deserialize};
use super::merkle::compute_root;

#[derive(Serialize, Deserialize)]
pub struct CircuitOutputs{
    pub nullifier: Nullifier,
    pub root_history: Vec<TreeRoot>
}

pub fn prover_logic(root_history: Vec<TreeRoot>, snapshot: &mut KairosDeltaTree, nullifier: Nullifier, public_key: SignedPublicKey) -> CircuitOutputs{
    let mut uid = UniqueIdentity{
        nullifier: Some(nullifier.clone()),
        identity: None
    };
    uid.compute_public_identity(public_key);
    let public_identity: Identity = uid.identity.unwrap();
    let new_root: TreeRoot = compute_root(snapshot, public_identity);
    // The verifier will have to check that the journal Root History
    // matches its current Root History e.g. that all Roots contained
    // in the journal's Root History are contained in the actual Root History

    // Todo: Make Root History a HashMap / HashSet => especially important
    // when developing an on-chain solution.
    if !root_history.contains(&new_root){
        panic!("Root is not contained in Root History")
    };
    CircuitOutputs{
        nullifier,
        root_history
    }
}