// compute a zero knowledge proof
// that Sha256(nullifier, public_key) is a leaf 
// that the merkle proof of that leaf is valid for one of the roots in a given list

use std::path::PathBuf;

// private inputs: tree snapshot, public key
// public inputs/outputs: list of roots
// public outputs: nullifier
use crypto::identity::{Identity, Nullifier, UniqueIdentity};
use kairos_delta_tree::KairosDeltaTree;
use pgp::SignedPublicKey;
use crate::storage::TreeRoot;
use serde::{Serialize, Deserialize};
use super::merkle::compute_root;
use crypto::gpg::GpgSigner;

#[derive(Serialize, Deserialize)]
pub struct CircuitInputs{
    pub root_history: Vec<TreeRoot>,
    pub snapshot: KairosDeltaTree,
    pub nullifier: Nullifier,
    pub public_key_path: PathBuf
    // todo: serialize / deserialize pgp public key
}

#[derive(Serialize, Deserialize)]
pub struct CircuitOutputs{
    pub nullifier: Nullifier,
    pub root_history: Vec<TreeRoot>
}

pub fn prover_logic(inputs: &mut CircuitInputs) -> CircuitOutputs{
    let mut gpg_signer: GpgSigner = GpgSigner{
        secret_key_asc_path: None,
        public_key_asc_path: Some(inputs.public_key_path.clone()),
        signed_public_key: None,
        signed_secret_key: None
    };
    gpg_signer.init_verifier();
    let mut uid = UniqueIdentity{
        nullifier: Some(inputs.nullifier.clone()),
        identity: None
    };
    uid.compute_public_identity(gpg_signer.signed_public_key.unwrap());
    let public_identity: Identity = uid.identity.unwrap();
    let new_root: TreeRoot = compute_root(&mut inputs.snapshot, public_identity);
    // The verifier will have to check that the journal Root History
    // matches its current Root History e.g. that all Roots contained
    // in the journal's Root History are contained in the actual Root History

    // Todo: Make Root History a HashMap / HashSet => especially important
    // when developing an on-chain solution.
    if !inputs.root_history.contains(&new_root){
        panic!("Root is not contained in Root History")
    };
    CircuitOutputs{
        nullifier: inputs.nullifier.clone(),
        root_history: inputs.root_history.clone()
    }
}