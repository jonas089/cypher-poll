// compute a zero knowledge proof
// that Sha256(nullifier, public_key) is a leaf
// that the merkle proof of that leaf is valid for one of the roots in a given list

use risc0_types::{CircuitInputs, CircuitOutputs};
// private inputs: tree snapshot, public key
// public inputs/outputs: list of roots
// public outputs: nullifier
use super::merkle::compute_root;
use crate::storage::TreeRoot;
use crypto::gpg::GpgSigner;
use crypto::identity::{Identity, UniqueIdentity};

pub fn prover_logic(inputs: &mut CircuitInputs) -> CircuitOutputs {
    let mut gpg_signer: GpgSigner = GpgSigner {
        secret_key_asc_path: None,
        public_key_asc_string: Some(inputs.public_key_string.clone()),
        signed_public_key: None,
        signed_secret_key: None,
    };
    gpg_signer.init_verifier();
    let mut uid = UniqueIdentity {
        nullifier: Some(inputs.nullifier.clone()),
        identity: None,
    };
    uid.compute_public_identity(gpg_signer.signed_public_key.unwrap());
    let identity: Identity = uid.identity.unwrap();

    let new_root: TreeRoot = compute_root(&mut inputs.snapshot, identity);
    // The verifier will have to check that the journal Root History
    // matches its current Root History e.g. that all Roots contained
    // in the journal's Root History are contained in the actual Root History

    // Todo: Make Root History a HashMap / HashSet => especially important
    // when developing an on-chain solution.
    if !inputs.root_history.contains(&new_root) {
        println!("Root: {:?}", &new_root);
        println!("Root history: {:?}", &inputs.root_history);
        panic!("Root is not contained in Root History")
    };
    CircuitOutputs {
        nullifier: inputs.nullifier.clone(),
        root_history: inputs.root_history.clone(),
    }
}
