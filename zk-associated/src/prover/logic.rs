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
use crypto::{CryptoHasherSha256, hash};
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
    uid.compute_public_identity(gpg_signer.signed_public_key.unwrap(), inputs.vote.clone());
    let identity: Identity = uid.identity.unwrap();
    let new_root: TreeRoot = compute_root(&mut inputs.snapshot, identity);
    // check that the input hash is valid

    if !inputs.root_history.contains(&new_root) {
        println!("Root: {:?}", &new_root);
        println!("Root history: {:?}", &inputs.root_history);
        panic!("Root is not contained in Root History")
    };
    CircuitOutputs {
        nullifier: inputs.nullifier.clone(),
        root_history: inputs.root_history.clone(),
        vote: inputs.vote.clone()
    }
}
