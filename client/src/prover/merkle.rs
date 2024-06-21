use crypto::identity::Identity;
use kairos_delta_tree::KairosDeltaTree;
use crate::storage::TreeRoot;

// compute a merkle root for an identity
pub fn compute_root(snapshot: &mut KairosDeltaTree, leaf: Identity) -> TreeRoot{
    snapshot.merkle_proof(leaf)
}