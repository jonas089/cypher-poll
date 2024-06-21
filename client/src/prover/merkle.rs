use crate::storage::TreeRoot;
use crypto::identity::Identity;
use voting_tree::VotingTree;

// compute a merkle root for an identity
pub fn compute_root(snapshot: &mut VotingTree, leaf: Identity) -> TreeRoot {
    snapshot.compute_root(leaf)
}
