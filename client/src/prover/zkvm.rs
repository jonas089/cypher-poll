// compute a zero knowledge proof
// that Sha256(nullifier, public_key) is a leaf 
// that the merkle proof of that leaf is valid for one of the roots in a given list

// private inputs: tree snapshot, public key
// public inputs/outputs: list of roots
// public outputs: nullifier, vote


/* Pseudocode
    leaf = sha(nullifier, public_key);

    let root = merkle_proof(snapshot, leaf);
    assert!(list_of_roots.contains(root));

    journal.commit(
        nullifier,
        list_of_roots,
        vote
    );



    If the proof is valid for the on-chain list_of_roots, then the vote can be accepted and the nullifier 
    must be invalidated
*/