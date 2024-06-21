# Anonymous GitHub GPG Voting Protocol built with Risc0
Cypher-poll is an anonymous voting protocol which anyone with a GitHub identity and at least one associated GPG key can use.
The service can be modified to enforce further restrictions on who is eligible to vote, by default any GitHub account with a GPG key can vote once (not once per GPG key!).

## Registration process
The registration process consists of the user submitting their `Identity`, which is a `Hash` of their unique `Nullifier` concatenated by their `Public Key`.
If the user successfully generates a `Signature` for a `Public Key` that is associated with their GitHub account, the Hash of the `Nullifier` and `Public Key` is inserted in a fixed size `Merkle Tree`. A Snapshot of the `Merkle Tree` at that point in time is returned to the user.

## Voting process
To issue a vote, the user must submit a zero knowledge proof that the `Nullifier` that is being redeemed was included in the `Merkle Tree` for a given Snapshot. The Snapshot that was returned by the server at the end of the registration process is sufficent as long as the corresponding `Merkle Root` is included in the set of valid `Merkle Roots` in service (or Blockchain) state.

If the proof is accepted, the vote is counted and the `Nullifier` is added to a list to ensure that it cannot be used again.

## Run the Server

## Client Documentation

