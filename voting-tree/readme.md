# Kairos Delta Tree for native Transaction Rollup
This implementation of a fixed-size Merkle Tree stores only the leafs affected by an insertion. Additionally, I implemeted a function to verify the integrity of an insert operation similar to how a merkle proof are used.

# Run tests

```rust
cargo test -- --nocapture
```