use crypto::{hash_left_right, CryptoHasherSha256};
use serde::{Deserialize, Serialize};

pub const ROOT_HISTORY_SIZE: u16 = 30u16;
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VotingTree {
    pub zero_node: Vec<u8>,
    pub zero_levels: Vec<Vec<u8>>,
    pub filled: Vec<Vec<u8>>,
    pub root: Option<Vec<u8>>,
    pub index: usize,
    pub depth: usize,
}

impl VotingTree {
    pub fn calculate_zero_levels(&mut self) {
        let mut zero_levels: Vec<Vec<u8>> = vec![self.zero_node.clone()];
        for _i in 0..self.depth - 1 {
            zero_levels.push(hash_left_right(
                CryptoHasherSha256,
                zero_levels[zero_levels.len() - 1].clone().as_mut(),
                zero_levels[zero_levels.len() - 1].clone().as_mut(),
            ));
        }
        self.zero_levels = zero_levels;
    }
    pub fn add_leaf(&mut self, leaf: Vec<u8>) {
        let mut current_index = self.index;
        let mut current_hash: Vec<u8> = leaf.clone();
        for i in 0..self.depth {
            if current_index % 2 == 0 {
                self.filled[i] = current_hash.clone();
                current_hash = hash_left_right(
                    CryptoHasherSha256,
                    current_hash.as_mut(),
                    self.zero_levels[i].clone().as_mut(),
                );
            } else {
                let left = self.filled[i].clone();
                current_hash = hash_left_right(
                    CryptoHasherSha256,
                    left.clone().as_mut(),
                    current_hash.clone().as_mut(),
                );
            }
            current_index /= 2;
        }
        self.root = Some(current_hash);
        self.index += 1;
    }
    pub fn compute_root(&mut self, leaf: Vec<u8>) -> Vec<u8> {
        let mut current_index = self.index - 1;
        let mut current_hash: Vec<u8> = leaf.clone();
        for i in 0..self.depth {
            if current_index % 2 == 0 {
                current_hash = hash_left_right(
                    CryptoHasherSha256,
                    current_hash.as_mut(),
                    self.zero_levels[i].clone().as_mut(),
                );
            } else {
                current_hash = hash_left_right(
                    CryptoHasherSha256,
                    self.filled[i].clone().as_mut(),
                    current_hash.clone().as_mut(),
                );
            }
            current_index /= 2;
        }
        current_hash
    }
}

#[test]
fn test_tree() {
    use crypto::hash;
    // construct merkle tree
    let mut tree: VotingTree = VotingTree {
        zero_node: hash(CryptoHasherSha256, &vec![0; 32]),
        zero_levels: Vec::new(),
        filled: vec![vec![], vec![], vec![], vec![], vec![]],
        root: None,
        index: 0,
        depth: 5,
    };
    tree.calculate_zero_levels();
    let leaf = vec![
        242, 69, 81, 38, 252, 95, 197, 129, 177, 105, 42, 137, 129, 73, 125, 148, 130, 204, 83, 82,
        126, 104, 106, 71, 156, 96, 55, 233, 132, 103, 128, 11,
    ];
    let _ = tree.add_leaf(leaf.clone());
    let merkle_root: Option<Vec<u8>> = tree.root.clone();
    assert_eq!(
        tree.compute_root(leaf.clone()),
        merkle_root.clone().unwrap()
    );
    println!("First root: {:?}", &merkle_root.unwrap());

    let _ = tree.add_leaf(leaf.clone());
    let merkle_root = tree.root.clone();
    assert_eq!(
        tree.compute_root(leaf.clone()),
        merkle_root.clone().unwrap()
    );
    println!("Second root: {:?}", &merkle_root.unwrap());
}
