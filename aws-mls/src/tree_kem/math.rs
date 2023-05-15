use alloc::vec::Vec;

use crate::client::MlsError;

use super::node::LeafIndex;

pub fn level(x: u32) -> u32 {
    x.trailing_ones()
}

pub fn root(n: u32) -> u32 {
    n - 1
}

pub fn left(x: u32) -> Result<u32, MlsError> {
    let k = level(x);
    if k == 0 {
        Err(MlsError::LeafNodeNoChildren)
    } else {
        Ok(x ^ (0x01 << (k - 1)))
    }
}

pub fn right(x: u32) -> Result<u32, MlsError> {
    let k = level(x);
    if k == 0 {
        Err(MlsError::LeafNodeNoChildren)
    } else {
        Ok(x ^ (0x03 << (k - 1)))
    }
}

pub fn parent(x: u32, n: u32) -> Result<u32, MlsError> {
    if x == root(n) {
        return Err(MlsError::LeafNodeNoParent);
    }

    let lvl = level(x);
    Ok((x & !(1 << (lvl + 1))) | (1 << lvl))
}

pub fn sibling(x: u32, n: u32) -> Result<u32, MlsError> {
    let p = parent(x, n)?;
    if x < p {
        right(p)
    } else {
        left(p)
    }
}

pub fn direct_path(x: u32, n: u32) -> Result<Vec<u32>, MlsError> {
    if x > 2 * n - 1 {
        return Err(MlsError::InvalidTreeIndex);
    }

    let mut d = Vec::new();
    let mut m = 1 << (level(x) + 1);
    while m <= n {
        d.push((x & !m) | (m - 1));
        m <<= 1;
    }

    Ok(d)
}

pub fn copath(x: u32, n: u32) -> Result<Vec<u32>, MlsError> {
    let mut d = Vec::new();

    if x == root(n) {
        return Ok(d);
    }

    d = direct_path(x, n)?;
    d.insert(0, x);
    d.pop();

    d.into_iter().map(|y| sibling(y, n)).collect()
}

pub fn leaf_lca_level(x: u32, y: u32) -> u32 {
    let mut xn = x;
    let mut yn = y;
    let mut k = 0;

    while xn != yn {
        xn >>= 1;
        yn >>= 1;
        k += 1;
    }

    k
}

pub fn subtree(x: u32) -> (LeafIndex, LeafIndex) {
    let breadth = 1 << level(x);
    (
        LeafIndex((x + 1 - breadth) >> 1),
        LeafIndex(((x + breadth) >> 1) + 1),
    )
}

pub struct BfsIterBottomUp {
    level: usize,
    mask: usize,
    level_end: usize,
    ctr: usize,
}

impl BfsIterBottomUp {
    pub fn new(num_leaves: usize) -> Self {
        Self {
            level: 1,
            mask: 0,
            level_end: num_leaves,
            ctr: 0,
        }
    }
}

impl Iterator for BfsIterBottomUp {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ctr == self.level_end {
            if self.level_end == 1 {
                return None;
            }
            self.level_end = ((self.level_end - 1) >> 1) + 1;
            self.level += 1;
            self.ctr = 0;
            self.mask = (self.mask << 1) | 1;
        }
        let res = Some((self.ctr << self.level) | self.mask);
        self.ctr += 1;
        res
    }
}

pub struct BfsIterTopDown {
    level: usize,
    mask: usize,
    level_end: usize,
    ctr: usize,
}

impl BfsIterTopDown {
    pub fn new(num_leaves: usize) -> Self {
        let depth = num_leaves.trailing_zeros() as usize;
        Self {
            level: depth + 1,
            mask: (1 << depth) - 1,
            level_end: 1,
            ctr: 0,
        }
    }
}

impl Iterator for BfsIterTopDown {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ctr == self.level_end {
            if self.level == 1 {
                return None;
            }
            self.level_end = (((self.level_end - 1) << 1) | 1) + 1;
            self.level -= 1;
            self.ctr = 0;
            self.mask >>= 1;
        }
        let res = Some((self.ctr << self.level) | self.mask);
        self.ctr += 1;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Serialize, Deserialize)]
    struct TestCase {
        n_leaves: u32,
        n_nodes: u32,
        root: u32,
        left: Vec<Option<u32>>,
        right: Vec<Option<u32>>,
        parent: Vec<Option<u32>>,
        sibling: Vec<Option<u32>>,
    }

    pub fn node_width(n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            2 * (n - 1) + 1
        }
    }

    #[test]
    fn test_bfs_iterator() {
        let expected = [0, 2, 4, 6, 8, 10, 12, 14, 1, 5, 9, 13, 3, 11, 7];
        let bfs = BfsIterBottomUp::new(8);
        assert_eq!(bfs.collect::<Vec<_>>(), expected);

        let expected = [7, 3, 11, 1, 5, 9, 13, 0, 2, 4, 6, 8, 10, 12, 14];
        let bfs = BfsIterTopDown::new(8);
        assert_eq!(bfs.collect::<Vec<_>>(), expected);
    }

    fn generate_tree_math_test_cases() -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for log_n_leaves in 0..8 {
            let n_leaves = 1 << log_n_leaves;
            let n_nodes = node_width(n_leaves);
            let left = (0..n_nodes).map(|x| left(x).ok()).collect::<Vec<_>>();
            let right = (0..n_nodes).map(|x| right(x).ok()).collect::<Vec<_>>();

            let parent = (0..n_nodes)
                .map(|x| parent(x, n_leaves).ok())
                .collect::<Vec<_>>();

            let sibling = (0..n_nodes)
                .map(|x| sibling(x, n_leaves).ok())
                .collect::<Vec<_>>();

            test_cases.push(TestCase {
                n_leaves,
                n_nodes,
                root: root(n_leaves),
                left,
                right,
                parent,
                sibling,
            })
        }

        test_cases
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_case_json!(tree_math, generate_tree_math_test_cases())
    }

    #[test]
    fn test_tree_math() {
        let test_cases = load_test_cases();

        for case in test_cases {
            assert_eq!(node_width(case.n_leaves), case.n_nodes);
            assert_eq!(root(case.n_leaves), case.root);
            for x in 0..case.n_nodes {
                assert_eq!(left(x).ok(), case.left[x as usize]);
                assert_eq!(right(x).ok(), case.right[x as usize]);
                assert_eq!(parent(x, case.n_leaves).ok(), case.parent[x as usize]);
                assert_eq!(sibling(x, case.n_leaves).ok(), case.sibling[x as usize]);
            }
        }
    }

    #[test]
    fn test_direct_path() {
        let expected: Vec<Vec<u32>> = [
            [0x01, 0x03, 0x07, 0x0f].to_vec(),
            [0x03, 0x07, 0x0f].to_vec(),
            [0x01, 0x03, 0x07, 0x0f].to_vec(),
            [0x07, 0x0f].to_vec(),
            [0x05, 0x03, 0x07, 0x0f].to_vec(),
            [0x03, 0x07, 0x0f].to_vec(),
            [0x05, 0x03, 0x07, 0x0f].to_vec(),
            [0x0f].to_vec(),
            [0x09, 0x0b, 0x07, 0x0f].to_vec(),
            [0x0b, 0x07, 0x0f].to_vec(),
            [0x09, 0x0b, 0x07, 0x0f].to_vec(),
            [0x07, 0x0f].to_vec(),
            [0x0d, 0x0b, 0x07, 0x0f].to_vec(),
            [0x0b, 0x07, 0x0f].to_vec(),
            [0x0d, 0x0b, 0x07, 0x0f].to_vec(),
            [].to_vec(),
            [0x11, 0x13, 0x17, 0x0f].to_vec(),
            [0x13, 0x17, 0x0f].to_vec(),
            [0x11, 0x13, 0x17, 0x0f].to_vec(),
            [0x17, 0x0f].to_vec(),
            [0x15, 0x13, 0x17, 0x0f].to_vec(),
            [0x13, 0x17, 0x0f].to_vec(),
            [0x15, 0x13, 0x17, 0x0f].to_vec(),
            [0x0f].to_vec(),
            [0x19, 0x1b, 0x17, 0x0f].to_vec(),
            [0x1b, 0x17, 0x0f].to_vec(),
            [0x19, 0x1b, 0x17, 0x0f].to_vec(),
            [0x17, 0x0f].to_vec(),
            [0x1d, 0x1b, 0x17, 0x0f].to_vec(),
            [0x1b, 0x17, 0x0f].to_vec(),
            [0x1d, 0x1b, 0x17, 0x0f].to_vec(),
        ]
        .to_vec();

        for (i, item) in expected.iter().enumerate() {
            assert_eq!(item, &direct_path(i as u32, 16).unwrap())
        }
    }

    #[test]
    fn test_copath_path() {
        let expected: Vec<Vec<u32>> = [
            [0x02, 0x05, 0x0b, 0x17].to_vec(),
            [0x05, 0x0b, 0x17].to_vec(),
            [0x00, 0x05, 0x0b, 0x17].to_vec(),
            [0x0b, 0x17].to_vec(),
            [0x06, 0x01, 0x0b, 0x17].to_vec(),
            [0x01, 0x0b, 0x17].to_vec(),
            [0x04, 0x01, 0x0b, 0x17].to_vec(),
            [0x17].to_vec(),
            [0x0a, 0x0d, 0x03, 0x17].to_vec(),
            [0x0d, 0x03, 0x17].to_vec(),
            [0x08, 0x0d, 0x03, 0x17].to_vec(),
            [0x03, 0x17].to_vec(),
            [0x0e, 0x09, 0x03, 0x17].to_vec(),
            [0x09, 0x03, 0x17].to_vec(),
            [0x0c, 0x09, 0x03, 0x17].to_vec(),
            [].to_vec(),
            [0x12, 0x15, 0x1b, 0x07].to_vec(),
            [0x15, 0x1b, 0x07].to_vec(),
            [0x10, 0x15, 0x1b, 0x07].to_vec(),
            [0x1b, 0x07].to_vec(),
            [0x16, 0x11, 0x1b, 0x07].to_vec(),
            [0x11, 0x1b, 0x07].to_vec(),
            [0x14, 0x11, 0x1b, 0x07].to_vec(),
            [0x07].to_vec(),
            [0x1a, 0x1d, 0x13, 0x07].to_vec(),
            [0x1d, 0x13, 0x07].to_vec(),
            [0x18, 0x1d, 0x13, 0x07].to_vec(),
            [0x13, 0x07].to_vec(),
            [0x1e, 0x19, 0x13, 0x07].to_vec(),
            [0x19, 0x13, 0x07].to_vec(),
            [0x1c, 0x19, 0x13, 0x07].to_vec(),
        ]
        .to_vec();

        for (i, item) in expected.iter().enumerate() {
            assert_eq!(item, &copath(i as u32, 16).unwrap())
        }
    }
}
