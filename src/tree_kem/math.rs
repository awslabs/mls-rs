use thiserror::Error;

#[derive(Error, Debug)]
pub enum TreeMathError {
    #[error("leaf node has no children")]
    NoChildren,
    #[error("root node has no parent")]
    NoParent,
    #[error("no common ancestor")]
    NoCommonAncestor,
    #[error("index out of range")]
    InvalidIndex,
}

pub fn level(x: u32) -> u32 {
    x.trailing_ones()
}

pub fn node_width(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}

pub fn root(n: u32) -> u32 {
    n - 1
}

pub fn left(x: u32) -> Result<u32, TreeMathError> {
    let k = level(x);
    if k == 0 {
        Err(TreeMathError::NoChildren)
    } else {
        Ok(x ^ (0x01 << (k - 1)))
    }
}

pub fn right(x: u32) -> Result<u32, TreeMathError> {
    let k = level(x);
    if k == 0 {
        Err(TreeMathError::NoChildren)
    } else {
        Ok(x ^ (0x03 << (k - 1)))
    }
}

pub fn parent_step(x: u32) -> u32 {
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    (x | (1 << k)) ^ (b << (k + 1))
}

pub fn parent(x: u32, n: u32) -> Result<u32, TreeMathError> {
    if x == root(n) {
        return Err(TreeMathError::NoParent);
    }

    let mut p = parent_step(x);
    while p >= node_width(n) {
        p = parent_step(p)
    }

    Ok(p)
}

pub fn sibling(x: u32, n: u32) -> Result<u32, TreeMathError> {
    let p = parent(x, n)?;
    if x < p {
        right(p)
    } else {
        left(p)
    }
}

pub fn direct_path(x: u32, n: u32) -> Result<Vec<u32>, TreeMathError> {
    let r = root(n);
    let mut d = Vec::new();

    if x == r {
        return Ok(d);
    }

    let mut x_mut = x;

    while x_mut != r {
        x_mut = parent(x_mut, n)?;
        d.push(x_mut)
    }

    Ok(d)
}

pub fn copath(x: u32, n: u32) -> Result<Vec<u32>, TreeMathError> {
    let mut d = Vec::new();

    if x == root(n) {
        return Ok(d);
    }

    d = direct_path(x, n)?;
    d.insert(0, x);
    d.pop();

    d.into_iter().map(|y| sibling(y, n)).collect()
}

pub fn common_ancestor_direct(x: u32, y: u32) -> u32 {
    let lx = level(x) + 1;
    let ly = level(y) + 1;

    if lx <= ly && x >> ly == y >> ly {
        y
    } else if ly <= lx && x >> lx == y >> lx {
        x
    } else {
        let mut xn = x;
        let mut yn = y;
        let mut k = 0;

        while xn != yn {
            xn >>= 1;
            yn >>= 1;
            k += 1;
        }

        (xn << k) + (1 << (k - 1)) - 1
    }
}

pub fn subtree(x: u32) -> (u32, u32) {
    let breadth = 1 << level(x);
    (x + 1 - breadth, x + breadth)
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
        load_test_cases!(tree_math, generate_tree_math_test_cases)
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
