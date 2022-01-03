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

pub fn log2(x: u32) -> u32 {
    (x as f32).log2().floor() as u32
}

pub fn level(x: u32) -> u32 {
    if x & 0x01 == 0 {
        return 0;
    }

    let mut k: u32 = 0;
    while ((x >> k) & 0x01) == 1 {
        k += 1;
    }

    k
}

pub fn node_width(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}

pub fn root(n: u32) -> u32 {
    let w = node_width(n);
    (1 << log2(w)) - 1
}

pub fn left(x: u32) -> Result<u32, TreeMathError> {
    let k = level(x);
    if k == 0 {
        Err(TreeMathError::NoChildren)
    } else {
        Ok(x ^ (0x01 << (k - 1)))
    }
}

pub fn right(x: u32, n: u32) -> Result<u32, TreeMathError> {
    let k = level(x);
    if k == 0 {
        Err(TreeMathError::NoChildren)
    } else {
        let mut r = x ^ (0x03 << (k - 1));
        while r >= node_width(n) {
            r = left(r)?
        }
        Ok(r)
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
        right(p, n)
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

#[cfg(test)]
mod test {
    use super::*;
    use serde::Deserialize;
    use std::fs::File;
    use std::io::BufReader;

    #[derive(Deserialize)]
    struct TestCase {
        n_leaves: u32,
        n_nodes: u32,
        root: Vec<u32>,
        left: Vec<Option<u32>>,
        right: Vec<Option<u32>>,
        parent: Vec<Option<u32>>,
        sibling: Vec<Option<u32>>,
    }

    fn run_test_case(case: &TestCase) {
        assert_eq!(node_width(case.n_leaves), case.n_nodes);

        for i in 0..case.n_leaves {
            assert_eq!(root(i + 1), case.root[i as usize]);
            assert_eq!(left(i).ok(), case.left[i as usize]);
            assert_eq!(right(i, case.n_leaves).ok(), case.right[i as usize]);
            assert_eq!(parent(i, case.n_leaves).ok(), case.parent[i as usize]);
            assert_eq!(sibling(i, case.n_leaves).ok(), case.sibling[i as usize]);
        }
    }

    #[test]
    fn test_tree_math() {
        let file = File::open("test_data/kat_treemath_openmls.json").expect("failed to open file");

        let test_vectors: Vec<TestCase> =
            serde_json::from_reader(BufReader::new(file)).expect("failed to parse vector file");

        test_vectors.iter().for_each(run_test_case);
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
            [0x11, 0x13, 0x0f].to_vec(),
            [0x13, 0x0f].to_vec(),
            [0x11, 0x13, 0x0f].to_vec(),
            [0x0f].to_vec(),
            [0x13, 0x0f].to_vec(),
        ]
        .to_vec();

        for (i, item) in expected.iter().enumerate() {
            assert_eq!(item, &direct_path(i as u32, 11).unwrap())
        }
    }

    #[test]
    fn test_copath_path() {
        let expected: Vec<Vec<u32>> = [
            [0x02, 0x05, 0x0b, 0x13].to_vec(),
            [0x05, 0x0b, 0x13].to_vec(),
            [0x00, 0x05, 0x0b, 0x13].to_vec(),
            [0x0b, 0x13].to_vec(),
            [0x06, 0x01, 0x0b, 0x13].to_vec(),
            [0x01, 0x0b, 0x13].to_vec(),
            [0x04, 0x01, 0x0b, 0x13].to_vec(),
            [0x13].to_vec(),
            [0x0a, 0x0d, 0x03, 0x13].to_vec(),
            [0x0d, 0x03, 0x13].to_vec(),
            [0x08, 0x0d, 0x03, 0x13].to_vec(),
            [0x03, 0x13].to_vec(),
            [0x0e, 0x09, 0x03, 0x13].to_vec(),
            [0x09, 0x03, 0x13].to_vec(),
            [0x0c, 0x09, 0x03, 0x13].to_vec(),
            [].to_vec(),
            [0x12, 0x14, 0x07].to_vec(),
            [0x14, 0x07].to_vec(),
            [0x10, 0x14, 0x07].to_vec(),
            [0x07].to_vec(),
            [0x11, 0x07].to_vec(),
        ]
        .to_vec();

        for (i, item) in expected.iter().enumerate() {
            assert_eq!(item, &copath(i as u32, 11).unwrap())
        }
    }
}
