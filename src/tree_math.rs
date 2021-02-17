use crate::util::log2;
use thiserror::Error;
use std::collections::BTreeSet;
use std::iter::FromIterator;

#[derive(Error, Debug)]
pub enum TreeMathError {
    #[error("leaf node has no children")]
    NoChildren,
    #[error("root node has no parent")]
    NoParent,
    #[error("no common ancestor")]
    NoCommonAncestor
}

fn level(x: u64) -> u64 {
    if x & 0x01 == 0 {
        return 0;
    }

    let mut k: u64 = 0;
    while ((x >> k) & 0x01) == 1 {
        k += 1;
    }

    k
}

fn node_width(n: u64) -> u64 {
    if n == 0 {
        return 0;
    } else {
        2 * (n - 1) + 1
    }
}

fn root(n: u64) -> u64 {
    let w = node_width(n);
    (1 << log2(w)) - 1
}

fn left(x: u64) -> Result<u64, TreeMathError> {
    let k = level(x);
    if k == 0 {
        Err(TreeMathError::NoChildren)
    } else {
        Ok(x ^ (0x01 << (k - 1)))
    }
}

fn right(x: u64, n: u64) -> Result<u64, TreeMathError> {
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

fn parent_step(x: u64) -> u64 {
    let k = level(x);
    let b = (x >> (k + 1)) & 0x01;
    (x | (1 << k)) ^ (b << (k + 1))
}

fn parent(x: u64, n: u64) -> Result<u64, TreeMathError> {
    if x == root(n) {
        return Err(TreeMathError::NoParent)
    }

    let mut p = parent_step(x);
    while p >= node_width(n) {
        p = parent_step(p)
    }

    Ok(p)
}

fn sibling(x: u64, n: u64) -> Result<u64, TreeMathError> {
    let p = parent(x, n)?;
    if x < p {
        right(p, n)
    } else {
        left(p)
    }
}

fn direct_path(x: u64, n: u64) -> Result<Vec<u64>, TreeMathError> {
    let r = root(n);
    let mut d = Vec::new();

    if x == r {
        Ok(d)
    } else {
        let mut x_mut = x;

        while x != r {
            x_mut = parent(x_mut, n)?;
            d.push(x_mut)
        }

        Ok(d)
    }
}

fn copath(x: u64, n: u64) -> Result<Vec<u64>, TreeMathError> {
    let mut d = Vec::new();

    if x == root(n) {
        Ok(d)
    } else {
        d = direct_path(x, n)?;
        d.insert(0, x);
        d.pop();
        let copath: Result<Vec<_>, _> =
            d.into_iter()
                .map(|y| sibling(y, n))
                .collect();
        copath
    }
}

fn common_ancestor_semantic(x: u64, y: u64, n: u64) -> Result<u64, TreeMathError> {
    let dx: BTreeSet<u64> = BTreeSet::from_iter([x].to_vec())
        .union(&BTreeSet::from_iter(direct_path(x, n)?))
        .cloned()
        .collect();

    let dy: BTreeSet<u64> = BTreeSet::from_iter([y].to_vec())
        .union(&BTreeSet::from_iter(direct_path(y, n)?))
        .cloned()
        .collect();

    let dxy: Vec<u64> = dx.intersection(&dy).cloned().collect();

    if let Some(common_ancestor) = dxy.into_iter()
        .map(|i| level(i))
        .min() {
        Ok(common_ancestor)
    } else {
        Err(TreeMathError::NoCommonAncestor)
    }
}

fn common_ancestor_direct(x: u64, y: u64) -> u64 {
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
            xn = xn >> 1;
            yn = yn >> 1;
            k += 1;
        }

        (xn << k) + (1 << (k - 1)) -1
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize};
    use std::fs::File;
    use std::io::BufReader;
    use super::*;

    #[derive(Deserialize)]
    struct TestCase {
        n_leaves: u64,
        n_nodes: u64,
        root: Vec<u64>,
        left: Vec<Option<u64>>,
        right: Vec<Option<u64>>,
        parent: Vec<Option<u64>>,
        sibling: Vec<Option<u64>>
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
        let file = File::open("test_data/kat_treemath_openmls.json")
            .expect("failed to open file");

        let test_vectors: Vec<TestCase> = serde_json::from_reader(BufReader::new(file))
            .expect("failed to parse vector file");

        test_vectors.iter().for_each(|tv| run_test_case(tv));
    }
}