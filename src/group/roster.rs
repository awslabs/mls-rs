use crate::signing_identity::SigningIdentity;

use super::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    node: LeafNode,
    index: LeafIndex,
}

impl Member {
    pub fn index(&self) -> u32 {
        self.index.0
    }

    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.node.signing_identity
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.node.capabilities
    }

    pub fn extensions(&self) -> &ExtensionList<LeafNodeExtension> {
        &self.node.extensions
    }

    #[cfg(feature = "benchmark")]
    pub fn leaf_bytes(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.node.tls_serialize_detached()
    }
}

impl From<(LeafIndex, &LeafNode)> for Member {
    fn from(item: (LeafIndex, &LeafNode)) -> Self {
        Member {
            node: item.1.clone(),
            index: item.0,
        }
    }
}

impl From<&(LeafIndex, LeafNode)> for Member {
    fn from(item: &(LeafIndex, LeafNode)) -> Self {
        Member {
            node: item.1.clone(),
            index: item.0,
        }
    }
}

pub struct Roster<I>
where
    I: Iterator<Item = Member>,
{
    inner: I,
    total_members: u32,
}

impl<I> Roster<I>
where
    I: Iterator<Item = Member>,
{
    pub fn into_vec(self) -> Vec<Member> {
        self.collect()
    }

    pub fn member_count(&self) -> usize {
        self.total_members as usize
    }
}

impl<I> Iterator for Roster<I>
where
    I: Iterator<Item = Member>,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn roster(&self) -> Roster<impl Iterator<Item = Member> + '_> {
        let roster_iter = self
            .current_epoch_tree()
            .non_empty_leaves()
            .map(Member::from);

        Roster {
            inner: roster_iter,
            total_members: self.current_epoch_tree().occupied_leaf_count(),
        }
    }
}
