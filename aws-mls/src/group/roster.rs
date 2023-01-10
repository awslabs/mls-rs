use aws_mls_core::group::RosterEntry;

use super::*;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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

impl RosterEntry for Member {
    fn index(&self) -> u32 {
        self.index()
    }

    fn signing_identity(&self) -> &SigningIdentity {
        self.signing_identity()
    }
}

impl From<&(KeyPackage, LeafIndex)> for Member {
    fn from(item: &(KeyPackage, LeafIndex)) -> Self {
        Self::from((item.1, &item.0.leaf_node))
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

impl GroupState {
    pub(crate) fn roster(&self) -> Vec<Member> {
        self.public_tree
            .non_empty_leaves()
            .map(Member::from)
            .collect()
    }
}
