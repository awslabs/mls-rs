use super::*;
use cfg_if::cfg_if;

pub use aws_mls_core::group::Member;

pub(crate) fn member_from_key_package(key_package: &KeyPackage, index: LeafIndex) -> Member {
    member_from_leaf_node(&key_package.leaf_node, index)
}

pub(crate) fn member_from_leaf_node(leaf_node: &LeafNode, leaf_index: LeafIndex) -> Member {
    cfg_if! {
        if #[cfg(feature = "benchmark")] {
            Member::new(
                *leaf_index,
                leaf_node.signing_identity.clone(),
                leaf_node.capabilities.clone(),
                leaf_node.extensions.clone(),
                leaf_node.tls_serialize_detached().unwrap()
            )
        } else {
            Member::new(
                *leaf_index,
                leaf_node.signing_identity.clone(),
                leaf_node.capabilities.clone(),
                leaf_node.extensions.clone(),
            )
        }
    }
}

impl GroupState {
    pub(crate) fn roster(&self) -> Vec<Member> {
        self.roster_iter().collect()
    }

    pub(crate) fn roster_iter(&self) -> impl Iterator<Item = Member> + '_ {
        self.public_tree
            .non_empty_leaves()
            .map(|(index, node)| member_from_leaf_node(node, index))
    }

    pub(crate) fn signing_identity_iter(&self) -> impl Iterator<Item = &SigningIdentity> + '_ {
        self.public_tree
            .non_empty_leaves()
            .map(|(_, node)| &node.signing_identity)
    }
}
