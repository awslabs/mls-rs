use crate::identity::SigningIdentity;

pub trait RosterEntry {
    fn index(&self) -> u32;
    fn signing_identity(&self) -> &SigningIdentity;
    // TODO: Leaf extensions
    // TODO: Capabilities
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RosterUpdate<T: RosterEntry> {
    pub added: Vec<T>,
    pub removed: Vec<T>,
    pub updated: Vec<T>,
}
