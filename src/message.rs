use crate::{
    credential::Credential,
    group::{GroupInfo, StateUpdate, Welcome},
    key_package::KeyPackage,
    Proposal,
};

#[derive(Clone, Debug)]
pub enum ProcessedMessagePayload {
    Application(Vec<u8>),
    Commit(StateUpdate),
    Proposal(Proposal),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
}

#[derive(Clone, Debug)]
pub struct ProcessedMessage {
    pub message: ProcessedMessagePayload,
    pub sender_credential: Option<Credential>,
}
