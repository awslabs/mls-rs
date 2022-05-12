use crate::{
    credential::Credential,
    group::{framing::MLSCiphertext, GroupInfo, StateUpdate, Welcome},
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
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum ExternalProcessedMessagePayload {
    Commit(StateUpdate),
    Proposal(Proposal),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
    Ciphertext(MLSCiphertext),
}

#[derive(Clone, Debug)]
pub struct ExternalProcessedMessage {
    pub message: ExternalProcessedMessagePayload,
    pub sender_credential: Option<Credential>,
    pub authenticated_data: Vec<u8>,
}
