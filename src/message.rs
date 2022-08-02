use crate::{
    group::{framing::MLSCiphertext, GroupError, StateUpdate},
    Proposal,
};

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    ApplicationMessage(Vec<u8>),
    Commit(StateUpdate),
    Proposal(Proposal),
}

#[derive(Clone, Debug)]
pub struct ProcessedMessage<E> {
    pub event: E,
    pub sender_index: Option<u32>,
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ExternalEvent {
    Commit(StateUpdate),
    Proposal(Proposal),
    Ciphertext(MLSCiphertext),
}

impl TryFrom<Event> for ExternalEvent {
    type Error = GroupError;

    fn try_from(value: Event) -> Result<Self, Self::Error> {
        match value {
            Event::ApplicationMessage(_) => Err(GroupError::UnencryptedApplicationMessage),
            Event::Commit(c) => Ok(ExternalEvent::Commit(c)),
            Event::Proposal(p) => Ok(ExternalEvent::Proposal(p)),
        }
    }
}

impl TryFrom<ProcessedMessage<Event>> for ProcessedMessage<ExternalEvent> {
    type Error = GroupError;

    fn try_from(value: ProcessedMessage<Event>) -> Result<Self, Self::Error> {
        Ok(Self {
            event: value.event.try_into()?,
            sender_index: value.sender_index,
            authenticated_data: value.authenticated_data,
        })
    }
}
