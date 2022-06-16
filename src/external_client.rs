use thiserror::Error;

use crate::{
    group::framing::{MLSMessage, WireFormat},
    session::SessionError,
    ExternalClientConfig, ExternalSession,
};

#[derive(Debug, Error)]
pub enum ExternalClientError {
    #[error("invalid message type, expected {0:?}")]
    InvalidMessageType(WireFormat),
    #[error(transparent)]
    SessionError(#[from] SessionError),
}

pub struct ExternalClient<C: ExternalClientConfig> {
    config: C,
}

impl<C> ExternalClient<C>
where
    C: ExternalClientConfig + Clone,
{
    pub fn join_session(
        &self,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<ExternalSession<C>, ExternalClientError> {
        let group_info =
            group_info
                .into_group_info()
                .ok_or(ExternalClientError::InvalidMessageType(
                    WireFormat::GroupInfo,
                ))?;

        ExternalSession::join(self.config.clone(), group_info, tree_data).map_err(Into::into)
    }
}

impl<C: ExternalClientConfig> ExternalClient<C> {
    pub fn new(config: C) -> Self {
        Self { config }
    }
}
