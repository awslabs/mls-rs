use thiserror::Error;

use crate::{
    group::{framing::MLSMessage, ExternalGroup, GroupError},
    ExternalClientConfig,
};

#[derive(Debug, Error)]
pub enum ExternalClientError {
    #[error(transparent)]
    GroupError(#[from] GroupError),
}

pub struct ExternalClient<C: ExternalClientConfig> {
    config: C,
}

impl<C> ExternalClient<C>
where
    C: ExternalClientConfig + Clone,
{
    pub fn observe_group(
        &self,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<ExternalGroup<C>, ExternalClientError> {
        ExternalGroup::join(self.config.clone(), group_info, tree_data).map_err(Into::into)
    }
}

impl<C: ExternalClientConfig> ExternalClient<C> {
    pub fn new(config: C) -> Self {
        Self { config }
    }
}
