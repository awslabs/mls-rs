use crate::{
    cipher_suite::CipherSuite,
    external_client_config::{ExternalClientConfig, ExternalClientGroupConfig},
    group::{ExternalGroup, GroupContext},
    message::ExternalProcessedMessage,
    session::SessionError,
    tree_kem::TreeKemPublic,
    ProtocolVersion,
};
use tls_codec::Deserialize;

pub struct ExternalSession<C: ExternalClientConfig> {
    config: C,
    protocol: ExternalGroup<ExternalClientGroupConfig<C>>,
}

impl<C> ExternalSession<C>
where
    C: ExternalClientConfig,
    C::EpochRepository: Clone,
    C::CredentialValidator: Clone,
{
    pub fn join(
        config: C,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_context: GroupContext,
        tree_data: &[u8],
        confirmation_tag: &[u8],
    ) -> Result<Self, SessionError> {
        let group_config = ExternalClientGroupConfig::new(&config, &group_context.group_id);
        let nodes = Deserialize::tls_deserialize(&mut &*tree_data)?;
        let public_tree = TreeKemPublic::import_node_data(cipher_suite, nodes)?;

        Ok(Self {
            config,
            protocol: ExternalGroup::new(
                group_config,
                protocol_version,
                cipher_suite,
                group_context,
                public_tree,
                &Deserialize::tls_deserialize(&mut &*confirmation_tag)?,
            )?,
        })
    }

    pub fn process_incoming_bytes(
        &mut self,
        message: &[u8],
    ) -> Result<ExternalProcessedMessage, SessionError> {
        Ok(self
            .protocol
            .process_incoming_bytes(message, |id| self.config.external_signing_key(id))?)
    }
}
