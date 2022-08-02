use crate::{
    external_client_config::{ExternalClientConfig, ExternalClientGroupConfig},
    group::{ExternalGroup, GroupInfo},
    keychain::Keychain,
    message::{ExternalEvent, ProcessedMessage},
    session::SessionError,
    signing_identity::SigningIdentity,
    tree_kem::TreeKemPublic,
    AddProposal, RemoveProposal,
};
use tls_codec::{Deserialize, Serialize};

pub struct ExternalSession<C: ExternalClientConfig> {
    config: C,
    protocol: ExternalGroup<ExternalClientGroupConfig<C>>,
}

impl<C> ExternalSession<C>
where
    C: ExternalClientConfig + Clone,
{
    pub(crate) fn join(
        config: C,
        group_info: GroupInfo,
        tree_data: Option<&[u8]>,
    ) -> Result<Self, SessionError> {
        let group_config = ExternalClientGroupConfig::new(config.clone());

        let public_tree = tree_data
            .map(|rt| {
                let nodes = Deserialize::tls_deserialize(&mut &*rt)?;
                TreeKemPublic::import_node_data(group_info.group_context.cipher_suite, nodes)
            })
            .transpose()?;

        Ok(Self {
            config,
            protocol: ExternalGroup::new(group_config, group_info, public_tree)?,
        })
    }

    pub fn process_incoming_bytes(
        &mut self,
        message: &[u8],
    ) -> Result<ProcessedMessage<ExternalEvent>, SessionError> {
        self.protocol
            .process_incoming_bytes(message)
            .map_err(Into::into)
    }

    fn signer_for_proposal(
        &self,
    ) -> Result<(SigningIdentity, <C::Keychain as Keychain>::Signer), SessionError> {
        let cipher_suite = self.protocol.cipher_suite();

        self.config
            .keychain()
            .default_identity(cipher_suite)
            .ok_or(SessionError::SigningIdentityNotFound(cipher_suite))
    }

    pub fn propose_add(
        &self,
        proposal: AddProposal,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let (signing_identity, signer) = self.signer_for_proposal()?;

        let add =
            self.protocol
                .propose_add(proposal, authenticated_data, &signing_identity, &signer)?;

        add.tls_serialize_detached().map_err(Into::into)
    }

    pub fn propose_remove(
        &self,
        proposal: RemoveProposal,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let (signing_identity, signer) = self.signer_for_proposal()?;

        let remove = self.protocol.propose_remove(
            proposal,
            authenticated_data,
            &signing_identity,
            &signer,
        )?;

        remove.tls_serialize_detached().map_err(Into::into)
    }
}
