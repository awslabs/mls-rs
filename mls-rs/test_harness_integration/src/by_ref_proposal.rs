use tonic::{Request, Response, Status};

use crate::mls_client::ProposalResponse;

#[tonic::async_trait]
pub(crate) trait ByRefProposalSender<T> {
    async fn propose(&self, request: Request<T>) -> Result<Response<ProposalResponse>, Status>;
}

#[cfg(feature = "by_ref_proposal")]
pub(crate) mod inner {
    use mls_rs::{
        extension::built_in::ExternalSendersExt,
        identity::{basic::BasicCredential, Credential, SigningIdentity},
        mls_rs_codec::MlsDecode,
        psk::ExternalPskId,
        Group, MlsMessage, ProtocolVersion,
    };
    use tonic::{Request, Response, Status};

    use crate::{
        abort, find_member, get_tree,
        mls_client::{
            AddExternalSignerRequest, AddProposalRequest, ExternalPskProposalRequest,
            ExternalSignerProposalRequest, GroupContextExtensionsProposalRequest, ProposalResponse,
            ReInitProposalRequest, RemoveProposalRequest, ResumptionPskProposalRequest,
            UpdateProposalRequest,
        },
        parse_extensions, MlsClientImpl, TestClientConfig, PROPOSAL_DESC_ADD, PROPOSAL_DESC_GCE,
        PROPOSAL_DESC_REMOVE,
    };

    #[cfg(feature = "psk")]
    use crate::{PROPOSAL_DESC_EXTERNAL_PSK, PROPOSAL_DESC_REINIT, PROPOSAL_DESC_RESUMPTION_PSK};

    use super::ByRefProposalSender;

    impl MlsClientImpl {
        pub(crate) async fn send_proposal<F>(
            &self,
            index: u32,
            propose: F,
        ) -> Result<Response<ProposalResponse>, Status>
        where
            F: FnOnce(&mut Group<TestClientConfig>) -> Result<MlsMessage, Status>,
        {
            let mut clients = self.clients.lock().await;

            let group = clients
                .get_mut(&index)
                .ok_or_else(|| Status::aborted("no group with such index."))?
                .group
                .as_mut()
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let proposal = propose(group).and_then(|p| p.to_bytes().map_err(abort))?;

            Ok(Response::new(ProposalResponse { proposal }))
        }
    }

    #[tonic::async_trait]
    impl ByRefProposalSender<GroupContextExtensionsProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<GroupContextExtensionsProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();

            self.send_proposal(request.state_id, move |group| {
                let ext = parse_extensions(request.extensions);

                group
                    .propose_group_context_extensions(ext, vec![])
                    .map_err(abort)
            })
            .await
        }
    }

    #[tonic::async_trait]
    impl ByRefProposalSender<ReInitProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<ReInitProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();

            self.send_proposal(request.state_id, move |group| {
                group
                    .propose_reinit(
                        Some(request.group_id),
                        ProtocolVersion::MLS_10,
                        (request.cipher_suite as u16).into(),
                        parse_extensions(request.extensions),
                        vec![],
                    )
                    .map_err(abort)
            })
            .await
        }
    }

    #[cfg(feature = "psk")]
    #[tonic::async_trait]
    impl ByRefProposalSender<ResumptionPskProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<ResumptionPskProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();

            self.send_proposal(request.state_id, move |group| {
                let epoch_id = request.epoch_id;

                group
                    .propose_resumption_psk(epoch_id, vec![])
                    .map_err(abort)
            })
            .await
        }
    }

    #[cfg(not(feature = "psk"))]
    #[tonic::async_trait]
    impl ByRefProposalSender<ResumptionPskProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            _: Request<ResumptionPskProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }
    }

    #[cfg(feature = "psk")]
    #[tonic::async_trait]
    impl ByRefProposalSender<ExternalPskProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<ExternalPskProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();

            self.send_proposal(request.state_id, move |group| {
                let psk_id = ExternalPskId::new(request.psk_id);
                group.propose_external_psk(psk_id, vec![]).map_err(abort)
            })
            .await
        }
    }

    #[cfg(not(feature = "psk"))]
    #[tonic::async_trait]
    impl ByRefProposalSender<ExternalPskProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            _: Request<ExternalPskProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }
    }

    #[tonic::async_trait]
    impl ByRefProposalSender<RemoveProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<RemoveProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();

            self.send_proposal(request.state_id, move |group| {
                let removed_cred = Credential::Basic(BasicCredential::new(request.removed_id));
                let removed_index = find_member(&group.roster().members(), &removed_cred)?;

                group.propose_remove(removed_index, vec![]).map_err(abort)
            })
            .await
        }
    }

    #[tonic::async_trait]
    impl ByRefProposalSender<UpdateProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<UpdateProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();

            self.send_proposal(request.state_id, move |group| {
                group.propose_update(vec![]).map_err(abort)
            })
            .await
        }
    }

    #[tonic::async_trait]
    impl ByRefProposalSender<AddProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<AddProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();
            let key_package = MlsMessage::from_bytes(&request.key_package).map_err(abort)?;

            self.send_proposal(request.state_id, move |group| {
                group.propose_add(key_package, vec![]).map_err(abort)
            })
            .await
        }
    }

    #[tonic::async_trait]
    impl ByRefProposalSender<AddExternalSignerRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<AddExternalSignerRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();

            self.send_proposal(request.state_id, move |group| {
                let mut extensions = group.context().extensions().clone();

                let ext_sender =
                    SigningIdentity::mls_decode(&mut &*request.external_sender).map_err(abort)?;

                let mut ext_senders = extensions
                    .get_as::<ExternalSendersExt>()
                    .map_err(abort)?
                    .unwrap_or(ExternalSendersExt::new(vec![]))
                    .allowed_senders
                    .to_vec();

                ext_senders.push(ext_sender);

                extensions
                    .set_from(ExternalSendersExt::new(ext_senders))
                    .map_err(abort)?;

                group
                    .propose_group_context_extensions(extensions, vec![])
                    .map_err(abort)
            })
            .await
        }
    }

    #[tonic::async_trait]
    impl ByRefProposalSender<ExternalSignerProposalRequest> for MlsClientImpl {
        async fn propose(
            &self,
            request: Request<ExternalSignerProposalRequest>,
        ) -> Result<Response<ProposalResponse>, Status> {
            let request = request.into_inner();
            let ext_clients = &mut self.external_clients.lock().await;

            let ext_client = ext_clients
                .get_mut(&request.signer_id)
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let group_info = MlsMessage::from_bytes(&request.group_info).map_err(abort)?;

            let mut server = ext_client
                .ext_client
                .observe_group(group_info, get_tree(&request.ratchet_tree)?)
                .map_err(abort)?;

            let proposal = request
                .description
                .ok_or_else(|| Status::aborted("proposal not found"))?;

            let proposal = match proposal.proposal_type.as_slice() {
                PROPOSAL_DESC_ADD => {
                    let key_package =
                        MlsMessage::from_bytes(&proposal.key_package).map_err(abort)?;

                    server.propose_add(key_package, vec![]).map_err(abort)
                }
                PROPOSAL_DESC_REMOVE => {
                    let cred = Credential::Basic(BasicCredential::new(proposal.removed_id.clone()));
                    let removed_index = find_member(&server.roster().members(), &cred)?;

                    server.propose_remove(removed_index, vec![]).map_err(abort)
                }
                #[cfg(feature = "psk")]
                PROPOSAL_DESC_EXTERNAL_PSK => server
                    .propose_external_psk(ExternalPskId::new(proposal.psk_id), vec![])
                    .map_err(abort),
                #[cfg(feature = "psk")]
                PROPOSAL_DESC_RESUMPTION_PSK => server
                    .propose_resumption_psk(proposal.epoch_id, vec![])
                    .map_err(abort),
                PROPOSAL_DESC_GCE => server
                    .propose_group_context_extensions(parse_extensions(proposal.extensions), vec![])
                    .map_err(abort),
                #[cfg(feature = "psk")]
                PROPOSAL_DESC_REINIT => server
                    .propose_reinit(
                        Some(proposal.group_id),
                        ProtocolVersion::MLS_10,
                        (proposal.cipher_suite as u16).into(),
                        parse_extensions(proposal.extensions),
                        vec![],
                    )
                    .map_err(abort),
                _ => Err(Status::aborted("unsupported proposal type")),
            }?;

            let resp = ProposalResponse {
                proposal: proposal.to_bytes().map_err(abort)?,
            };

            Ok(Response::new(resp))
        }
    }
}

#[cfg(not(feature = "by_ref_proposal"))]
pub(crate) mod inner {
    use crate::MlsClientImpl;

    use super::*;

    #[tonic::async_trait]
    impl<T: Send + Sync + 'static> ByRefProposalSender<T> for MlsClientImpl {
        async fn propose(&self, _: Request<T>) -> Result<Response<ProposalResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }
    }
}

#[cfg(feature = "by_ref_proposal")]
pub(crate) mod external_proposal {
    use mls_rs_crypto_openssl::OpensslCryptoProvider;
    use tonic::{Request, Response, Status};

    use mls_rs::{
        external_client::builder::ExternalClientBuilder,
        identity::{
            basic::{BasicCredential, BasicIdentityProvider},
            SigningIdentity,
        },
        mls_rs_codec::MlsEncode,
        CipherSuiteProvider, CryptoProvider, MlsMessage,
    };

    use crate::{
        abort, create_client,
        mls_client::{
            CreateExternalSignerRequest, CreateExternalSignerResponse, NewMemberAddProposalRequest,
            NewMemberAddProposalResponse,
        },
        ExternalClientDetails,
    };

    use crate::MlsClientImpl;

    impl MlsClientImpl {
        pub(crate) async fn new_member_add_proposal(
            &self,
            request: Request<NewMemberAddProposalRequest>,
        ) -> Result<Response<NewMemberAddProposalResponse>, Status> {
            let request = request.into_inner();

            let group_info = MlsMessage::from_bytes(&request.group_info).map_err(abort)?;

            let cipher_suite = group_info
                .cipher_suite()
                .ok_or(Status::aborted("message not group info"))?;

            let client = create_client(cipher_suite.into(), &request.identity).await?;

            let proposal = client
                .client
                .external_add_proposal(&group_info, None, vec![])
                .map_err(abort)?
                .to_bytes()
                .map_err(abort)?;

            let (_, key_pckg_secrets) = client.key_package_repo.key_packages()[0].clone();
            let signature_priv = client.signer.to_vec();

            let transaction_id = self.insert_client(client).await;

            let resp = NewMemberAddProposalResponse {
                transaction_id,
                proposal,
                init_priv: key_pckg_secrets.init_key.to_vec(),
                encryption_priv: key_pckg_secrets.leaf_node_key.to_vec(),
                signature_priv,
            };

            Ok(Response::new(resp))
        }

        pub(crate) async fn create_external_signer(
            &self,
            request: Request<CreateExternalSignerRequest>,
        ) -> Result<Response<CreateExternalSignerResponse>, Status> {
            let request = request.into_inner();

            let cs = OpensslCryptoProvider::new()
                .cipher_suite_provider((request.cipher_suite as u16).into())
                .ok_or_else(|| Status::aborted("ciphersuite not supported"))?;

            let (secret_key, public_key) = cs.signature_key_generate().map_err(abort)?;
            let credential = BasicCredential::new(request.identity).into_credential();
            let signing_identity = SigningIdentity::new(credential, public_key);

            let external_sender = signing_identity.mls_encode_to_vec().map_err(abort)?;

            let mut ext_clients = self.external_clients.lock().await;

            let ext_client = ExternalClientBuilder::new()
                .crypto_provider(OpensslCryptoProvider::default())
                .identity_provider(BasicIdentityProvider::new())
                .signer(secret_key, signing_identity)
                .build();

            let signer_id = *ext_clients.keys().max().unwrap_or(&0);

            ext_clients.insert(signer_id, ExternalClientDetails { ext_client });

            let resp = CreateExternalSignerResponse {
                signer_id,
                external_sender,
            };

            Ok(Response::new(resp))
        }
    }
}

#[cfg(not(feature = "by_ref_proposal"))]
pub(crate) mod external_proposal {
    use tonic::{Request, Response, Status};

    use crate::mls_client::{
        CreateExternalSignerRequest, CreateExternalSignerResponse, NewMemberAddProposalRequest,
        NewMemberAddProposalResponse,
    };

    use crate::MlsClientImpl;

    impl MlsClientImpl {
        pub(crate) async fn new_member_add_proposal(
            &self,
            _: Request<NewMemberAddProposalRequest>,
        ) -> Result<Response<NewMemberAddProposalResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }

        pub(crate) async fn create_external_signer(
            &self,
            _: Request<CreateExternalSignerRequest>,
        ) -> Result<Response<CreateExternalSignerResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }
    }
}
