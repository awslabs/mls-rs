//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client written by Richard Barnes.

use aws_mls::{
    aws_mls_codec::{MlsDecode, MlsEncode},
    external_client::{
        self,
        builder::{ExternalBaseConfig, ExternalClientBuilder},
        ExternalClient,
    },
    group::ReceivedMessage,
};

use aws_mls::{
    client_builder::{
        BaseConfig, ClientBuilder, Preferences, WithCryptoProvider, WithIdentityProvider,
        WithKeychain,
    },
    crypto::SignatureSecretKey,
    error::MlsError,
    extension::built_in::ExternalSendersExt,
    group::{Member, StateUpdate},
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        Credential, SigningIdentity,
    },
    storage_provider::{
        in_memory::{
            InMemoryKeyPackageStorage, InMemoryKeychainStorage, InMemoryPreSharedKeyStorage,
        },
        ExternalPskId,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, Group,
    MLSMessage, ProtocolVersion,
};

use aws_mls_crypto_openssl::OpensslCryptoProvider;
use clap::Parser;
use futures::future::{BoxFuture, FutureExt};
use std::net::IpAddr;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};

use mls_client::{
    AddExternalSignerRequest, AddProposalRequest, CommitRequest, CommitResponse,
    CreateBranchRequest, CreateExternalSignerRequest, CreateExternalSignerResponse,
    CreateGroupRequest, CreateGroupResponse, CreateKeyPackageRequest, CreateKeyPackageResponse,
    CreateSubgroupResponse, ExportRequest, ExportResponse, ExternalJoinRequest,
    ExternalJoinResponse, ExternalPskProposalRequest, ExternalSignerProposalRequest,
    GroupContextExtensionsProposalRequest, GroupInfoRequest, GroupInfoResponse,
    HandleBranchRequest, HandleBranchResponse, HandleCommitRequest, HandleCommitResponse,
    HandlePendingCommitRequest, HandleReInitCommitResponse, HandleReInitWelcomeRequest,
    JoinGroupRequest, JoinGroupResponse, NameRequest, NameResponse, NewMemberAddProposalRequest,
    NewMemberAddProposalResponse, ProposalResponse, ProtectRequest, ProtectResponse,
    ReInitProposalRequest, ReInitWelcomeRequest, RemoveProposalRequest,
    ResumptionPskProposalRequest, StateAuthRequest, StateAuthResponse, StorePskRequest,
    StorePskResponse, SupportedCiphersuitesRequest, SupportedCiphersuitesResponse,
    UnprotectRequest, UnprotectResponse, UpdateProposalRequest,
};

fn abort<T: std::fmt::Debug>(e: T) -> Status {
    Status::aborted(format!("Aborted with error {e:?}"))
}

pub mod mls_client {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "Wickr MLS";

const PROPOSAL_DESC_ADD: &[u8] = b"add";
const PROPOSAL_DESC_REMOVE: &[u8] = b"remove";
const PROPOSAL_DESC_EXTERNAL_PSK: &[u8] = b"externalPSK";
const PROPOSAL_DESC_RESUMPTION_PSK: &[u8] = b"resumptionPSK";
const PROPOSAL_DESC_GCE: &[u8] = b"groupContextExtensions";
const PROPOSAL_DESC_REINIT: &[u8] = b"reinit";

type TestClientConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithKeychain<InMemoryKeychainStorage, WithCryptoProvider<OpensslCryptoProvider, BaseConfig>>,
>;

type TestExternalClientConfig = external_client::builder::WithKeychain<
    InMemoryKeychainStorage,
    external_client::builder::WithIdentityProvider<
        BasicIdentityProvider,
        external_client::builder::WithCryptoProvider<OpensslCryptoProvider, ExternalBaseConfig>,
    >,
>;

#[derive(Default)]
pub struct MlsClientImpl {
    clients: Mutex<Vec<ClientDetails>>,
    external_clients: Mutex<Vec<ExternalClientDetails>>,
}

struct ClientDetails {
    client: Client<TestClientConfig>,
    psk_store: InMemoryPreSharedKeyStorage,
    control_encryption: bool,
    group: Option<Group<TestClientConfig>>,
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    keychain: InMemoryKeychainStorage,
    key_package_repo: InMemoryKeyPackageStorage,
}

struct ExternalClientDetails {
    ext_client: ExternalClient<TestExternalClientConfig>,
    signing_identity: SigningIdentity,
}

#[tonic::async_trait]
impl MlsClient for MlsClientImpl {
    async fn name(&self, _request: Request<NameRequest>) -> Result<Response<NameResponse>, Status> {
        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn supported_ciphersuites(
        &self,
        _request: tonic::Request<SupportedCiphersuitesRequest>,
    ) -> Result<tonic::Response<SupportedCiphersuitesResponse>, tonic::Status> {
        let response = SupportedCiphersuitesResponse {
            ciphersuites: CipherSuite::all().map(|cs| u16::from(cs) as u32).collect(),
        };

        Ok(Response::new(response))
    }

    async fn create_group(
        &self,
        request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        let request = request.into_inner();

        let mut client = create_client(request.cipher_suite as u16, &request.identity).await?;

        let group = client
            .client
            .create_group_with_id(
                ProtocolVersion::MLS_10,
                (request.cipher_suite as u16).into(),
                request.group_id,
                client.signing_identity.clone(),
                ExtensionList::default(),
            )
            .await
            .map_err(abort)?;

        client.group = Some(group);
        client.control_encryption = request.encrypt_handshake;

        let mut clients = self.clients.lock().await;
        clients.push(client);

        Ok(Response::new(CreateGroupResponse {
            state_id: clients.len() as u32 - 1,
        }))
    }

    async fn create_key_package(
        &self,
        request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let request = request.into_inner();

        let client = create_client(request.cipher_suite as u16, &request.identity).await?;

        let key_package = client
            .client
            .generate_key_package_message(
                ProtocolVersion::MLS_10,
                (request.cipher_suite as u16).into(),
                client.signing_identity.clone(),
            )
            .await
            .map_err(abort)?;

        let (_, key_pckg_secrets) = client.key_package_repo.key_packages()[0].clone();
        let signature_priv = client.signer.to_vec();

        let mut clients = self.clients.lock().await;
        clients.push(client);

        let resp = CreateKeyPackageResponse {
            transaction_id: clients.len() as u32 - 1,
            key_package: key_package.to_bytes().map_err(abort)?,
            init_priv: key_pckg_secrets.init_key.to_vec(),
            encryption_priv: key_pckg_secrets.leaf_node_key.to_vec(),
            signature_priv,
        };

        Ok(Response::new(resp))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut clients = self.clients.lock().await;

        let welcome_msg = MLSMessage::from_bytes(&request.welcome).map_err(abort)?;

        let client = clients
            .get_mut(request.transaction_id as usize)
            .ok_or_else(|| Status::aborted("no client with such index"))?;

        let (group, _) = client
            .client
            .join_group(get_tree(&request.ratchet_tree), welcome_msg)
            .await
            .map_err(abort)?;

        let epoch_authenticator = group.epoch_authenticator().map_err(abort)?.to_vec();
        client.group = Some(group);
        client.control_encryption = request.encrypt_handshake;

        Ok(Response::new(JoinGroupResponse {
            state_id: request.transaction_id,
            epoch_authenticator,
        }))
    }

    async fn external_join(
        &self,
        request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        let request = request.into_inner();

        let group_info = MLSMessage::from_bytes(&request.group_info).map_err(abort)?;
        let tree = get_tree(&request.ratchet_tree);

        let cipher_suite = group_info
            .cipher_suite()
            .ok_or_else(|| Status::aborted("ciphersuite not found"))?;

        let mut client = create_client(cipher_suite.into(), &request.identity).await?;
        client.control_encryption = request.encrypt_handshake;

        for psk in request.psks.clone().into_iter() {
            client
                .psk_store
                .insert(psk.psk_id.into(), psk.psk_secret.into());
        }

        let removed_index = if request.remove_prior {
            // Create a server to inspect the group and find the old copy
            let server = ExternalClient::builder()
                .crypto_provider(OpensslCryptoProvider::default())
                .identity_provider(BasicIdentityProvider::new())
                .build();

            let server = server
                .observe_group(group_info.clone(), tree)
                .await
                .map_err(abort)?;

            let idx = find_member(&server.roster(), &client.signing_identity.credential)?;
            Some(idx)
        } else {
            None
        };

        let (group, commit) = client
            .client
            .commit_external(
                group_info.clone(),
                tree,
                client.signing_identity.clone(),
                removed_index,
                vec![],
                vec![],
            )
            .await
            .map_err(abort)?;

        let epoch_authenticator = group.epoch_authenticator().map_err(abort)?.to_vec();

        client.group = Some(group);
        let mut clients = self.clients.lock().await;
        clients.push(client);

        let resp = ExternalJoinResponse {
            state_id: clients.len() as u32 - 1,
            commit: commit.to_bytes().unwrap(),
            epoch_authenticator,
        };

        Ok(Response::new(resp))
    }

    async fn group_info(
        &self,
        request: tonic::Request<GroupInfoRequest>,
    ) -> Result<tonic::Response<GroupInfoResponse>, tonic::Status> {
        let request = request.into_inner();

        let groups = self.clients.lock().await;

        let group = groups
            .get(request.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .group
            .as_ref()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let group_info = group
            .group_info_message_allowing_ext_commit()
            .await
            .and_then(|m| m.to_bytes())
            .map_err(abort)?;

        Ok(Response::new(GroupInfoResponse {
            group_info,
            ratchet_tree: group.export_tree().map_err(abort)?,
        }))
    }

    async fn state_auth(
        &self,
        _request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        // TODO
        Ok(Response::new(StateAuthResponse::default()))
    }

    async fn export(
        &self,
        _request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        // TODO
        Ok(Response::new(ExportResponse::default()))
    }

    async fn protect(
        &self,
        request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut clients = self.clients.lock().await;

        let ciphertext = clients
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .encrypt_application_message(&request.plaintext, request.authenticated_data)
            .await
            .and_then(|m| m.to_bytes())
            .map_err(abort)?;

        Ok(Response::new(ProtectResponse { ciphertext }))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut clients = self.clients.lock().await;
        let ciphertext = MLSMessage::from_bytes(&request.ciphertext).map_err(abort)?;

        let message = clients
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .process_incoming_message(ciphertext)
            .await
            .map_err(abort)?;

        let app_msg = match message {
            ReceivedMessage::ApplicationMessage(app_msg) => app_msg,
            _ => return Err(Status::aborted("message type is not application data.")),
        };

        Ok(Response::new(UnprotectResponse {
            plaintext: app_msg.data().to_vec(),
            authenticated_data: app_msg.authenticated_data,
        }))
    }

    async fn store_psk(
        &self,
        request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        let request = request.into_inner();

        self.clients
            .lock()
            .await
            .get_mut(request.state_or_transaction_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .psk_store
            .insert(
                ExternalPskId::new(request.psk_id),
                request.psk_secret.into(),
            );

        Ok(Response::new(StorePskResponse::default()))
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();
        let key_package = MLSMessage::from_bytes(&request.key_package).map_err(abort)?;

        self.send_proposal(request.state_id, move |group| {
            Ok(group.propose_add(key_package, vec![]).boxed())
        })
        .await
    }

    async fn update_proposal(
        &self,
        request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        self.send_proposal(request.state_id, move |group| {
            Ok(group.propose_update(vec![]).boxed())
        })
        .await
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        self.send_proposal(request.state_id, move |group| {
            let removed_cred = Credential::Basic(BasicCredential::new(request.removed_id));
            let removed_index = find_member(&group.roster(), &removed_cred)?;
            Ok(group.propose_remove(removed_index, vec![]).boxed())
        })
        .await
    }

    async fn external_psk_proposal(
        &self,
        request: tonic::Request<ExternalPskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        self.send_proposal(request.state_id, move |group| {
            let psk_id = ExternalPskId::new(request.psk_id);
            Ok(group.propose_external_psk(psk_id, vec![]).boxed())
        })
        .await
    }

    async fn resumption_psk_proposal(
        &self,
        request: tonic::Request<ResumptionPskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        self.send_proposal(request.state_id, move |group| {
            let epoch_id = request.epoch_id;
            Ok(group.propose_resumption_psk(epoch_id, vec![]).boxed())
        })
        .await
    }

    async fn re_init_proposal(
        &self,
        request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        self.send_proposal(request.state_id, move |group| {
            Ok(group
                .propose_reinit(
                    Some(request.group_id),
                    ProtocolVersion::MLS_10,
                    (request.cipher_suite as u16).into(),
                    parse_extensions(request.extensions),
                    vec![],
                )
                .boxed())
        })
        .await
    }

    async fn group_context_extensions_proposal(
        &self,
        request: tonic::Request<GroupContextExtensionsProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        self.send_proposal(request.state_id, move |group| {
            let ext = parse_extensions(request.extensions);
            Ok(group.propose_group_context_extensions(ext, vec![]).boxed())
        })
        .await
    }

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        self.commit(request).await
    }

    async fn re_init_commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        self.commit(request).await
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        Ok(self.handle_commit(request).await?.0)
    }

    async fn handle_re_init_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleReInitCommitResponse>, tonic::Status> {
        let (commit_resp, update) = self.handle_commit(request).await?;
        self.handle_re_init_commit(commit_resp, update).await
    }

    async fn handle_pending_re_init_commit(
        &self,
        request: tonic::Request<HandlePendingCommitRequest>,
    ) -> Result<tonic::Response<HandleReInitCommitResponse>, tonic::Status> {
        let request = request.into_inner();

        let (resp, update) = {
            let clients = &mut self.clients.lock().await;

            let group = clients
                .get_mut(request.state_id as usize)
                .ok_or_else(|| Status::aborted("no group with such index."))?
                .group
                .as_mut()
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let update = group.apply_pending_commit().await.map_err(abort)?;

            let resp = HandleCommitResponse {
                state_id: request.state_id,
                epoch_authenticator: group.epoch_authenticator().map_err(abort)?.to_vec(),
            };

            (resp, update)
        };

        self.handle_re_init_commit(Response::new(resp), update.state_update)
            .await
    }

    async fn handle_pending_commit(
        &self,
        request: tonic::Request<HandlePendingCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let request_ref = request.into_inner();
        let clients = &mut self.clients.lock().await;

        let group = clients
            .get_mut(request_ref.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        group.apply_pending_commit().await.map_err(abort)?;

        let resp = HandleCommitResponse {
            state_id: request_ref.state_id,
            epoch_authenticator: group.epoch_authenticator().map_err(abort)?.to_vec(),
        };

        Ok(Response::new(resp))
    }

    async fn re_init_welcome(
        &self,
        request: tonic::Request<ReInitWelcomeRequest>,
    ) -> Result<tonic::Response<CreateSubgroupResponse>, tonic::Status> {
        let request = request.into_inner();

        self.branch_or_reinit(
            request.reinit_id,
            &request.key_package,
            request.force_path,
            request.external_tree,
            None,
        )
        .await
    }

    async fn handle_re_init_welcome(
        &self,
        request: tonic::Request<HandleReInitWelcomeRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let request = request.into_inner();
        let clients = &mut self.clients.lock().await;

        let mut client = clients
            .get_mut(request.reinit_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let group = client
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let welcome = MLSMessage::from_bytes(&request.welcome).map_err(abort)?;

        let (group, _tree) = group
            .finish_reinit_join(welcome, get_tree(&request.ratchet_tree))
            .await
            .map_err(abort)?;

        let resp = JoinGroupResponse {
            epoch_authenticator: group.epoch_authenticator().map_err(abort)?.to_vec(),
            state_id: request.reinit_id,
        };

        client.group = Some(group);

        Ok(Response::new(resp))
    }

    async fn create_branch(
        &self,
        request: Request<CreateBranchRequest>,
    ) -> Result<Response<CreateSubgroupResponse>, tonic::Status> {
        let request = request.into_inner();

        self.branch_or_reinit(
            request.state_id,
            &request.key_packages,
            request.force_path,
            request.external_tree,
            Some(request.group_id),
        )
        .await
    }

    async fn handle_branch(
        &self,
        request: Request<HandleBranchRequest>,
    ) -> Result<Response<HandleBranchResponse>, tonic::Status> {
        let request = request.into_inner();
        let clients = &mut self.clients.lock().await;

        // Find the key package generated earlier based on the transaction_id
        let (id, key_package_data) = {
            let key_package_client = clients
                .get(request.transaction_id as usize)
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            key_package_client.key_package_repo.key_packages()[0].clone()
        };

        let mut client = clients
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        // Insert the previously created key package
        client.key_package_repo.insert(id, key_package_data);

        let group = client
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let tree = get_tree(&request.ratchet_tree);
        let welcome = MLSMessage::from_bytes(&request.welcome).map_err(abort)?;

        let (new_group, _info) = group.join_subgroup(welcome, tree).await.map_err(abort)?;

        let resp = HandleBranchResponse {
            state_id: request.state_id,
            epoch_authenticator: new_group.epoch_authenticator().map_err(abort)?.to_vec(),
        };

        client.group = Some(new_group);

        Ok(Response::new(resp))
    }

    async fn new_member_add_proposal(
        &self,
        request: Request<NewMemberAddProposalRequest>,
    ) -> Result<Response<NewMemberAddProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        let group_info = MLSMessage::from_bytes(&request.group_info).map_err(abort)?;

        let cipher_suite = group_info
            .cipher_suite()
            .ok_or(Status::aborted("message not group info"))?;

        let client = create_client(cipher_suite.into(), &request.identity).await?;

        let proposal = client
            .client
            .external_add_proposal(group_info, None, client.signing_identity.clone(), vec![])
            .await
            .map_err(abort)?
            .to_bytes()
            .map_err(abort)?;

        let (_, key_pckg_secrets) = client.key_package_repo.key_packages()[0].clone();
        let signature_priv = client.signer.to_vec();

        let mut clients = self.clients.lock().await;
        clients.push(client);

        let resp = NewMemberAddProposalResponse {
            transaction_id: clients.len() as u32 - 1,
            proposal,
            init_priv: key_pckg_secrets.init_key.to_vec(),
            encryption_priv: key_pckg_secrets.leaf_node_key.to_vec(),
            signature_priv,
        };

        Ok(Response::new(resp))
    }

    async fn create_external_signer(
        &self,
        request: Request<CreateExternalSignerRequest>,
    ) -> Result<Response<CreateExternalSignerResponse>, tonic::Status> {
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
            .single_signing_identity(signing_identity.clone(), secret_key, cs.cipher_suite())
            .build();

        ext_clients.push(ExternalClientDetails {
            ext_client,
            signing_identity,
        });

        let resp = CreateExternalSignerResponse {
            signer_id: ext_clients.len() as u32 - 1,
            external_sender,
        };

        Ok(Response::new(resp))
    }

    async fn add_external_signer(
        &self,
        request: Request<AddExternalSignerRequest>,
    ) -> Result<Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();

        self.send_proposal(request.state_id, move |group| {
            let mut extensions = group.context_extensions().clone();

            let ext_sender =
                SigningIdentity::mls_decode(&mut &*request.external_sender).map_err(abort)?;

            let mut ext_senders = extensions
                .get_as::<ExternalSendersExt>()
                .map_err(abort)?
                .unwrap_or(ExternalSendersExt::new(vec![]))
                .allowed_senders()
                .to_vec();

            ext_senders.push(ext_sender);

            extensions
                .set_from(ExternalSendersExt::new(ext_senders))
                .map_err(abort)?;

            Ok(group
                .propose_group_context_extensions(extensions, vec![])
                .boxed())
        })
        .await
    }

    async fn external_signer_proposal(
        &self,
        request: Request<ExternalSignerProposalRequest>,
    ) -> Result<Response<ProposalResponse>, tonic::Status> {
        let request = request.into_inner();
        let ext_clients = &mut self.external_clients.lock().await;

        let ext_client = ext_clients
            .get_mut(request.signer_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let group_info = MLSMessage::from_bytes(&request.group_info).map_err(abort)?;

        let mut server = ext_client
            .ext_client
            .observe_group(group_info, get_tree(&request.ratchet_tree))
            .await
            .map_err(abort)?;

        let proposal = request
            .description
            .ok_or_else(|| Status::aborted("proposal not found"))?;

        let server_id = &ext_client.signing_identity;

        let proposal = match proposal.proposal_type.as_slice() {
            PROPOSAL_DESC_ADD => {
                let key_package = MLSMessage::from_bytes(&proposal.key_package).map_err(abort)?;

                server
                    .propose_add(key_package, server_id, vec![])
                    .await
                    .map_err(abort)
            }
            PROPOSAL_DESC_REMOVE => {
                let cred = Credential::Basic(BasicCredential::new(proposal.removed_id.clone()));
                let removed_index = find_member(&server.roster(), &cred)?;

                server
                    .propose_remove(removed_index, server_id, vec![])
                    .await
                    .map_err(abort)
            }
            PROPOSAL_DESC_EXTERNAL_PSK => server
                .propose_external_psk(ExternalPskId::new(proposal.psk_id), server_id, vec![])
                .await
                .map_err(abort),
            PROPOSAL_DESC_RESUMPTION_PSK => server
                .propose_resumption_psk(proposal.epoch_id, server_id, vec![])
                .await
                .map_err(abort),
            PROPOSAL_DESC_GCE => server
                .propose_group_context_extensions(
                    parse_extensions(proposal.extensions),
                    server_id,
                    vec![],
                )
                .await
                .map_err(abort),
            PROPOSAL_DESC_REINIT => server
                .propose_reinit(
                    Some(proposal.group_id),
                    ProtocolVersion::MLS_10,
                    (proposal.ciphersuite as u16).into(),
                    parse_extensions(proposal.extensions),
                    server_id,
                    vec![],
                )
                .await
                .map_err(abort),
            _ => Err(Status::aborted("unsupported proposal type")),
        }?;

        let resp = ProposalResponse {
            proposal: proposal.to_bytes().map_err(abort)?,
        };

        Ok(Response::new(resp))
    }
}

impl MlsClientImpl {
    async fn branch_or_reinit(
        &self,
        client_id: u32,
        key_packages: &[Vec<u8>],
        force_path: bool,
        external_tree: bool,
        subgroup_id: Option<Vec<u8>>,
    ) -> Result<tonic::Response<CreateSubgroupResponse>, tonic::Status> {
        let clients = &mut self.clients.lock().await;

        let client = clients
            .get_mut(client_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let group = client
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let new_key_pkgs = key_packages
            .iter()
            .map(|kp| MLSMessage::from_bytes(kp))
            .collect::<Result<_, _>>()
            .map_err(abort)?;

        let mut preferences = group.preferences();
        preferences.encrypt_controls = client.control_encryption;
        preferences.force_commit_path_update = force_path;
        preferences.ratchet_tree_extension = !external_tree;

        let (new_group, welcome) = if let Some(id) = subgroup_id {
            group
                .branch(id, new_key_pkgs, Some(preferences))
                .await
                .map_err(abort)?
        } else {
            group
                .finish_reinit_commit(
                    new_key_pkgs,
                    Some(client.signing_identity.clone()),
                    Some(preferences),
                )
                .await
                .map_err(abort)?
        };

        let welcome = welcome
            .map(|msg| msg.to_bytes())
            .transpose()
            .map_err(abort)?
            .unwrap_or_default();

        let ratchet_tree = if external_tree {
            new_group.export_tree().unwrap()
        } else {
            vec![]
        };

        let resp = CreateSubgroupResponse {
            epoch_authenticator: new_group.epoch_authenticator().map_err(abort)?.to_vec(),
            state_id: client_id,
            welcome,
            ratchet_tree,
        };

        client.group = Some(new_group);

        Ok(Response::new(resp))
    }

    async fn handle_re_init_commit(
        &self,
        commit_resp: tonic::Response<HandleCommitResponse>,
        update: StateUpdate,
    ) -> Result<tonic::Response<HandleReInitCommitResponse>, tonic::Status> {
        let commit_resp = commit_resp.into_inner();
        let mut clients = self.clients.lock().await;

        let client = clients
            .get_mut(commit_resp.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let group = client
            .group
            .as_ref()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        // Generate a signing identity for the possibly new ciphersuite after reinit
        let cipher_suite = update
            .pending_reinit_ciphersuite()
            .ok_or_else(|| Status::aborted("reinit not found in commit"))?;

        let provider = OpensslCryptoProvider::new()
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| Status::aborted("ciphersuite not supported"))?;

        let (secret_key, public_key) = provider.signature_key_generate().map_err(abort)?;

        let credential = group
            .current_member_signing_identity()
            .map_err(abort)?
            .credential
            .clone();

        let signing_identity = SigningIdentity::new(credential, public_key);

        // Store the new identity s.t. the group and client can use it
        client
            .keychain
            .insert(signing_identity.clone(), secret_key, cipher_suite);

        // Generate a key packge used to join the new group after reinit
        let key_package = client
            .client
            .generate_key_package_message(
                ProtocolVersion::MLS_10,
                cipher_suite,
                signing_identity.clone(),
            )
            .await
            .map_err(abort)?;

        let resp = HandleReInitCommitResponse {
            epoch_authenticator: commit_resp.epoch_authenticator,
            key_package: key_package.to_bytes().map_err(abort)?,
            reinit_id: commit_resp.state_id,
        };

        client.signing_identity = signing_identity;

        Ok(Response::new(resp))
    }

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut clients = self.clients.lock().await;

        let client = clients
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let group = client
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        for proposal_bytes in &request.by_reference {
            let proposal = MLSMessage::from_bytes(proposal_bytes).map_err(abort)?;

            match group.process_incoming_message(proposal).await {
                Ok(_) | Err(MlsError::CantProcessMessageFromSelf) => Ok(()),
                Err(e) => Err(abort(e)),
            }?;
        }

        let mut preferences = group.preferences();
        preferences.encrypt_controls = client.control_encryption;
        preferences.force_commit_path_update = request.force_path;
        preferences.ratchet_tree_extension = !request.external_tree;

        let roster = group.roster();

        let mut commit_builder = group.commit_builder().set_commit_preferences(preferences);

        for proposal in request.by_value {
            match proposal.proposal_type.as_slice() {
                PROPOSAL_DESC_ADD => {
                    let key_package =
                        MLSMessage::from_bytes(&proposal.key_package).map_err(abort)?;

                    commit_builder = commit_builder.add_member(key_package).map_err(abort)?;
                }
                PROPOSAL_DESC_REMOVE => {
                    let cred = Credential::Basic(BasicCredential::new(proposal.removed_id.clone()));

                    commit_builder = commit_builder
                        .remove_member(find_member(&roster, &cred)?)
                        .map_err(abort)?;
                }
                PROPOSAL_DESC_EXTERNAL_PSK => {
                    let psk_id = ExternalPskId::new(proposal.psk_id.to_vec());
                    commit_builder = commit_builder.add_external_psk(psk_id).map_err(abort)?;
                }
                PROPOSAL_DESC_RESUMPTION_PSK => {
                    commit_builder = commit_builder
                        .add_resumption_psk(proposal.epoch_id)
                        .map_err(abort)?;
                }
                PROPOSAL_DESC_GCE => {
                    commit_builder = commit_builder
                        .set_group_context_ext(parse_extensions(proposal.extensions.clone()))
                        .map_err(abort)?;
                }
                _ => (),
            }
        }

        let commit_output = commit_builder.build().await.map_err(abort)?;

        let mut group_clone = group.clone();
        group_clone.apply_pending_commit().await.unwrap();

        let ratchet_tree = if request.external_tree {
            group_clone.export_tree().unwrap()
        } else {
            vec![]
        };

        let welcome = commit_output
            .welcome_message
            .map(|w| w.to_bytes())
            .transpose()
            .map_err(abort)?
            .unwrap_or_default();

        let resp = CommitResponse {
            commit: commit_output.commit_message.to_bytes().map_err(abort)?,
            welcome,
            ratchet_tree,
        };

        Ok(Response::new(resp))
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<(tonic::Response<HandleCommitResponse>, StateUpdate), tonic::Status> {
        let request = request.into_inner();
        let clients = &mut self.clients.lock().await;

        let group = clients
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        for proposal in &request.proposal {
            let proposal = MLSMessage::from_bytes(proposal).map_err(abort)?;

            match group.process_incoming_message(proposal).await {
                Ok(_) | Err(MlsError::CantProcessMessageFromSelf) => Ok(()),
                Err(e) => Err(abort(e)),
            }?;
        }

        let commit = MLSMessage::from_bytes(&request.commit).map_err(abort)?;

        let message = group
            .process_incoming_message(commit)
            .await
            .map_err(abort)?;

        let resp = HandleCommitResponse {
            state_id: request.state_id,
            epoch_authenticator: group.epoch_authenticator().map_err(abort)?.to_vec(),
        };

        match message {
            ReceivedMessage::Commit(update) => Ok((Response::new(resp), update.state_update)),
            _ => Err(Status::aborted("message not a commit.")),
        }
    }

    async fn send_proposal<F>(
        &self,
        index: u32,
        propose: F,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status>
    where
        F: FnOnce(
            &mut Group<TestClientConfig>,
        ) -> Result<BoxFuture<'_, Result<MLSMessage, MlsError>>, tonic::Status>,
    {
        let mut clients = self.clients.lock().await;

        let group = clients
            .get_mut(index as usize)
            .ok_or_else(|| Status::aborted("no group with such index."))?
            .group
            .as_mut()
            .ok_or_else(|| Status::aborted("no group with such index."))?;

        let proposal = propose(group)?
            .await
            .and_then(|p| p.to_bytes())
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse { proposal }))
    }
}

async fn create_client(cipher_suite: u16, identity: &[u8]) -> Result<ClientDetails, Status> {
    let cipher_suite = CipherSuite::from(cipher_suite);

    let provider = OpensslCryptoProvider::new()
        .cipher_suite_provider(cipher_suite)
        .ok_or_else(|| Status::aborted("ciphersuite not supported"))?;

    let (secret_key, public_key) = provider.signature_key_generate().map_err(abort)?;
    let credential = BasicCredential::new(identity.to_vec()).into_credential();
    let signing_identity = SigningIdentity::new(credential, public_key);
    let mut keychain = InMemoryKeychainStorage::default();
    keychain.insert(signing_identity.clone(), secret_key.clone(), cipher_suite);

    let psk_store = InMemoryPreSharedKeyStorage::default();
    let key_package_repo = InMemoryKeyPackageStorage::new();

    let client = ClientBuilder::new()
        .crypto_provider(OpensslCryptoProvider::default())
        .identity_provider(BasicIdentityProvider::new())
        .keychain(keychain.clone())
        .preferences(Preferences::default().with_ratchet_tree_extension(true))
        .psk_store(psk_store.clone())
        .key_package_repo(key_package_repo.clone())
        .build();

    Ok(ClientDetails {
        client,
        psk_store,
        group: None,
        control_encryption: false,
        signing_identity,
        signer: secret_key,
        keychain,
        key_package_repo,
    })
}

fn get_tree(tree: &[u8]) -> Option<&[u8]> {
    if tree.is_empty() {
        None
    } else {
        Some(tree)
    }
}

fn parse_extensions(extensions: Vec<mls_client::Extension>) -> ExtensionList {
    extensions
        .into_iter()
        .map(|e| Extension::new((e.extension_type as u16).into(), e.extension_data))
        .collect::<Vec<_>>()
        .into()
}

fn find_member(roster: &[Member], cred: &Credential) -> Result<u32, Status> {
    roster
        .iter()
        .find(|member| &member.signing_identity().credential == cred)
        .map(|member| member.index())
        .ok_or_else(|| Status::aborted(format!("member \"{:?}\" not found", cred)))
}

#[derive(Parser)]
struct Opts {
    #[clap(short, long, value_parser, default_value = "0.0.0.0")]
    host: IpAddr,

    #[clap(short, long, value_parser, default_value = "50002")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    let mls_client_impl = MlsClientImpl::default();

    println!("serving on host {} port {}", opts.host, opts.port);

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve((opts.host, opts.port).into())
        .await?;

    Ok(())
}
