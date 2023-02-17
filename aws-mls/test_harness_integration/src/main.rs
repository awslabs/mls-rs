//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client written by Richard Barnes.

use aws_mls::client_builder::{
    BaseConfig, ClientBuilder, Preferences, WithCryptoProvider, WithIdentityProvider, WithKeychain,
};
use aws_mls::group::{Event, StateUpdate};
use aws_mls::identity::basic::{BasicCredential, BasicIdentityProvider};
use aws_mls::identity::SigningIdentity;
use aws_mls::storage_provider::in_memory::{InMemoryKeychainStorage, InMemoryPreSharedKeyStorage};
use aws_mls::storage_provider::{ExternalPskId, PreSharedKey};
use aws_mls::tls_codec::{Deserialize, Serialize};
use aws_mls::Group;
use aws_mls::MLSMessage;
use aws_mls::ProtocolVersion;
use aws_mls::{CipherSuite, CryptoProvider};
use aws_mls::{CipherSuiteProvider, Client};
use aws_mls::{Extension, ExtensionList};

use aws_mls_crypto_openssl::OpensslCryptoProvider;
use clap::Parser;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::ops::Deref;
use tokio::sync::Mutex;
use tonic::{transport::Server, Code::Aborted, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
// TODO(RLB) Convert this back to more specific `use` directives
use mls_client::*;

fn abort<T: std::fmt::Debug>(e: T) -> Status {
    Status::new(Aborted, format!("Aborted with error {e:?}"))
}

pub mod mls_client {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "AWS MLS";
const TEST_VECTOR: [u8; 4] = [0, 1, 2, 3];

impl TryFrom<i32> for TestVectorType {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TestVectorType::TreeMath),
            1 => Ok(TestVectorType::Encryption),
            2 => Ok(TestVectorType::KeySchedule),
            3 => Ok(TestVectorType::Transcript),
            4 => Ok(TestVectorType::Treekem),
            5 => Ok(TestVectorType::Messages),
            _ => Err(()),
        }
    }
}

impl TryFrom<(StateUpdate, u32)> for HandleCommitResponse {
    type Error = Status;

    fn try_from((state_update, state_id): (StateUpdate, u32)) -> Result<Self, Self::Error> {
        let added = state_update
            .roster_update()
            .added()
            .iter()
            .map(|member| member.index())
            .collect();

        let updated_indices = state_update
            .roster_update()
            .updated()
            .iter()
            .map(|member| member.index())
            .collect();

        let removed_indices = state_update
            .roster_update()
            .removed()
            .iter()
            .map(|removed| removed.index())
            .collect();

        let removed_leaves = state_update
            .roster_update()
            .removed()
            .iter()
            .map(|member| member.leaf_bytes().to_vec())
            .collect::<Vec<_>>();

        let psks = state_update
            .added_psks()
            .iter()
            .map(|psk_id| psk_id.tls_serialize_detached())
            .collect::<Result<Vec<_>, _>>()
            .map_err(abort)?;

        Ok(Self {
            state_id,
            added,
            updated: updated_indices,
            removed_indices,
            removed_leaves,
            psks,
            active: state_update.is_active() as u32,
        })
    }
}

type TestClientConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithKeychain<InMemoryKeychainStorage, WithCryptoProvider<OpensslCryptoProvider, BaseConfig>>,
>;

#[derive(Default)]
pub struct MlsClientImpl {
    clients: Mutex<Vec<ClientDetails>>,
    groups: Mutex<Vec<GroupDetails>>,
}

struct ClientDetails {
    client: Client<TestClientConfig>,
    psk_store: InMemoryPreSharedKeyStorage,
}

struct GroupDetails {
    group: Group<TestClientConfig>,
    psk_store: InMemoryPreSharedKeyStorage,
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

    /* Taken verbatim from the mock client. It will likely be deleted. */
    async fn generate_test_vector(
        &self,
        request: tonic::Request<GenerateTestVectorRequest>,
    ) -> Result<tonic::Response<GenerateTestVectorResponse>, tonic::Status> {
        println!("Got GenerateTestVector request");

        let obj = request.get_ref();
        let type_msg = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => "Tree math",
            Ok(TestVectorType::Encryption) => "Encryption",
            Ok(TestVectorType::KeySchedule) => "Key Schedule",
            Ok(TestVectorType::Transcript) => "Transcript",
            Ok(TestVectorType::Treekem) => "TreeKEM",
            Ok(TestVectorType::Messages) => "Messages",
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{type_msg} test vector request");

        let response = GenerateTestVectorResponse {
            test_vector: TEST_VECTOR.to_vec(),
        };

        Ok(Response::new(response))
    }

    async fn verify_test_vector(
        &self,
        request: tonic::Request<VerifyTestVectorRequest>,
    ) -> Result<tonic::Response<VerifyTestVectorResponse>, tonic::Status> {
        println!("Got VerifyTestVector request");

        let obj = request.get_ref();
        let type_msg = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => "Tree math",
            Ok(TestVectorType::Encryption) => "Encryption",
            Ok(TestVectorType::KeySchedule) => "Key Schedule",
            Ok(TestVectorType::Transcript) => "Transcript",
            Ok(TestVectorType::Treekem) => "TreeKEM",
            Ok(TestVectorType::Messages) => "Messages",
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{type_msg} test vector request");

        if obj.test_vector != TEST_VECTOR {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid test vector",
            ));
        }

        Ok(Response::new(VerifyTestVectorResponse::default()))
    }

    async fn create_group(
        &self,
        request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        let request_ref = request.into_inner();

        let cipher_suite = CipherSuite::from(request_ref.cipher_suite as u16);

        let provider = OpensslCryptoProvider::new()
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| Status::new(Aborted, "ciphersuite not supported"))?;

        let (secret_key, public_key) = provider.signature_key_generate().map_err(abort)?;

        let credential = BasicCredential::new(b"creator".to_vec()).into_credential();

        let signing_identity = SigningIdentity::new(credential, public_key);

        let psk_store = InMemoryPreSharedKeyStorage::default();

        let creator = Client::builder()
            .identity_provider(BasicIdentityProvider::new())
            .crypto_provider(OpensslCryptoProvider::default())
            .single_signing_identity(signing_identity.clone(), secret_key, cipher_suite)
            .preferences(Preferences::default().with_ratchet_tree_extension(true))
            .psk_store(psk_store.clone())
            .build();

        let group = creator
            .create_group_with_id(
                ProtocolVersion::MLS_10,
                cipher_suite,
                request_ref.group_id,
                signing_identity,
                ExtensionList::default(),
            )
            .await
            .map_err(abort)?;

        let mut groups = self.groups.lock().await;
        groups.push(GroupDetails { group, psk_store });

        Ok(Response::new(CreateGroupResponse {
            state_id: groups.len() as u32,
        }))
    }

    async fn create_key_package(
        &self,
        request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut clients = self.clients.lock().await;

        let cipher_suite = CipherSuite::from(request_ref.cipher_suite as u16);

        let provider = OpensslCryptoProvider::new()
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| Status::new(Aborted, "ciphersuite not supported"))?;

        let (secret_key, public_key) = provider.signature_key_generate().map_err(abort)?;

        let credential =
            BasicCredential::new(format!("alice{}", clients.len()).into_bytes()).into_credential();

        let signing_identity = SigningIdentity::new(credential, public_key);

        let psk_store = InMemoryPreSharedKeyStorage::default();

        let client = ClientBuilder::new()
            .crypto_provider(OpensslCryptoProvider::default())
            .identity_provider(BasicIdentityProvider::new())
            .single_signing_identity(signing_identity.clone(), secret_key, cipher_suite)
            .preferences(Preferences::default().with_ratchet_tree_extension(true))
            .psk_store(psk_store.clone())
            .build();

        let key_package = client
            .generate_key_package_message(ProtocolVersion::MLS_10, cipher_suite, signing_identity)
            .await
            .map_err(abort)?;

        clients.push(ClientDetails { client, psk_store });

        let resp = CreateKeyPackageResponse {
            transaction_id: clients.len() as u32,
            key_package: key_package.to_bytes().map_err(abort)?,
        };

        Ok(Response::new(resp))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let clients = self.clients.lock().await;
        let client_index = request_ref.transaction_id as usize - 1;

        let welcome_msg = MLSMessage::tls_deserialize(&mut &*request_ref.welcome).map_err(abort)?;

        let (group, _) = clients[client_index]
            .client
            .join_group(None, welcome_msg)
            .await
            .map_err(abort)?;

        let mut groups = self.groups.lock().await;

        groups.push(GroupDetails {
            group,
            psk_store: clients[client_index].psk_store.clone(),
        });

        Ok(Response::new(JoinGroupResponse {
            state_id: groups.len() as u32,
        }))
    }

    async fn external_join(
        &self,
        _request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        // TODO
        Ok(Response::new(ExternalJoinResponse::default()))
    }

    async fn public_group_state(
        &self,
        _request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        // TODO
        Ok(Response::new(PublicGroupStateResponse::default()))
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
        let request_ref = request.get_ref();
        let mut groups = self.groups.lock().await;

        let ciphertext = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group
            .encrypt_application_message(&request_ref.application_data, vec![])
            .await
            .and_then(|m| Ok(m.tls_serialize_detached()?))
            .map_err(abort)?;

        Ok(Response::new(ProtectResponse { ciphertext }))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut groups = self.groups.lock().await;

        let ciphertext =
            MLSMessage::tls_deserialize(&mut &*request_ref.ciphertext).map_err(abort)?;

        let message = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group
            .process_incoming_message(ciphertext)
            .await
            .map_err(abort)?;

        let application_data = match message.event {
            Event::ApplicationMessage(plaintext) => plaintext,
            _ => {
                return Err(Status::new(
                    Aborted,
                    "message type is not application data.",
                ))
            }
        };

        Ok(Response::new(UnprotectResponse { application_data }))
    }

    async fn store_psk(
        &self,
        request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        let request_ref = request.get_ref();

        let _ = self
            .groups
            .lock()
            .await
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .psk_store
            .insert(
                ExternalPskId::new(request_ref.psk_id.clone()),
                PreSharedKey::from(request_ref.psk.clone()),
            );

        Ok(Response::new(StorePskResponse::default()))
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut groups = self.groups.lock().await;

        let group = &mut groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group;

        let key_package = MLSMessage::from_bytes(&request_ref.key_package).map_err(abort)?;

        let proposal_packet = group
            .propose_add(key_package, vec![])
            .await
            .and_then(|m| Ok(m.tls_serialize_detached()?))
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn update_proposal(
        &self,
        request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut groups = self.groups.lock().await;

        let group = &mut groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group;

        let proposal_packet = group
            .propose_update(vec![])
            .await
            .and_then(|p| Ok(p.tls_serialize_detached()?))
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut groups = self.groups.lock().await;

        let removed = groups
            .get(request_ref.removed as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "removed has no group"))?
            .group
            .current_member_index();

        let group = &mut groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group;

        let proposal_packet = group
            .propose_remove(removed, vec![])
            .await
            .and_then(|p| Ok(p.tls_serialize_detached()?))
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn psk_proposal(
        &self,
        request: tonic::Request<PskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.into_inner();
        let mut groups = self.groups.lock().await;

        let group = &mut groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group;

        let proposal_packet = group
            .propose_psk(ExternalPskId::new(request_ref.psk_id), vec![])
            .await
            .and_then(|p| Ok(p.tls_serialize_detached()?))
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        // TODO
        Ok(Response::new(ProposalResponse::default()))
    }

    async fn group_context_extensions_proposal(
        &self,
        request: tonic::Request<GroupContextExtensionsProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.into_inner();
        let mut groups = self.groups.lock().await;

        let extensions = request_ref
            .extension_type
            .into_iter()
            .zip(request_ref.extension_data.into_iter())
            .map(|(extension_type, extension_data)| {
                Extension::new((extension_type as u16).into(), extension_data)
            })
            .collect::<Vec<_>>();

        let group = &mut groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group;

        let proposal_packet = group
            .propose_group_context_extensions(ExtensionList::from(extensions), vec![])
            .await
            .and_then(|p| Ok(p.tls_serialize_detached()?))
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let group_index = request_ref.state_id as usize - 1;
        let mut groups = self.groups.lock().await;

        for proposal_bytes in &request_ref.by_reference {
            let proposal =
                MLSMessage::tls_deserialize(&mut proposal_bytes.deref()).map_err(abort)?;

            groups
                .get_mut(group_index)
                .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
                .group
                .process_incoming_message(proposal)
                .await
                .map_err(abort)?;
        }

        // TODO: handle by value

        let commit_output = groups
            .get_mut(group_index)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group
            .commit(vec![])
            .await
            .map_err(abort)?;

        let resp = CommitResponse {
            commit: commit_output
                .commit_message
                .tls_serialize_detached()
                .map_err(abort)?,
            welcome: commit_output
                .welcome_message
                .map(|w| w.tls_serialize_detached())
                .transpose()
                .map_err(abort)?
                .unwrap_or_default(),
        };

        Ok(Response::new(resp))
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let group_index = request_ref.state_id as usize - 1;
        let mut groups = self.groups.lock().await;

        for proposal in &request_ref.proposal {
            let proposal = MLSMessage::tls_deserialize(&mut proposal.deref()).map_err(abort)?;

            groups
                .get_mut(group_index)
                .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
                .group
                .process_incoming_message(proposal)
                .await
                .map_err(abort)?;
        }

        let commit = MLSMessage::tls_deserialize(&mut &*request_ref.commit).map_err(abort)?;

        let message = groups
            .get_mut(group_index)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group
            .process_incoming_message(commit)
            .await
            .map_err(abort)?;

        match message.event {
            Event::Commit(state_update) => Ok(Response::new(
                (state_update, request_ref.state_id).try_into()?,
            )),
            _ => Err(Status::new(Aborted, "message not a commit.")),
        }
    }

    async fn handle_pending_commit(
        &self,
        request: tonic::Request<HandlePendingCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let group_index = request_ref.state_id as usize - 1;
        let mut groups = self.groups.lock().await;

        let state_update = groups
            .get_mut(group_index)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .group
            .apply_pending_commit()
            .await
            .map_err(abort)?;

        Ok(Response::new(
            (state_update, request_ref.state_id).try_into()?,
        ))
    }

    async fn handle_external_commit(
        &self,
        _request: tonic::Request<HandleExternalCommitRequest>,
    ) -> Result<tonic::Response<HandleExternalCommitResponse>, tonic::Status> {
        // TODO
        Ok(Response::new(HandleExternalCommitResponse::default()))
    }
}

#[derive(Parser)]
struct Opts {
    #[clap(short, long, value_parser, default_value = "::1")]
    host: IpAddr,

    #[clap(short, long, value_parser, default_value = "50003")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    let mls_client_impl = MlsClientImpl::default();

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve((opts.host, opts.port).into())
        .await?;

    Ok(())
}
