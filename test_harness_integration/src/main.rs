//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client written by Richard Barnes.

use aws_mls::cipher_suite::{CipherSuite, MaybeCipherSuite, SignaturePublicKey};
use aws_mls::client::Client;
use aws_mls::client_config::{
    ClientConfig, InMemoryClientConfig, Preferences, ONE_YEAR_IN_SECONDS,
};
use aws_mls::credential::Credential;
use aws_mls::extension::{Extension, ExtensionList};
use aws_mls::group::framing::MLSMessage;
use aws_mls::group::{Event, Group, StateUpdate};

use aws_mls::key_package::KeyPackage;
use aws_mls::psk::{ExternalPskId, Psk};
use aws_mls::signing_identity::SigningIdentity;
use aws_mls::tls_codec::{Deserialize, Serialize};
use aws_mls::ProtocolVersion;

use clap::Parser;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Mutex;
use tonic::{transport::Server, Code::Aborted, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
// TODO(RLB) Convert this back to more specific `use` directives
use mls_client::*;

fn abort<T: std::fmt::Debug>(e: T) -> Status {
    Status::new(Aborted, format!("Aborted with error {e:?}"))
}

pub mod mls_client {
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
            .added
            .iter()
            .map(|leaf_index| **leaf_index)
            .collect();

        let updated = state_update
            .updated
            .iter()
            .map(|leaf_index| **leaf_index)
            .collect();

        let removed_indices = state_update
            .removed
            .iter()
            .map(|(leaf_index, _)| **leaf_index)
            .collect();

        let removed_leaves = state_update
            .removed
            .iter()
            .map(|(_, leaf)| leaf.tls_serialize_detached())
            .collect::<Result<Vec<_>, _>>()
            .map_err(abort)?;

        let psks = state_update
            .psks
            .iter()
            .map(|psk_id| psk_id.tls_serialize_detached())
            .collect::<Result<Vec<_>, _>>()
            .map_err(abort)?;

        Ok(Self {
            state_id,
            added,
            updated,
            removed_indices,
            removed_leaves,
            psks,
            active: state_update.active as u32,
        })
    }
}

#[derive(Default)]
pub struct MlsClientImpl {
    clients: Mutex<Vec<Client<InMemoryClientConfig>>>,
    groups: Mutex<Vec<Group<InMemoryClientConfig>>>,
    configs: Mutex<Vec<InMemoryClientConfig>>,
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
            ciphersuites: CipherSuite::all().map(|cs| cs as u32).collect(),
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
        println!("{} test vector request", type_msg);

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
        println!("{} test vector request", type_msg);

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

        let cipher_suite = MaybeCipherSuite::from_raw_value(request_ref.cipher_suite as u16)
            .into_enum()
            .ok_or_else(|| Status::new(Aborted, "ciphersuite not supported"))?;

        let secret_key = cipher_suite.generate_signing_key().map_err(abort)?;
        let credential = Credential::Basic(b"creator".to_vec());
        let signature_key = SignaturePublicKey::try_from(&secret_key).map_err(abort)?;

        let creator = InMemoryClientConfig::default()
            .with_signing_identity(SigningIdentity::new(credential, signature_key), secret_key)
            .with_preferences(Preferences::default().with_ratchet_tree_extension(true))
            .with_lifetime_duration(ONE_YEAR_IN_SECONDS)
            .build_client();

        let group = creator
            .create_group_with_id(
                ProtocolVersion::Mls10,
                cipher_suite,
                request_ref.group_id,
                ExtensionList::default(),
            )
            .map_err(abort)?;

        let mut groups = self.groups.lock().unwrap();
        groups.push(group);

        self.configs.lock().unwrap().push(creator.config);

        Ok(Response::new(CreateGroupResponse {
            state_id: groups.len() as u32,
        }))
    }

    async fn create_key_package(
        &self,
        request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut clients = self.clients.lock().unwrap();

        let cipher_suite = MaybeCipherSuite::from_raw_value(request_ref.cipher_suite as u16)
            .into_enum()
            .ok_or_else(|| Status::new(Aborted, "ciphersuite not supported"))?;

        let secret_key = cipher_suite.generate_signing_key().map_err(abort)?;
        let credential = Credential::Basic(format!("alice{}", clients.len()).into_bytes());
        let signature_key = SignaturePublicKey::try_from(&secret_key).map_err(abort)?;

        let client = InMemoryClientConfig::default()
            .with_signing_identity(SigningIdentity::new(credential, signature_key), secret_key)
            .with_preferences(Preferences::default().with_ratchet_tree_extension(true))
            .with_lifetime_duration(ONE_YEAR_IN_SECONDS)
            .build_client();

        let key_package = client
            .generate_key_package(ProtocolVersion::Mls10, cipher_suite)
            .map_err(abort)?;

        clients.push(client);

        let resp = CreateKeyPackageResponse {
            transaction_id: clients.len() as u32,
            key_package: key_package.to_vec().map_err(abort)?,
        };

        Ok(Response::new(resp))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let clients = self.clients.lock().unwrap();
        let client_index = request_ref.transaction_id as usize - 1;

        let welcome_msg = MLSMessage::tls_deserialize(&mut &*request_ref.welcome).map_err(abort)?;

        let group = clients[client_index]
            .join_group(None, welcome_msg)
            .map_err(abort)?;

        let mut groups = self.groups.lock().unwrap();
        groups.push(group);

        self.configs
            .lock()
            .unwrap()
            .push(clients[client_index].config.clone());

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
        let mut groups = self.groups.lock().unwrap();

        let ciphertext = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .encrypt_application_message(&request_ref.application_data, vec![])
            .and_then(|m| Ok(m.tls_serialize_detached()?))
            .map_err(abort)?;

        Ok(Response::new(ProtectResponse { ciphertext }))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut groups = self.groups.lock().unwrap();

        let ciphertext =
            MLSMessage::tls_deserialize(&mut &*request_ref.ciphertext).map_err(abort)?;

        let message = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .process_incoming_message(ciphertext)
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
            .configs
            .lock()
            .unwrap()
            .get(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .secret_store()
            .insert(
                ExternalPskId(request_ref.psk_id.clone()),
                Psk::from(request_ref.psk.clone()),
            );

        Ok(Response::new(StorePskResponse::default()))
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut groups = self.groups.lock().unwrap();

        let group = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?;

        let key_package =
            KeyPackage::tls_deserialize(&mut &*request_ref.key_package).map_err(abort)?;

        let add_proposal = group.add_proposal(key_package).map_err(abort)?;

        let proposal_packet = group
            .proposal_message(add_proposal, vec![])
            .and_then(|p| Ok(p.tls_serialize_detached()?))
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
        let mut groups = self.groups.lock().unwrap();

        let group = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?;

        let update_proposal = group.update_proposal().map_err(abort)?;

        let proposal_packet = group
            .proposal_message(update_proposal, vec![])
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
        let mut groups = self.groups.lock().unwrap();

        let removed = groups
            .get(request_ref.removed as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "removed has no group"))?
            .current_member_index();

        let group = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?;

        let remove_proposal = group.remove_proposal(removed).map_err(abort)?;

        let proposal_packet = group
            .proposal_message(remove_proposal, vec![])
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
        let mut groups = self.groups.lock().unwrap();

        let group = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?;

        let psk_proposal = group
            .psk_proposal(ExternalPskId(request_ref.psk_id))
            .map_err(abort)?;

        let proposal_packet = group
            .proposal_message(psk_proposal, vec![])
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
        let mut groups = self.groups.lock().unwrap();

        let extensions = request_ref
            .extension_type
            .into_iter()
            .zip(request_ref.extension_data.into_iter())
            .map(|(extension_type, extension_data)| Extension {
                extension_type: extension_type as u16,
                extension_data,
            })
            .collect::<Vec<_>>();

        let group = groups
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?;

        let group_context_proposal =
            group.group_context_extensions_proposal(ExtensionList::from(extensions));

        let proposal_packet = group
            .proposal_message(group_context_proposal, vec![])
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
        let mut groups = self.groups.lock().unwrap();

        for proposal_bytes in &request_ref.by_reference {
            let proposal =
                MLSMessage::tls_deserialize(&mut proposal_bytes.deref()).map_err(abort)?;

            groups
                .get_mut(group_index)
                .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
                .process_incoming_message(proposal)
                .map_err(abort)?;
        }

        // TODO: handle by value

        let (commit, welcome) = groups
            .get_mut(group_index)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .commit_proposals(vec![], vec![])
            .map_err(abort)?;

        let resp = CommitResponse {
            commit: commit.tls_serialize_detached().map_err(abort)?,
            welcome: welcome
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
        let mut groups = self.groups.lock().unwrap();

        for proposal in &request_ref.proposal {
            let proposal = MLSMessage::tls_deserialize(&mut proposal.deref()).map_err(abort)?;

            groups
                .get_mut(group_index)
                .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
                .process_incoming_message(proposal)
                .map_err(abort)?;
        }

        let commit = MLSMessage::tls_deserialize(&mut &*request_ref.commit).map_err(abort)?;

        let message = groups
            .get_mut(group_index)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .process_incoming_message(commit)
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
        let mut groups = self.groups.lock().unwrap();

        let state_update = groups
            .get_mut(group_index)
            .ok_or_else(|| Status::new(Aborted, "no group with such index."))?
            .process_pending_commit()
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
