#[cfg(feature = "psk")]
pub(crate) mod inner {
    use mls_rs::{
        group::StateUpdate, identity::SigningIdentity, mls_rs_codec::MlsEncode,
        CipherSuiteProvider, CryptoProvider, MlsMessage,
    };
    use mls_rs_crypto_openssl::OpensslCryptoProvider;
    use tonic::{Request, Response, Status};

    use crate::{
        abort, get_tree,
        mls_client::{
            CreateSubgroupResponse, HandleBranchRequest, HandleBranchResponse,
            HandleCommitResponse, HandlePendingCommitRequest, HandleReInitCommitResponse,
            HandleReInitWelcomeRequest, JoinGroupResponse,
        },
        MlsClientImpl,
    };

    impl MlsClientImpl {
        pub(crate) async fn handle_pending_re_init_commit(
            &self,
            request: Request<HandlePendingCommitRequest>,
        ) -> Result<Response<HandleReInitCommitResponse>, Status> {
            let request = request.into_inner();

            let (resp, update) = {
                let clients = &mut self.clients.lock().await;

                let group = clients
                    .get_mut(&request.state_id)
                    .ok_or_else(|| Status::aborted("no group with such index."))?
                    .group
                    .as_mut()
                    .ok_or_else(|| Status::aborted("no group with such index."))?;

                let update = group.apply_pending_commit().map_err(abort)?;

                let resp = HandleCommitResponse {
                    state_id: request.state_id,
                    epoch_authenticator: group.epoch_authenticator().map_err(abort)?.to_vec(),
                };

                (resp, update)
            };

            self.handle_re_init_commit(Response::new(resp), update.state_update)
                .await
        }

        pub(crate) async fn handle_re_init_welcome(
            &self,
            request: Request<HandleReInitWelcomeRequest>,
        ) -> Result<Response<JoinGroupResponse>, Status> {
            let request = request.into_inner();
            let clients = &mut self.clients.lock().await;

            let client = clients
                .get_mut(&request.reinit_id)
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let group = client
                .group
                .as_mut()
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let welcome = MlsMessage::from_bytes(&request.welcome).map_err(abort)?;

            let reinit_client = group
                .clone()
                .get_reinit_client(
                    Some(client.signer.clone()),
                    Some(client.signing_identity.clone()),
                )
                .map_err(abort)?;

            let (group, _info) = reinit_client
                .join(&welcome, get_tree(&request.ratchet_tree)?)
                .map_err(abort)?;

            let resp = JoinGroupResponse {
                epoch_authenticator: group.epoch_authenticator().map_err(abort)?.to_vec(),
                state_id: request.reinit_id,
            };

            client.group = Some(group);

            Ok(Response::new(resp))
        }

        pub(crate) async fn handle_branch(
            &self,
            request: Request<HandleBranchRequest>,
        ) -> Result<Response<HandleBranchResponse>, Status> {
            let request = request.into_inner();
            let clients = &mut self.clients.lock().await;

            // Find the key package generated earlier based on the transaction_id
            let (id, key_package_data) = {
                let key_package_client = clients
                    .get(&request.transaction_id)
                    .ok_or_else(|| Status::aborted("no group with such index."))?;

                key_package_client.key_package_repo.key_packages()[0].clone()
            };

            let client = clients
                .get_mut(&request.state_id)
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            // Insert the previously created key package
            client.key_package_repo.insert(id, key_package_data);

            let group = client
                .group
                .as_mut()
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let tree = get_tree(&request.ratchet_tree)?;

            let welcome = MlsMessage::from_bytes(&request.welcome).map_err(abort)?;

            let (new_group, _info) = group.join_subgroup(&welcome, tree).map_err(abort)?;

            let resp = HandleBranchResponse {
                state_id: request.state_id,
                epoch_authenticator: new_group.epoch_authenticator().map_err(abort)?.to_vec(),
            };

            client.group = Some(new_group);

            Ok(Response::new(resp))
        }

        pub(crate) async fn branch_or_reinit(
            &self,
            client_id: u32,
            key_packages: &[Vec<u8>],
            force_path: bool,
            external_tree: bool,
            subgroup_id: Option<Vec<u8>>,
        ) -> Result<Response<CreateSubgroupResponse>, Status> {
            let clients = &mut self.clients.lock().await;

            let client = clients
                .get_mut(&client_id)
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let group = client
                .group
                .as_mut()
                .ok_or_else(|| Status::aborted("no group with such index."))?;

            let new_key_pkgs = key_packages
                .iter()
                .map(|kp| MlsMessage::from_bytes(kp))
                .collect::<Result<_, _>>()
                .map_err(abort)?;

            {
                let mut mls_rules = client.mls_rules.commit_options.lock().unwrap();
                mls_rules.path_required = force_path;
                mls_rules.ratchet_tree_extension = !external_tree;
            };

            let (new_group, welcome) = if let Some(id) = subgroup_id {
                group.branch(id, new_key_pkgs).map_err(abort)?
            } else {
                let client = group
                    .clone()
                    .get_reinit_client(
                        Some(client.signer.clone()),
                        Some(client.signing_identity.clone()),
                    )
                    .map_err(abort)?;

                client.commit(new_key_pkgs).map_err(abort)?
            };

            let welcome = welcome
                .first()
                .map(|msg| msg.to_bytes())
                .transpose()
                .map_err(abort)?
                .unwrap_or_default();

            let ratchet_tree = if external_tree {
                new_group.export_tree().mls_encode_to_vec().unwrap()
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

        pub(crate) async fn handle_re_init_commit(
            &self,
            commit_resp: Response<HandleCommitResponse>,
            update: StateUpdate,
        ) -> Result<Response<HandleReInitCommitResponse>, Status> {
            let commit_resp = commit_resp.into_inner();
            let mut clients = self.clients.lock().await;

            let client = clients
                .get_mut(&commit_resp.state_id)
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

            // Generate a key packge used to join the new group after reinit
            let reinit_client = group
                .clone()
                .get_reinit_client(Some(secret_key.clone()), Some(signing_identity.clone()))
                .map_err(abort)?;

            let key_package = reinit_client.generate_key_package().map_err(abort)?;

            let resp = HandleReInitCommitResponse {
                epoch_authenticator: commit_resp.epoch_authenticator,
                key_package: key_package.to_bytes().map_err(abort)?,
                reinit_id: commit_resp.state_id,
            };

            client.signing_identity = signing_identity;
            client.signer = secret_key;

            Ok(Response::new(resp))
        }
    }
}

#[cfg(not(feature = "psk"))]
pub(crate) mod inner {
    use mls_rs::group::StateUpdate;
    use tonic::{Request, Response, Status};

    use crate::{
        mls_client::{
            CreateSubgroupResponse, HandleBranchRequest, HandleBranchResponse,
            HandleCommitResponse, HandlePendingCommitRequest, HandleReInitCommitResponse,
            HandleReInitWelcomeRequest, JoinGroupResponse,
        },
        MlsClientImpl,
    };

    impl MlsClientImpl {
        pub(crate) async fn handle_pending_re_init_commit(
            &self,
            _: Request<HandlePendingCommitRequest>,
        ) -> Result<Response<HandleReInitCommitResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }

        pub(crate) async fn handle_re_init_welcome(
            &self,
            _: Request<HandleReInitWelcomeRequest>,
        ) -> Result<Response<JoinGroupResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }

        pub(crate) async fn handle_branch(
            &self,
            _: Request<HandleBranchRequest>,
        ) -> Result<Response<HandleBranchResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }

        pub(crate) async fn handle_re_init_commit(
            &self,
            _: Response<HandleCommitResponse>,
            _: StateUpdate,
        ) -> Result<Response<HandleReInitCommitResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }

        pub(crate) async fn branch_or_reinit(
            &self,
            _: u32,
            _: &[Vec<u8>],
            _: bool,
            _: bool,
            _: Option<Vec<u8>>,
        ) -> Result<Response<CreateSubgroupResponse>, Status> {
            Err(Status::aborted("Unsupported"))
        }
    }
}
