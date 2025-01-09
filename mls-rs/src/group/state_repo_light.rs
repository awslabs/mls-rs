// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::client::MlsError;

use alloc::vec::Vec;
use mls_rs_codec::MlsEncode;
use mls_rs_core::{
    error::IntoAnyError,
    group::{GroupState, GroupStateStorage},
};

use super::snapshot::Snapshot;

#[derive(Debug, Clone)]
pub(crate) struct GroupStateRepository<S: GroupStateStorage> {
    storage: S,
}

impl<S: GroupStateStorage> GroupStateRepository<S> {
    pub fn new(storage: S) -> Result<GroupStateRepository<S>, MlsError> {
        Ok(GroupStateRepository { storage })
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn write_to_storage(&mut self, group_snapshot: Snapshot) -> Result<(), MlsError> {
        let group_state = GroupState {
            data: group_snapshot.mls_encode_to_vec()?,
            id: group_snapshot.state.context.group_id,
        };

        self.storage
            .write(group_state, Vec::new(), Vec::new())
            .await
            .map_err(|e| MlsError::GroupStorageError(e.into_any_error()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::{
            snapshot::{test_utils::get_test_snapshot, Snapshot},
            test_utils::{test_member, TEST_GROUP},
        },
        storage_provider::in_memory::InMemoryGroupStateStorage,
    };

    use alloc::vec;

    use super::GroupStateRepository;

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_snapshot(epoch_id: u64) -> Snapshot {
        get_test_snapshot(TEST_CIPHER_SUITE, epoch_id).await
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_stored_groups_list() {
        let mut test_repo =
            GroupStateRepository::new(InMemoryGroupStateStorage::default()).unwrap();

        test_repo
            .write_to_storage(test_snapshot(0).await)
            .await
            .unwrap();

        assert_eq!(test_repo.storage.stored_groups(), vec![TEST_GROUP])
    }
}
