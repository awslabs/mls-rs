// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::extension::ExtensionList;

use super::*;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct GroupInfo {
    pub group_context: GroupContext,
    pub extensions: ExtensionList,
    pub confirmation_tag: ConfirmationTag,
    pub signer: LeafIndex,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub signature: Vec<u8>,
}

#[derive(MlsEncode, MlsSize)]
struct SignableGroupInfo<'a> {
    group_context: &'a GroupContext,
    extensions: &'a ExtensionList,
    confirmation_tag: &'a ConfirmationTag,
    signer: LeafIndex,
}

impl<'a> Signable<'a> for GroupInfo {
    const SIGN_LABEL: &'static str = "GroupInfoTBS";
    type SigningContext = ();

    fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signable_content(
        &self,
        _context: &Self::SigningContext,
    ) -> Result<Vec<u8>, mls_rs_codec::Error> {
        SignableGroupInfo {
            group_context: &self.group_context,
            extensions: &self.extensions,
            confirmation_tag: &self.confirmation_tag,
            signer: self.signer,
        }
        .mls_encode_to_vec()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}
