// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{MlsDecode, MlsEncode, MlsSize};
use alloc::vec::Vec;

impl MlsSize for bool {
    fn mls_encoded_len(&self) -> usize {
        1
    }
}

impl MlsEncode for bool {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), crate::Error> {
        writer.push(*self as u8);
        Ok(())
    }
}

impl MlsDecode for bool {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, crate::Error> {
        match u8::mls_decode(reader)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(crate::Error::Custom(6)),
        }
    }
}
