// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use der::{
    asn1::{BitString, ContextSpecific, OctetString, Uint},
    oid::ObjectIdentifier,
    Any, Decode, Encode, Sequence,
};
use js_sys::Array;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKeyPair, EcKeyGenParams};

use crate::{get_crypto, key_type::KeyType, CryptoError};

/// Generate private / public key pair.
pub(crate) async fn generate(curve: &'static str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let crypto = get_crypto()?;
    let private_key_type = KeyType::EcdhSecret(curve);
    let public_key_type = KeyType::EcdhPublic(curve);

    let params = EcKeyGenParams::new(private_key_type.algorithm(), curve);

    let key_usages = Array::new_with_length(1);
    key_usages.set(0, private_key_type.usage().into());

    let key_pair = crypto.generate_key_with_object(&params, true, &key_usages)?;
    let key_pair: CryptoKeyPair = JsFuture::from(key_pair).await?.into();

    let private_key = private_key_type.export(&crypto, &key_pair).await?;
    let public_key = public_key_type.export(&crypto, &key_pair).await?;

    Ok((private_key, public_key))
}

#[derive(Debug, Sequence)]
pub(crate) struct DerPrivateKey {
    version: Uint,
    pub private_key: OctetString,
    pub public_key: Option<ContextSpecific<BitString>>,
}

/// `private_key` is a DER-serialized `DerPrivateKey` struct.
#[derive(Debug, Sequence)]
struct DerPrivateKeySerializedFormat {
    version: Uint,
    algorithm_identifier: AlgorithmIdentifier,
    private_key: OctetString,
}

#[derive(Debug, Sequence, Clone)]
struct AlgorithmIdentifier {
    object_identifier: ObjectIdentifier,
    parameters: Any,
}

impl DerPrivateKey {
    /// Generates a key without the public key.
    pub(crate) fn from_raw(private_key: &[u8]) -> Result<Self, der::Error> {
        Ok(Self {
            version: Uint::new(&[1])?,
            private_key: OctetString::new(private_key)?,
            public_key: None,
        })
    }

    pub(crate) fn to_bytes(&self, named_curve: Any) -> Result<Vec<u8>, der::Error> {
        let algorithm_identifier = AlgorithmIdentifier {
            object_identifier: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: named_curve,
        };

        DerPrivateKeySerializedFormat {
            version: Uint::new(&[0])?,
            algorithm_identifier,
            private_key: OctetString::new(self.to_der()?)?,
        }
        .to_der()
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        let private_key = DerPrivateKeySerializedFormat::from_der(bytes)?;

        Self::from_der(private_key.private_key.as_bytes())
    }

    pub(crate) fn is_der(bytes: &[u8]) -> bool {
        DerPrivateKeySerializedFormat::from_der(bytes).is_ok()
    }
}
