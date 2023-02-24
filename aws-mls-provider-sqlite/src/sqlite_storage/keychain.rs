use crate::SqLiteDataStorageError;
use async_trait::async_trait;
use aws_mls_core::{
    crypto::{CipherSuite, SignatureSecretKey},
    identity::SigningIdentity,
    keychain::KeychainStorage,
};
use openssl::sha::sha512;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct SqLiteKeychainStorage {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StoredSigningIdentity {
    identity: SigningIdentity,
    signer: SignatureSecretKey,
    cipher_suite: CipherSuite,
}

impl SqLiteKeychainStorage {
    pub(crate) fn new(connection: Connection) -> SqLiteKeychainStorage {
        SqLiteKeychainStorage {
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    pub fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) -> Result<(), SqLiteDataStorageError> {
        let (id, _) = identifier_hash(&identity)?;
        self.insert_storage(
            id.as_slice(),
            StoredSigningIdentity {
                identity,
                signer,
                cipher_suite,
            },
        )
    }

    pub fn delete(&mut self, identity: &SigningIdentity) -> Result<(), SqLiteDataStorageError> {
        let (identifier, _) = identifier_hash(identity)?;
        self.delete_storage(&identifier)
    }

    fn insert_storage(
        &mut self,
        identifier: &[u8],
        identity_data: StoredSigningIdentity,
    ) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();
        let StoredSigningIdentity {
            identity,
            signer,
            cipher_suite,
        } = identity_data;

        connection
            .execute(
                "INSERT INTO keychain (
                    identifier,
                    identity,
                    signature_secret_key,
                    cipher_suite
                ) VALUES (?,?,?,?)",
                params![
                    identifier,
                    bincode::serialize(&identity)
                        .map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))?,
                    bincode::serialize(&signer)
                        .map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))?,
                    u16::from(cipher_suite)
                ],
            )
            .map(|_| {})
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    fn delete_storage(&mut self, identifier: &[u8]) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .execute(
                "DELETE FROM keychain WHERE identifier = ?",
                params![identifier],
            )
            .map(|_| {})
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    pub fn get_identities(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<(SigningIdentity, SignatureSecretKey)>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        let mut stmt = connection
            .prepare("SELECT identity, signature_secret_key FROM keychain WHERE cipher_suite = ?")
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        let results = stmt
            .query_map(params![u16::from(cipher_suite)], |row| {
                Ok((
                    bincode::deserialize(&row.get::<_, Vec<u8>>(0)?).unwrap(),
                    bincode::deserialize(&row.get::<_, Vec<u8>>(1)?).unwrap(),
                ))
            })
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        // Can't use try_fold due to borrow constraints on stmt and connection
        let mut identities = Vec::new();

        for identity in results {
            identities
                .push(identity.map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?);
        }

        Ok(identities)
    }

    fn signer(
        &self,
        identifier: &[u8],
    ) -> Result<Option<SignatureSecretKey>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .query_row(
                "SELECT signature_secret_key FROM keychain WHERE identifier = ?",
                params![identifier],
                |row| Ok(bincode::deserialize(&row.get::<_, Vec<u8>>(0)?).unwrap()),
            )
            .optional()
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }
}

#[async_trait]
impl KeychainStorage for SqLiteKeychainStorage {
    type Error = SqLiteDataStorageError;

    async fn signer(
        &self,
        identity: &SigningIdentity,
    ) -> Result<Option<SignatureSecretKey>, Self::Error> {
        let (identifier, _) = identifier_hash(identity)?;
        Ok(self.signer(&identifier)?)
    }
}

fn identifier_hash(
    identity: &SigningIdentity,
) -> Result<(Vec<u8>, Vec<u8>), SqLiteDataStorageError> {
    let serialized_identity = bincode::serialize(&identity)
        .map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))?;
    let identifier = sha512(&serialized_identity);

    Ok((identifier.into(), serialized_identity))
}

#[cfg(test)]
mod tests {
    use aws_mls_core::{
        crypto::CipherSuite,
        identity::{BasicCredential, Credential, SigningIdentity},
    };

    use crate::{
        sqlite_storage::{connection_strategy::MemoryStrategy, test_utils::gen_rand_bytes},
        SqLiteDataStorageEngine,
    };

    use super::{SqLiteKeychainStorage, StoredSigningIdentity};

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

    fn test_signing_identity() -> (Vec<u8>, StoredSigningIdentity) {
        let identifier = gen_rand_bytes(32);

        let identity = StoredSigningIdentity {
            identity: SigningIdentity {
                signature_key: gen_rand_bytes(1024).into(),
                credential: Credential::Basic(BasicCredential::new(gen_rand_bytes(1024))),
            },
            signer: gen_rand_bytes(256).into(),
            cipher_suite: TEST_CIPHER_SUITE,
        };

        (identifier, identity)
    }

    fn test_storage() -> SqLiteKeychainStorage {
        SqLiteDataStorageEngine::new(MemoryStrategy)
            .unwrap()
            .keychain()
            .unwrap()
    }

    #[test]
    fn identity_insert() {
        let mut storage = test_storage();
        let (identifier, stored_identity) = test_signing_identity();

        storage
            .insert_storage(identifier.as_slice(), stored_identity.clone())
            .unwrap();

        let from_storage = storage.get_identities(TEST_CIPHER_SUITE).unwrap();

        assert_eq!(from_storage.len(), 1);
        assert_eq!(from_storage[0].0, stored_identity.identity);

        // Get just the signer
        let signer = storage.signer(&identifier).unwrap().unwrap();
        assert_eq!(stored_identity.signer, signer);
    }

    #[test]
    fn multiple_identities() {
        let mut storage = test_storage();
        let test_identities = (0..10).map(|_| test_signing_identity()).collect::<Vec<_>>();

        test_identities
            .clone()
            .into_iter()
            .for_each(|(identifier, identity)| {
                storage
                    .insert_storage(identifier.as_slice(), identity)
                    .unwrap();
            });

        let from_storage = storage.get_identities(TEST_CIPHER_SUITE).unwrap();

        from_storage.into_iter().for_each(|stored_identity| {
            assert!(test_identities
                .iter()
                .any(|item| { item.1.signer == stored_identity.1 }))
        });
    }

    #[test]
    fn delete_identity() {
        let mut storage = test_storage();
        let (identifier, identity) = test_signing_identity();

        storage
            .insert_storage(identifier.clone().as_slice(), identity)
            .unwrap();

        storage.delete_storage(&identifier).unwrap();

        assert!(storage
            .get_identities(TEST_CIPHER_SUITE)
            .unwrap()
            .is_empty());
    }
}
