use std::ops::Deref;

use crate::cipher_suite::CipherSuite;
use crate::key_package::KeyPackageRef;
use crate::{hash_reference::HashReference, key_package::KeyPackage};
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use super::GroupError;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct AddProposal {
    pub key_package: KeyPackage,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdateProposal {
    pub key_package: KeyPackage,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct RemoveProposal {
    pub to_remove: KeyPackageRef,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ProposalRef(HashReference);

impl Deref for ProposalRef {
    type Target = HashReference;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Proposal {
    #[tls_codec(discriminant = 1)]
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    //TODO: Psk,
    //TODO: ReInit,
    //TODO: ExternalInit,
}

impl Proposal {
    pub fn to_reference(&self, cipher_suite: CipherSuite) -> Result<ProposalRef, GroupError> {
        Ok(ProposalRef(HashReference::from_value(
            &self.tls_serialize_detached()?,
            cipher_suite,
        )?))
    }

    pub fn is_add(&self) -> bool {
        matches!(self, Self::Add(_))
    }

    pub fn as_add(&self) -> Option<&AddProposal> {
        match self {
            Proposal::Add(add) => Some(add),
            _ => None,
        }
    }

    pub fn is_update(&self) -> bool {
        matches!(self, Self::Update(_))
    }

    pub fn as_update(&self) -> Option<&UpdateProposal> {
        match self {
            Proposal::Update(update) => Some(update),
            _ => None,
        }
    }

    pub fn is_remove(&self) -> bool {
        matches!(self, Self::Remove(_))
    }

    pub fn as_remove(&self) -> Option<&RemoveProposal> {
        match self {
            Proposal::Remove(removal) => Some(removal),
            _ => None,
        }
    }
}

impl From<AddProposal> for Proposal {
    fn from(ap: AddProposal) -> Self {
        Proposal::Add(ap)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum ProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(Proposal),
    Reference(ProposalRef),
}

impl From<Proposal> for ProposalOrRef {
    fn from(proposal: Proposal) -> Self {
        Self::Proposal(proposal)
    }
}

impl From<ProposalRef> for ProposalOrRef {
    fn from(r: ProposalRef) -> Self {
        Self::Reference(r)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct PendingProposal {
    pub proposal: Proposal,
    pub sender: KeyPackageRef,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{hash_reference::HashReference, tree_kem::test::get_test_key_package};
    use ferriscrypt::{
        asym::ec_key::{generate_keypair, Curve},
        rand::SecureRng,
    };
    use tls_codec::Deserialize;

    use crate::{
        cipher_suite::CipherSuite,
        credential::{BasicCredential, CredentialConvertible},
        extension::ExtensionList,
        key_package::{KeyPackage, KeyPackageGenerator},
    };

    fn test_key_package(cipher_suite: CipherSuite) -> KeyPackage {
        let (public, secret) =
            generate_keypair(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let key_package_generator = KeyPackageGenerator {
            cipher_suite,
            credential: &BasicCredential::new(b"foo".to_vec(), public)
                .unwrap()
                .into_credential(),
            extensions: ExtensionList::new(),
            signing_key: &secret,
        };

        key_package_generator.generate().unwrap().key_package
    }

    #[test]
    fn test_add() {
        let add_proposal = AddProposal {
            key_package: test_key_package(CipherSuite::P256Aes128V1),
        };

        let proposal = Proposal::Add(add_proposal.clone());

        assert!(proposal.is_add());
        assert!(!proposal.is_update());
        assert!(!proposal.is_remove());
        assert_eq!(proposal.as_add(), Some(&add_proposal));
        assert_eq!(proposal.as_update(), None);
        assert_eq!(proposal.as_remove(), None);
    }

    #[test]
    fn test_update() {
        let update_proposal = UpdateProposal {
            key_package: test_key_package(CipherSuite::P256Aes128V1),
        };

        let proposal = Proposal::Update(update_proposal.clone());

        assert!(proposal.is_update());
        assert!(!proposal.is_add());
        assert!(!proposal.is_remove());
        assert_eq!(proposal.as_update(), Some(&update_proposal));
        assert_eq!(proposal.as_add(), None);
        assert_eq!(proposal.as_remove(), None);
    }

    #[test]
    fn test_remove() {
        let remove_proposal = RemoveProposal {
            to_remove: KeyPackageRef::from([0u8; 16]),
        };

        let proposal = Proposal::Remove(remove_proposal.clone());

        assert!(proposal.is_remove());
        assert!(!proposal.is_add());
        assert!(!proposal.is_update());
        assert_eq!(proposal.as_remove(), Some(&remove_proposal));
        assert_eq!(proposal.as_add(), None);
        assert_eq!(proposal.as_update(), None);
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    #[allow(dead_code)]
    fn generate_proposal_test_cases() -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for cipher_suite in CipherSuite::all() {
            let add = Proposal::from(AddProposal {
                key_package: get_test_key_package(cipher_suite, SecureRng::gen(16).unwrap())
                    .key_package,
            });

            let update = Proposal::Update(UpdateProposal {
                key_package: get_test_key_package(cipher_suite, SecureRng::gen(16).unwrap())
                    .key_package,
            });

            let mut key_package_ref = [0u8; 16];
            SecureRng::fill(&mut key_package_ref).unwrap();

            let remove = Proposal::Remove(RemoveProposal {
                to_remove: key_package_ref.into(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: add.tls_serialize_detached().unwrap(),
                output: add.to_reference(cipher_suite).unwrap().to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: update.tls_serialize_detached().unwrap(),
                output: update.to_reference(cipher_suite).unwrap().to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: remove.tls_serialize_detached().unwrap(),
                output: remove.to_reference(cipher_suite).unwrap().to_vec(),
            });
        }

        /*
        std::fs::write(
            "path/to/test_data/proposal_ref.json",
            serde_json::to_vec_pretty(&test_cases).unwrap(),
        )
        .unwrap();
        */

        test_cases
    }

    #[test]
    fn test_proposal_ref() {
        let test_cases: Vec<TestCase> =
            serde_json::from_slice(include_bytes!("../../test_data/proposal_ref.json")).unwrap();

        for one_case in test_cases {
            let proposal = Proposal::tls_deserialize(&mut one_case.input.as_slice()).unwrap();
            let proposal_ref = proposal
                .to_reference(CipherSuite::from_raw(one_case.cipher_suite).unwrap())
                .unwrap();

            let expected_out = ProposalRef(HashReference::from(
                <[u8; 16]>::try_from(one_case.output).unwrap(),
            ));

            assert_eq!(expected_out, proposal_ref);
        }
    }
}
