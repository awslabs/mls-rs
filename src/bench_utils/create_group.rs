use crate::cipher_suite::CipherSuite;

use crate::ProtocolVersion;

use crate::group::GroupState;

use crate::extension::ExtensionList;

use crate::client::test_utils::{get_basic_config, join_session, test_client_with_key_pkg};

// creates group modifying code found in client.rs
pub fn create_group(cipher_suite: CipherSuite, size: usize) -> GroupState {
    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_GROUP: &[u8] = b"group";

    let alice = get_basic_config(cipher_suite, "alice").build_client();
    let mut alice_session = alice
        .create_session_with_group_id(
            TEST_PROTOCOL_VERSION,
            cipher_suite,
            TEST_GROUP.to_vec(),
            ExtensionList::new(),
        )
        .unwrap();

    for n in 0..size {
        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, cipher_suite, &format!("bob{n}"));

        join_session(&mut alice_session, [], bob_key_pkg, &bob).unwrap();
    }

    // exporting the session as a group state
    alice_session.export()
}
