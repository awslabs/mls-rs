from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client, \
    client_config_default

client_config = client_config_default()

key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
alice = Client(b'alice', key, client_config)

key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
bob = Client(b'bob', key, client_config)

alice = alice.create_group(None)
message = bob.generate_key_package_message()

commit = alice.add_members([message])
alice.process_incoming_message(commit.commit_message)
bob = bob.join_group(None, commit.welcome_message).group

msg = alice.encrypt_application_message(b'hello, bob')
output = bob.process_incoming_message(msg)
assert output.data == b'hello, bob'

alice.write_to_storage()
bob.write_to_storage()
