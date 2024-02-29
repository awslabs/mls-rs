from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client, ClientConfig


alice_config = ClientConfig.new_sqlite("alice.db", bytes([0] * 32))
key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
alice = Client(b'alice', key, alice_config)

bob_config = ClientConfig.new_sqlite("bob.db", bytes([0] * 32))
key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
bob = Client(b'bob', key, bob_config)

alice = alice.create_group(None)
kp = bob.generate_key_package_message()
commit = alice.add_members([kp])
alice.process_incoming_message(commit.commit_message())
bob = bob.join_group(commit.welcome_messages()[0]).group

msg = alice.encrypt_application_message(b'hello, bob')
output = bob.process_incoming_message(msg)

alice.write_to_storage()

assert output.data == b'hello, bob'