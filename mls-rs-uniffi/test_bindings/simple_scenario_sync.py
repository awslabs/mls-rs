from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client

key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
alice = Client(b'alice', key)

key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
bob = Client(b'bob', key)

alice = alice.create_group(None)
kp = bob.generate_key_package_message()
commit = alice.add_members([kp])
alice.process_incoming_message(commit.commit_message())
bob = bob.join_group(commit.welcome_messages()[0]).group

msg = alice.encrypt_application_message(b'hello, bob')
output = bob.process_incoming_message(msg)

assert output.data == b'hello, bob'