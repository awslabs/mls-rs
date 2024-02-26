from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client
from asyncio import run

key = run(generate_signature_keypair(CipherSuite.CURVE25519_AES128))
alice = Client(b'alice', key)

key = run(generate_signature_keypair(CipherSuite.CURVE25519_AES128))
bob = Client(b'bob', key)

alice = run(alice.create_group(None))
kp = run(bob.generate_key_package_message())
commit = run(alice.add_members([kp]))
run(alice.process_incoming_message(commit.commit_message()))
bob = run(bob.join_group(commit.welcome_messages()[0])).group

msg = run(alice.encrypt_application_message(b'hello, bob'))
output = run(bob.process_incoming_message(msg))

assert output.data == b'hello, bob'