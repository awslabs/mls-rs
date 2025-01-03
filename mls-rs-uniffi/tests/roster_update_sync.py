from mls_rs_uniffi import Client, CipherSuite, generate_signature_keypair, client_config_default

client_config = client_config_default()
alice = Client(b'alice', generate_signature_keypair(CipherSuite.CURVE25519_AES128), client_config)
bob = Client(b'bob', generate_signature_keypair(CipherSuite.CURVE25519_AES128), client_config)
carla = Client(b'carla', generate_signature_keypair(CipherSuite.CURVE25519_AES128), client_config)

# Alice creates a group and adds Bob.
alice_group = alice.create_group(None)
key_package = bob.generate_key_package_message()
output = alice_group.add_members([key_package.message()])
alice_group.process_incoming_message(output.commit_message)

# Bob join the group and adds Carla.
bob_group = bob.join_group(None, output.welcome_message, key_package.key_package_data()).group
output = bob_group.add_members([carla.generate_key_package_message().message()])
bob_group.process_incoming_message(output.commit_message)

# Alice learns that Carla has been added to the group.
received = alice_group.process_incoming_message(output.commit_message)

assert len(received.effect.applied_proposals) == 1
