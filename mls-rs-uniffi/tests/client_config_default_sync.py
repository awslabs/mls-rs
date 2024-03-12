from mls_rs_uniffi import Client, CipherSuite, generate_signature_keypair, client_config_default

client_config = client_config_default()
key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
alice = Client(b'alice', key, client_config)

group = alice.create_group(None)
group.write_to_storage()
