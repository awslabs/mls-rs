from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client, \
    client_config_default

client_config = client_config_default()
client_config.use_ratchet_tree_extension = False

key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
alice = Client(b'alice', key, client_config)

group = alice.create_group(None)
commit = group.commit()

assert commit.ratchet_tree is not None
