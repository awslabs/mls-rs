import asyncio

from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client, \
    client_config_default


async def scenario():
    client_config = client_config_default()
    client_config.use_ratchet_tree_extension = False

    key = await generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    alice = Client(b'alice', key, client_config)

    group = await alice.create_group(None)
    commit = await group.commit()

    assert commit.ratchet_tree is not None


asyncio.run(scenario())
