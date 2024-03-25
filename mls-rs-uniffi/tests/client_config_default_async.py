import asyncio

from mls_rs_uniffi import Client, CipherSuite, generate_signature_keypair, client_config_default


async def scenario():
    client_config = client_config_default()
    key = await generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    alice = Client(b'alice', key, client_config)

    group = await alice.create_group(None)
    await group.write_to_storage()


asyncio.run(scenario())
