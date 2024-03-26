import asyncio

from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client, \
    client_config_default


async def scenario():
    client_config = client_config_default()

    key = await generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    alice = Client(b'alice', key, client_config)

    key = await generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    bob = Client(b'bob', key, client_config)

    alice = await alice.create_group(None)
    message = await bob.generate_key_package_message()

    commit = await alice.add_members([message])
    await alice.process_incoming_message(commit.commit_message)
    bob = (await bob.join_group(None, commit.welcome_message)).group

    msg = await alice.encrypt_application_message(b'hello, bob')
    output = await bob.process_incoming_message(msg)

    await alice.write_to_storage()

    assert output.data == b'hello, bob'


asyncio.run(scenario())
