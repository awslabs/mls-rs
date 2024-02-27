from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client
import asyncio

async def test():
    key = await generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    alice = Client(b'alice', key)

    key = await generate_signature_keypair(CipherSuite.CURVE25519_AES128)
    bob = Client(b'bob', key)

    alice = await alice.create_group(None)
    kp = await bob.generate_key_package_message()
    commit = await alice.add_members([kp])
    await alice.process_incoming_message(commit.commit_message())
    bob = (await bob.join_group(commit.welcome_messages()[0])).group

    msg = await alice.encrypt_application_message(b'hello, bob')
    output = await bob.process_incoming_message(msg)

    assert output.data == b'hello, bob'

asyncio.run(test())
