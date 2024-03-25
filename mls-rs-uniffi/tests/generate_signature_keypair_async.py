from mls_rs_uniffi import CipherSuite, generate_signature_keypair
import asyncio


async def scenario():
    signature_keypair = await generate_signature_keypair(
        CipherSuite.CURVE25519_AES128)
    assert signature_keypair.cipher_suite == CipherSuite.CURVE25519_AES128


asyncio.run(scenario())
