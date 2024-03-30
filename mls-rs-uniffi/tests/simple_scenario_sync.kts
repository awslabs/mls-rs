import uniffi.mls_rs_uniffi.*
import kotlin.test.*

val clientConfig = clientConfigDefault()

val aliceKey = generateSignatureKeypair(CipherSuite.CURVE25519_AES128)
val alice = Client("alice".toByteArray(), aliceKey, clientConfig)

val bobKey = generateSignatureKeypair(CipherSuite.CURVE25519_AES128)
val bob = Client("bob".toByteArray(), bobKey, clientConfig)

val aliceGroup = alice.createGroup(null)
val message = bob.generateKeyPackageMessage()

val commit = aliceGroup.addMembers(listOf(message))
aliceGroup.processIncomingMessage(commit.commitMessage)
val bobGroup = bob.joinGroup(null, commit.welcomeMessage!!).group

val encrypted = aliceGroup.encryptApplicationMessage("hello, bob".toByteArray())
val receivedMessage = bobGroup.processIncomingMessage(encrypted!!)
val decrypted = assertIs<ReceivedMessage.ApplicationMessage>(receivedMessage)
assertEquals(decrypted.data.decodeToString(), "hello, bob")

aliceGroup.writeToStorage()
bobGroup.writeToStorage()
