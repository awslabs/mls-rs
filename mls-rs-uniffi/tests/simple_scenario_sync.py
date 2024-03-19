from dataclasses import dataclass, field

from mls_rs_uniffi import CipherSuite, generate_signature_keypair, Client, \
    GroupStateStorage, GroupState, EpochRecord, ClientConfig, ProtocolVersion

@dataclass
class GroupStateData:
    state: bytes
    epoch_data: list[EpochRecord] = field(default_factory=list)

class PythonGroupStateStorage(GroupStateStorage):
    def __init__(self):
        self.groups: dict[str, GroupStateData] = {}

    def state(self, group_id: bytes):
        group = self.groups.get(group_id.hex())

        if group == None:
            return None 

        return group.state

    def epoch(self, group_id: bytes, epoch_id: int):
        group = self.groups[group_id.hex()]

        if group == None:
            return None

        for epoch in group.epoch_data:
            if epoch.id == epoch_id:
                return epoch

        return None

    def write(self, state: GroupState, epoch_inserts: list[EpochRecord], epoch_updates: list[EpochRecord]):
        if self.groups.get(state.id.hex()) == None:
            self.groups[state.id.hex()] = GroupStateData(state.data)

        group = self.groups[state.id.hex()]

        for insert in epoch_inserts:
            group.epoch_data.append(insert)

        for update in epoch_updates:
            for i in range(len(group.epoch_data)):
                if group.epoch_data[i].id == update.id:
                    group.epoch_data[i] = update

    def max_epoch_id(self, group_id: bytes):
        group = self.groups.get(group_id.hex())

        if group == None:
            return None 

        last = group.epoch_data.last()

        if last == None:
            return None

        return last.id

group_state_storage = PythonGroupStateStorage()
client_config = ClientConfig(group_state_storage)

key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
alice = Client(b'alice', key, client_config)

key = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
bob = Client(b'bob', key, client_config)

alice = alice.create_group(None)
message = bob.generate_key_package_message()

commit = alice.add_members([message])
alice.process_incoming_message(commit.commit_message)
bob = bob.join_group(commit.welcome_messages[0]).group

msg = alice.encrypt_application_message(b'hello, bob')
output = bob.process_incoming_message(msg)

alice.write_to_storage()

assert output.data == b'hello, bob'
assert len(group_state_storage.groups) == 1
