from time import time

from ...deprecated.payload import IntroductionResponsePayload
from ...messaging.deprecated.encoding import decode
from ...peer import Peer
from ..trustchain.community import TrustChainCommunity


class IdentityCommunity(TrustChainCommunity):

    DB_NAME = 'identity'
    version = '\x01'
    master_peer = Peer(("3081a7301006072a8648ce3d020106052b810400270381920004009ad2a2e35c328a3e92019873820d70b53b" +
                        "82a752490febbce8bbbe2531a06a165121b8068e674236f26055a59b12c2139445f14dd86c4c3c9598e8c999" +
                        "109f184556dac595f69001b5b16d2c14fe5f641f1a25227152df1989f0c8fb71a107ec55e8e67f464391491c" +
                        "2390bb53fc9b314c7eeb46be1955024ad9e632130e4e92e61295ed1bb1783663fd47fae71293").decode("HEX"))

    def __init__(self, *args, **kwargs):
        super(IdentityCommunity, self).__init__(*args, **kwargs)

        # Dict of hash -> (attribute_name, date, public_key)
        self.known_attestation_hashes = {}

    def add_known_hash(self, hash, name, public_key):
        """
        We know about this hash+peer combination. Thus we can handle sign requests for it.
        """
        self.known_attestation_hashes[hash] = (name, time(), public_key)

    def should_sign(self, block):
        transaction = block.transaction
        requested_keys = set(transaction.keys())
        required_keys = set(["hash", "name", "date"])
        if not required_keys.issubset(requested_keys):
            return False
        hash = transaction['hash']
        if hash not in self.known_attestation_hashes:
            return False
        if block.public_key != self.known_attestation_hashes[hash][2]:
            return False
        # Refuse to sign blocks older than 5 minutes
        if time() > self.known_attestation_hashes[hash][1] + 300:
            return False
        if transaction['name'] != self.known_attestation_hashes[hash][0]:
            return False
        return True

    def request_attestation_advertisement(self, peer, hash, name):
        """
        Request a peer to sign for our attestation advertisement.
        :param peer: the attestor of our block
        :param hash: the hash of the attestation
        :param name: the name of the attribute (metadata)
        """
        self.sign_block(peer,
                        public_key=peer.public_key.key_to_bin(),
                        transaction={
                                "hash": hash,
                                "name": name,
                                "date": time()
                            })

    def on_introduction_response(self, source_address, data):
        super(IdentityCommunity, self).on_introduction_response(source_address, data)

        auth, _, _ = self._ez_unpack_auth(IntroductionResponsePayload, data)
        peer = Peer(auth.public_key_bin, source_address)
        self.send_crawl_request(peer, peer.public_key.key_to_bin())
