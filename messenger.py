#!/usr/bin/env python3
import pickle
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag



def gov_decrypt(gov_priv, message):
    header, ciphertext = message
    shared_key_elgamal = gov_priv.exchange(ec.ECDH(), header.gov_pub)
    derived_key_elgamal = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'elgamal_key',
    ).derive(shared_key_elgamal)
    aesgcm = AESGCM(derived_key_elgamal)
    nonce_decrypt = header.gov_iv
    message_key = aesgcm.decrypt(nonce_decrypt, header.gov_ct, None)
    aesgcm_message = AESGCM(message_key)
    aad = header.rat_pub + header.iv + header.gov_iv + header.n.to_bytes(2, "big") + header.pn.to_bytes(2, "big")
    cleartext = aesgcm_message.decrypt(header.iv, ciphertext, aad)
    return cleartext.decode()

@dataclass
class Connection:
    dhs        : ec.EllipticCurvePrivateKey
    dhr        : ec.EllipticCurvePublicKey
    rk         : bytes = None
    cks        : bytes = None
    ckr        : bytes = None
    pn         : int = 0
    ns         : int = 0
    nr         : int = 0
    mk_skipped : dict = field(default_factory=dict)

@dataclass
class Header:
    rat_pub : bytes
    iv      : bytes
    gov_pub : bytes
    gov_iv  : bytes
    gov_ct  : bytes
    n       : int = 0
    pn      : int = 0

class Messenger:

    MAX_MSG_SKIP = 10

    def __init__(self, username, ca_pub_key, gov_pub):
        self.username = username
        self.ca_pub_key = ca_pub_key
        self.gov_pub = gov_pub
        self.conns = {}

    def generate_certificate(self):
        certificate = {}

        user_s_key = ec.generate_private_key(ec.SECP384R1())
        user_p_key = user_s_key.public_key()
        pem = user_p_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        certificate["client_username"] = self.username
        certificate["public_key"] = pem

        self.s_key = user_s_key

        return certificate

    def receive_certificate(self, cert_data, cert_sig):
        cert_data_pickle = pickle.dumps(cert_data)

        try:
            self.ca_pub_key.verify(cert_sig, cert_data_pickle, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ValueError("Invalid signature.")

        conect_public= cert_data["public_key"]
        conect_pub_k = serialization.load_pem_public_key(conect_public)

        self.conns[cert_data["client_username"]] = Connection(dhs=self.s_key,dhr=conect_pub_k)




    def send_message(self, username, message):
        connect_data =  self.conns[username]

        if connect_data.nr != 0:
            connect_data.dhs = ec.generate_private_key(ec.SECP384R1())
            connect_data.pn = connect_data.ns
            connect_data.ns = 0
            connect_data.nr = 0

        if not connect_data.rk or connect_data.ns == 0:
            peer_public_key = connect_data.dhr
            shared_key = connect_data.dhs.exchange(ec.ECDH(), peer_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=96,
                salt=connect_data.rk,
                info=b'root_key',
            ).derive(shared_key)
            connect_data.rk = derived_key[0:32]
            connect_data.cks = derived_key[32:64]

        cks_new = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'info',
        ).derive(connect_data.cks)
        connect_data.cks = cks_new[0:32]
        message_key = cks_new[32:64]
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)

        ephemeral_s = ec.generate_private_key(ec.SECP384R1())
        ephemeral_p = ephemeral_s.public_key()
        shared_key_elgamal = ephemeral_s.exchange(ec.ECDH(), self.gov_pub)
        derived_key_elgamal = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'elgamal_key',
        ).derive(shared_key_elgamal)
        aesgcm1 = AESGCM(derived_key_elgamal)
        nonce2 = os.urandom(12)
        gov_ct_elgamal = aesgcm1.encrypt(nonce2, message_key, None)

        user_p_key = connect_data.dhs.public_key()
        pem_user_pk = user_p_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        connect_data.ns += 1
        header = Header(rat_pub=pem_user_pk, iv = nonce, n = connect_data.ns, pn = connect_data.pn, gov_pub=ephemeral_p, gov_iv=nonce2, gov_ct=gov_ct_elgamal)

        aad = pem_user_pk + header.iv + header.gov_iv + header.n.to_bytes(2, "big") + header.pn.to_bytes(2, "big")

        ciphertext = aesgcm.encrypt(nonce, bytes(message, "utf-8"), aad)

        self.conns[username] = connect_data
        return((header, ciphertext))


    def receive_message(self, username, message):
        header, ciphertext = message

        connect_data = self.conns[username]

        connect_pub_k = serialization.load_pem_public_key(header.rat_pub)



        if not connect_data.rk or (connect_data.dhr != connect_pub_k):
            peer_public_key = connect_pub_k
            connect_data.dhr = peer_public_key
            shared_key = connect_data.dhs.exchange(ec.ECDH(), peer_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=96,
                salt=connect_data.rk,
                info=b'root_key',
            ).derive(shared_key)
            connect_data.rk = derived_key[0:32]
            connect_data.ckr = derived_key[32:64]

        key_id = (header.rat_pub, header.n)

        if key_id in connect_data.mk_skipped:
            mk = connect_data.mk_skipped.pop(key_id)

            aad = header.rat_pub + header.iv + header.gov_iv + header.n.to_bytes(2, "big") + header.pn.to_bytes(2,
                                                                                                                "big")
            try:
                cleartext = AESGCM(mk).decrypt(header.iv, ciphertext, aad)
            except InvalidTag:
                raise Exception("Integrity error.")
            self.conns[username] = connect_data
            return cleartext.decode()

        if header.n <= connect_data.nr:
            raise Exception("Replay detected.")

        while connect_data.nr + 1 < header.n:
            if len(connect_data.mk_skipped) >= self.MAX_MSG_SKIP:
                connect_data.mk_skipped.pop(next(iter(connect_data.mk_skipped)))

            ckr_new = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=b'info',
            ).derive(connect_data.ckr)

            connect_data.ckr = ckr_new[:32]
            mk_skip = ckr_new[32:64]
            connect_data.nr += 1

            connect_data.mk_skipped[(header.rat_pub, connect_data.nr)] = mk_skip

        ckr_new = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'info',
        ).derive(connect_data.ckr)
        connect_data.ckr = ckr_new[:32]
        mk = ckr_new[32:64]
        connect_data.nr += 1
        aad = header.rat_pub + header.iv + header.gov_iv + header.n.to_bytes(2, "big") + header.pn.to_bytes(2, "big")
        try:
            cleartext = AESGCM(mk).decrypt(header.iv, ciphertext, aad)
        except InvalidTag:
            raise Exception("Integrity error.")
        self.conns[username] = connect_data
        return cleartext.decode()


def main():
    pass

if __name__ == "__main__":
    main()
