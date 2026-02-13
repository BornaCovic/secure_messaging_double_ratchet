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
    """ TODO: Dekripcija poruke unutar kriptosustava javnog kljuca `Elgamal`
        gdje, umjesto kriptiranja jasnog teksta množenjem u Z_p, jasni tekst
        kriptiramo koristeci simetricnu sifru AES-GCM.

        Procitati poglavlje `The Elgamal Encryption Scheme` u udzbeniku
        `Understanding Cryptography` (Christof Paar , Jan Pelzl) te obratiti
        pozornost na `Elgamal Encryption Protocol`

        Dakle, funkcija treba:
        1. Izracunati `masking key` `k_M` koristeci privatni kljuc `gov_priv` i
           javni kljuc `gov_pub` koji se nalazi u zaglavlju `header`.
        2. Iz `k_M` derivirati kljuc `k` za AES-GCM koristeci odgovarajucu
           funkciju za derivaciju kljuca.
        3. Koristeci `k` i AES-GCM dekriptirati `gov_ct` iz zaglavlja da se
           dobije `sending (message) key` `mk`
        4. Koristeci `mk` i AES-GCM dekriptirati sifrat `ciphertext` orginalne
           poruke.
        5. Vratiti tako dobiveni jasni tekst.

        Naravno, lokalne varijable mozete proizvoljno imenovati.  Zaglavlje
        poruke `header` treba sadrzavati polja `gov_pub`, `gov_iv` i `gov_ct`.
        (mozete koristiti postojeci predlozak).
    """
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

# Možete se (ako želite) poslužiti sa sljedeće dvije strukture podataka
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

# Dopusteno je mijenjati sve osim sučelja.
class Messenger:
    """ Klasa koja implementira klijenta za čavrljanje
    """

    MAX_MSG_SKIP = 10

    def __init__(self, username, ca_pub_key, gov_pub):
        """ Inicijalizacija klijenta

        Argumenti:
            username (str)      --- ime klijenta
            ca_pub_key (class)  --- javni ključ od CA (certificate authority)
            gov_pub (class) --- javni ključ od vlade

        Returns: None
        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        self.gov_pub = gov_pub
        self.conns = {}

    def generate_certificate(self):
        """ TODO: Metoda generira i vraća certifikacijski objekt.

        Metoda generira inicijalni par Diffie-Hellman ključeva. Serijalizirani
        javni ključ, zajedno s imenom klijenta, pohranjuje se u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt može biti proizvoljnog
        tipa (npr. dict ili tuple). Za serijalizaciju ključa možete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        Returns: <certificate object>
        """

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
        """ TODO: Metoda verificira certifikat od `CA` i sprema informacije o
                  klijentu.

        Argumenti:
        cert_data --- certifikacijski objekt
        cert_sig  --- digitalni potpis od `cert_data`

        Returns: None

        Metoda prima certifikat --- certifikacijski objekt koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta s kojim želi komunicirati te njegov
        potpis. Certifikat se verificira pomoću javnog ključa CA (Certificate
        Authority), a ako verifikacija uspije, informacije o klijentu (ime i javni
        ključ) se pohranjuju. Javni ključ CA je spremljen tijekom inicijalizacije
        objekta.

        U slučaju da verifikacija ne prođe uspješno, potrebno je baciti iznimku.

        """
        cert_data_pickle = pickle.dumps(cert_data)

        try:
            self.ca_pub_key.verify(cert_sig, cert_data_pickle, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise ValueError("Invalid signature.")

        conect_public= cert_data["public_key"]
        conect_pub_k = serialization.load_pem_public_key(conect_public)

        self.conns[cert_data["client_username"]] = Connection(dhs=self.s_key,dhr=conect_pub_k)




    def send_message(self, username, message):
        """ TODO: Metoda šalje kriptiranu poruku `message` i odgovarajuće
                  zaglavlje korisniku `username`.

        Argumenti:
        message  --- poruka koju ćemo poslati
        username --- korisnik kojem šaljemo poruku

        returns: (header, ciphertext).

        Zaglavlje poruke treba sadržavati podatke potrebne
        1) klijentu da derivira nove ključeve i dekriptira poruku;
        2) Velikom Bratu da dekriptira `sending` ključ i dode do sadržaja poruke.

        Pretpostavite da već posjedujete certifikacijski objekt klijenta (dobiven
        pomoću metode `receive_certificate`) i da klijent posjeduje vaš. Ako
        prethodno niste komunicirali, uspostavite sesiju generiranjem ključeva po-
        trebnih za `Double Ratchet` prema specifikaciji. Inicijalni korijenski ključ
        (`root key` za `Diffie-Hellman ratchet`) izračunajte pomoću ključa
        dobivenog u certifikatu i vašeg inicijalnog privatnog ključa.



        Svaka poruka se sastoji od sadržaja i zaglavlja. Svaki put kada šaljete
        poruku napravite korak u lancu `symmetric-key ratchet` i lancu
        `Diffie-Hellman ratchet` ako je potrebno prema specifikaciji (ovo drugo
        možete napraviti i prilikom primanja poruke); `Diffie-Helman ratchet`
        javni ključ oglasite putem zaglavlja. S novim ključem za poruke
        (`message key`) kriptirajte i autentificirajte sadržaj poruke koristeći
        simetrični kriptosustav AES-GCM; inicijalizacijski vektor proslijedite
        putem zaglavlja. Dodatno, autentificirajte odgovarajuća polja iz
        zaglavlja, prema specifikaciji."""

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

        """Sve poruke se trebaju moći dekriptirati uz pomoć privatnog kljuca od
        Velikog brata; pripadni javni ključ dobiti ćete prilikom inicijalizacije
        kli- jenta. U tu svrhu koristite protokol enkripcije `ElGamal` tako da,
        umjesto množenja, `sending key` (tj. `message key`) kriptirate pomoću
        AES-GCM uz pomoć javnog ključa od Velikog Brata. Prema tome, neka
        zaglavlje do- datno sadržava polja `gov_pub` (`ephemeral key`) i
        `gov_ct` (`ciphertext`) koja predstavljaju izlaz `(k_E , y)`
        kriptosustava javnog kljuca `Elgamal` te `gov_iv` kao pripadni
        inicijalizacijski vektor.

        U ovu svrhu proučite `Elgamal Encryption Protocol` u udžbeniku
        `Understanding Cryptography` (glavna literatura). Takoder, pročitajte
        dokumentaciju funkcije `gov_decrypt`.

        Za zaglavlje možete koristiti već dostupnu strukturu `Header` koja sadrži
        sva potrebna polja.

        Metoda treba vratiti zaglavlje i kriptirani sadrzaj poruke kao `tuple`:
        (header, ciphertext).

        """
        self.conns[username] = connect_data
        return((header, ciphertext))


    def receive_message(self, username, message):
        """ TODO: Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- korisnik koji je poslao poruku

        returns: plaintext

        Metoda prima kriptiranu poruku od korisnika s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od korisnika
        (dobiven pomoću `receive_certificate`) i da je korisnik izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.
        connect_data =  self.conns[username]
        """
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

        """
        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.
        """


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
