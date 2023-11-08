import base64
import os
import re
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

#prsteni
privateKeyRing = []
publicKeyRing = []


def generatePrivateRing(email, password=None):
    privateKeyRing.clear()
    #nalazim sve fajlove koji imaju ovakav potpis(regex)
    ruta1 = re.compile(r"\w+\s\w+" + re.escape(email) +
                         r"_private_key_rsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    private_key_path = None

    ruta2 = re.compile(r"\w+\s\w+" + re.escape(email) +
                          r"_private_key_rsa_\w{1}_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    ruta3 = re.compile(r"\w+\s\w+" + re.escape(email) + r"_private_key_dsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    ruta4 = re.compile(
        r"\w+\s\w+" + re.escape(email) + r"_private_key_dsa_\w{1}_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")

    #ovde iteriram kroz folder
    for filename in os.listdir("Kljucevi"):
        HasPass = ""
        if ruta1.match(filename) or ruta2.match(filename) or ruta3.match(filename) or ruta4.match(filename):
            private_key_path = os.path.join("Kljucevi", filename)
            #otvaram taj fajl koji nadje
            with open(private_key_path, "rb") as f:
                private_key_pem = f.read()
            #gledam da izvucem timestamp kljuca iskreno evo sad gledam nzm sto je dva puta mrzi me da razmisljam
            match = ruta2.findall(filename) or ruta4.findall(filename)
            if match:
                HasPass = match[0]
                datetime_str = re.findall(r"\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}", private_key_path)
            else:
                HasPass = ""
                datetime_str = re.findall(r"\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}", private_key_path)

            #ovo mi ne treba al nek bleji tu
            datetime_str = re.findall(r"\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}", private_key_path)
            if datetime_str:
                datetime_obj = datetime.strptime(datetime_str[0], "%Y-%m-%d_%H_%M_%S")
                print("Parsed datetime object:", datetime_obj)
            else:
                print("Datetime not found in filename.")
            #svi kljucevi koji imaju sifre imaju u svom nazivu E to je ovaj HasPass ovde samo otkljucavamo kljuc (reci a)
            if HasPass:
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem,
                        password=password.encode(),
                        backend=default_backend()
                    )
                    print("Second Round private key imported")
                except ValueError:
                    print("Wrong password")
                    exit(2)
            else:
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem,
                        password=None,
                        backend=default_backend()
                    )
                    print("Private key imported")

                except ValueError:
                    print("Error")
                    exit(1)
            #ovde definisem parametre za prsten (moram da vidim samo kako private key da predstavim)
            KeyID = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)[-34:-26]
            KeyID = base64.b64encode(KeyID).decode()
            KeyID = int.from_bytes(base64.urlsafe_b64decode(KeyID), 'big')
            #encrypted_private_key = hash_private_key(private_key_pem, HasPass)
            key = (datetime_str, KeyID,
                   private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo),
                   private_key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())),
                   email)
            privateKeyRing.append(key)

#Generisanje javnog prstena uglavnom videces skoro sve isto kao i za privatne
def generatePublicRing():
    publicKeyRing.clear()
    #ova kobasica mora za email (^stavio sam ovaj znak kao specijalni karakter da mogu lepo da odvojim email to
    # #sam promenio i ustalim fajlovima za javne kljuceve ali mora da se proveri)
    pattern = re.compile(r"\w+\s\w+ˆ[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?_public_key_rsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    pattern1 = re.compile(r"\w+\s\w+ˆ[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?_public_key_dsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    pattern2 = re.compile(r"\w+\s\w+ˆ[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?_public_key_elgamal_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    public_key_path = None
    for filename in os.listdir("Kljucevi"):
        if pattern.match(filename) or pattern1.match(filename) or pattern2.match(filename):
            public_key_path = os.path.join("Kljucevi", filename)

            with open(public_key_path, "rb") as f:
                public_key_pem = f.read()

            datetime_str = re.findall(r"\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}", public_key_path)
            UserID = re.findall(r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?", public_key_path)
            try:
                if pattern2.match(filename):
                    import ElGamal
                    public_key = ElGamal.import_public_elgamal_keys_from_pem(UserID[0])
                    print("ElGamal key imported")
                else:
                    public_key = serialization.load_pem_public_key(
                        public_key_pem,
                        backend=default_backend()
                    )
                    print("Public key imported")

            except ValueError:
                print("Error")
                exit(1)
            #Ovde je sve ok sto se tice parametara nzm da li mi treba jos neki jer ne radimo poverenje

            if pattern2.match(filename):
                KeyID = int(public_key.y)
                KeyID = KeyID & ((1 << 64) - 1)
                PU = (datetime_str, KeyID, public_key.y, UserID)
                publicKeyRing.append(PU)
            else:
                KeyID = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)[-34:-26]
                print(KeyID)
                KeyID = base64.b64encode(KeyID).decode()
                KeyID = int.from_bytes(base64.urlsafe_b64decode(KeyID), 'big')
                key = (datetime_str, KeyID, public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo),UserID)
                publicKeyRing.append(key)

#testiranje funkcija
# generatePrivateRing("nemanjakrcmar.nk@gmail.com")
# for i in privateKeyRing:
#     print(i)
#
# generatePublicRing()
# for i in publicKeyRing:
#     print(i)
