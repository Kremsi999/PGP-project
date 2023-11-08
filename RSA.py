import base64
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

from KeyRings import privateKeyRing, publicKeyRing


#Generisanje kljuceva
def generate_rsa_keys(name, email, key_size, password=None):
    if (key_size == 2048) or (key_size == 1024):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        #Ako ima sifru
        if password:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        else:#Ako nema sifru
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        #timestap pise ti
        timestamp = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")

        #Kako se cuvaju
        if password:
            with open(f'Kljucevi/{name}_{email}_private_key_rsa_E_{key_size}_{timestamp}.pem', 'wb') as f:
                f.write(pem)
        else:
            with open(f'Kljucevi/{name}_{email}_private_key_rsa_{key_size}_{timestamp}.pem', 'wb') as f:
                f.write(pem)

        public_key = private_key.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        #izvlacim poslednjih 64 bita javnog kljuca
        last64 = pem[-34:-26]
        KeyID = base64.b64encode(last64).decode()
        KeyID = int.from_bytes(base64.urlsafe_b64decode(KeyID), 'big')

        # Save public key to a file
        with open(f'Kljucevi/{name}ˆ{email}_public_key_rsa_{key_size}_{timestamp}.pem', 'wb') as f:
            f.write(pem)

        key = (str(timestamp), KeyID,
               private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo),
               private_key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())),
               email)
        privateKeyRing.append(key)

        key = (str(timestamp), KeyID, public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.SubjectPublicKeyInfo),
               email)
        publicKeyRing.append(key)


#Enkripcija mora da se proveri ali trebalo bi da radi
def encrypt_message(msg, public_key):
    ciphertext = public_key.encrypt(
        msg.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


#Dekripcija mora da se proveri ali trebalo bi da radi
def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


#Potpisivanje mora da se proveri ali trebalo bi da radi
def sign_message(msg, private_key):
    signature = private_key.sign(
        msg.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


#Verifikacija mora da se proveri ali trebalo bi da radi
def verify_signature(msg, signature, public_key):
    try:
        public_key.verify(
            signature,
            msg.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return msg
    except InvalidSignature:
        return False


#Mora da se sredi ovo nmg sad idem da spavam
def delete_rsa_keys(name, email, key_size, KeyID, timestamp):
    if os.path.exists(f'Kljucevi/{name}_{email}_private_key_rsa_E_{key_size}_{timestamp}.pem'):
        if KeyID and email:
            os.remove(f'Kljucevi/{name}_{email}_private_key_rsa_E_{key_size}_{timestamp}.pem')

    if os.path.exists(f'Kljucevi/{name}_{email}_public_key_rsa_{key_size}_{timestamp}.pem'):
        if KeyID and email:
            os.remove(f'Kljucevi/{name}_{email}_public_key_rsa_{key_size}_{timestamp}.pem')


#Ovo ne da radi sije xD manje vise ista f-ja kao za generisanje kljuceva samo za jednu instancu
def import_private_key(email, password=None):
    HasPass = ""
    pattern = re.compile(r"\w+\s\w+" + re.escape(email) +
                         r"_private_key_rsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    private_key_path = None

    pattern1 = re.compile(r"\w+\s\w+" + re.escape(email) +
                          r"_private_key_rsa_\w{1}_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")


    for filename in os.listdir("Kljucevi"):
        if pattern.match(filename) or pattern1.match(filename):
            private_key_path = os.path.join("Kljucevi", filename)
            break

    if private_key_path is None:
        print("Private key file not found")
        return 404  #promenjeno sa exit(1) da bi moglao da se uhvati return

    with open(private_key_path, "rb") as f:
        private_key_pem = f.read()

    match = pattern1.findall(filename)
    if match:
        HasPass = match[0]

    datetime_str = re.findall(r"\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}", private_key_path)
    if datetime_str:
        datetime_obj = datetime.strptime(datetime_str[0], "%Y-%m-%d_%H_%M_%S")
        print("Parsed datetime object:", datetime_obj)
    else:
        print("Datetime not found in filename.")

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

    return private_key

#Ovo ne da radi sije xD manje vise ista f-ja kao za generisanje kljuceva samo za jednu instancu
def import_public_key(email):
    pattern = re.compile(
        r"\w+\s\w+" + re.escape(email) + r"_public_key_rsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    public_key_path = None
    pattern1 = re.compile(r"\w+\s\w+" + re.escape(email) +
                          r"_public_key_rsa_\w{1}_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")


    for filename in os.listdir("Kljucevi"):
        if pattern.match(filename) or pattern1.match(filename):
            public_key_path = os.path.join("Kljucevi", filename)
            break

    if public_key_path is None:
        print("Private key file not found")
        exit(1)

    with open(public_key_path, "rb") as f:
        public_key_pem = f.read()

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    datetime_str = re.findall(r"\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}", public_key_path)
    if datetime_str:
        datetime_obj = datetime.strptime(datetime_str[0], "%Y-%m-%d_%H_%M_%S")
        print("Parsed datetime object:", datetime_obj)
    else:
        print("Datetime not found in filename.")

    last64 = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)[-8:]
    KeyID = base64.b64encode(last64).decode()
    KeyID = int.from_bytes(base64.urlsafe_b64decode(KeyID), 'big')
    print(KeyID)

    return public_key


