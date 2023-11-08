import base64
import os
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

from KeyRings import privateKeyRing, publicKeyRing


#Generisanje kljuceva uglavnom sve isto kao rsa nzm da li treba uopste da ti pisem ovde komentare(da isti kurac kao RSA)
def generate_dsa_keys(name, email, key_size, password=None):
    if (key_size == 2048) or (key_size == 1024):
        private_key = dsa.generate_private_key(
            key_size=key_size,
            backend=default_backend()
        )
        if password:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )
        else:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

        timestamp = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")

        if password:
            with open(f'Kljucevi/{name}_{email}_private_key_dsa_E_{key_size}_{timestamp}.pem', 'wb') as f:
                f.write(pem)
        else:
            with open(f'Kljucevi/{name}_{email}_private_key_dsa_{key_size}_{timestamp}.pem', 'wb') as f:
                f.write(pem)

        public_key = private_key.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        last64 = pem[-8:]
        KeyID = base64.b64encode(last64).decode()
        KeyID = int.from_bytes(base64.urlsafe_b64decode(KeyID), 'big')

        with open(f'Kljucevi/{name}ˆ{email}_public_key_dsa_{key_size}_{timestamp}.pem', 'wb') as f:
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


#mora da se sredi
def delete_dsa_keys(name, email, key_size, KeyID, timestamp):
    if os.path.exists(f'Kljucevi/{name}_{email}_private_key_dsa_E_{key_size}_{timestamp}.pem'):
        if KeyID and email:
            os.remove(f'Kljucevi/{name}_{email}_private_key_dsa_E_{key_size}_{timestamp}.pem')

    if os.path.exists(f'Kljucevi/{name}_{email}_public_key_dsa_{key_size}_{timestamp}.pem'):
        if KeyID and email:
            os.remove(f'Kljucevi/{name}_{email}_public_key_dsa_{key_size}_{timestamp}.pem')


def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode(),
        hashes.SHA256()
    )

    return signature


def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message.encode(),
            hashes.SHA256()
        )
        return message
    except InvalidSignature:
        return False


def import_private_key(email, password=None):
    HasPass = ""
    pattern = re.compile(r"\w+\s\w+" + re.escape(email) + r"_private_key_dsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    pattern1 = re.compile(r"\w+\s\w+" + re.escape(email) + r"_private_key_dsa_\w{1}_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    private_key_path = None

    for filename in os.listdir("Kljucevi"):
        if pattern.match(filename) or pattern1.match(filename):
            private_key_path = os.path.join("Kljucevi", filename)
            break

    if private_key_path is None:
        print("Private key file not found")
        exit(1)

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
            print("Private key imported round 2")
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


def import_public_key(email):
    pattern = re.compile(r"\w+\s\w+" + re.escape(email) + r"_public_key_dsa_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")
    public_key_path = None
    pattern1 = re.compile(r"\w+\s\w+" + re.escape(email) + r"_public_key_dsa_\w{1}_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")

    for filename in os.listdir("Kljucevi"):
        if pattern.match(filename) or pattern1.match(filename):
            public_key_path = os.path.join("Kljucevi", filename)
            break

    if public_key_path is None:
        print("Public key file not found")
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

