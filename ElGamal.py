import base64
import re
from datetime import datetime
import os

from Cryptodome import Random
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import random
from Cryptodome.Util import number
import struct

from KeyRings import privateKeyRing, publicKeyRing


#Dobrodosao na kinesko mucenje
#Generise se kljuc
#(Gledao sam kako je moguce da generisem kljuc od 1024 bita i imam element od 1023 bita) pa u sustini radi samo mu treba
#mnogo vremena da uradi generisanje jer ipak maths hard


def generate_elgamal_keys(name, email, key_size, password=None):
    if (key_size == 2048) or (key_size == 1024):
        random_generator = Random.new().read
        key = ElGamal.generate(key_size, random_generator)
        y = int(key.y)
        y = y & ((1 << 64) - 1)
        print(y.bit_length())

    p = key.p
    g = key.g
    y = key.y
    x = key.x

    timestamp = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")

    with open(f'Kljucevi/{name}_{email}_private_key_elgamal_{key_size}_{timestamp}.pem', 'wb') as f:
        f.write(base64.b64encode(str(p).encode()))
        f.write(b'\n')
        f.write(base64.b64encode(str(g).encode()))
        f.write(b'\n')
        f.write(base64.b64encode(str(y).encode()))
        f.write(b'\n')
        f.write(base64.b64encode(str(x).encode()))

    with open(f'Kljucevi/{name}ˆ{email}_public_key_elgamal_{key_size}_{timestamp}.pem', 'wb') as f:
        f.write(base64.b64encode(str(p).encode()))
        f.write(b'\n')
        f.write(base64.b64encode(str(g).encode()))
        f.write(b'\n')
        f.write(base64.b64encode(str(y).encode()))

    KeyID = int(key.y)
    KeyID = KeyID & ((1 << 64) - 1)
    print(KeyID.bit_length())
    print(KeyID)

    PK = (str(timestamp), KeyID, key.y, key.x, email)
    privateKeyRing.append(PK)
    PU = (str(timestamp), KeyID, key.y, email)
    publicKeyRing.append(PU)


#Ono gore sto sam napisao
def import_privte_elgamal_keys_from_pem(email):
    pattern = re.compile(r"\w+\s\w+" + re.escape(email) +
                         r"_private_key_elgamal_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")

    private_key_path = None

    for filename in os.listdir("Kljucevi"):
        if pattern.match(filename):
            private_key_path = os.path.join("Kljucevi", filename)
            break

    if private_key_path is None:
        print("Private key file not found")
        exit(1)

    with open(private_key_path, 'rb') as f:
        lines = f.readlines()
    p = int(base64.b64decode(lines[0].strip()).decode())
    g = int(base64.b64decode(lines[1].strip()).decode())
    y = int(base64.b64decode(lines[2].strip()).decode())
    x = int(base64.b64decode(lines[3].strip()).decode())

    private_key = ElGamal.construct((p, g, y, x))
    return private_key


def import_public_elgamal_keys_from_pem(email):
    pattern = re.compile(
        r"\w+\s\w+" + re.escape(email) + r"_public_key_elgamal_\d{4}_\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}.pem")

    public_key_path = None

    for filename in os.listdir("Kljucevi"):
        if pattern.match(filename):
            public_key_path = os.path.join("Kljucevi", filename)
            break


    if public_key_path is None:
        print("Private key file not found")
        exit(1)

    with open(public_key_path, 'rb') as f:
        lines = f.readlines()
    p = int(base64.b64decode(lines[0].strip()).decode())
    g = int(base64.b64decode(lines[1].strip()).decode())
    y = int(base64.b64decode(lines[2].strip()).decode())

    public_key = ElGamal.construct((p, g, y))

    return public_key

#Trebace da se sreda za ovo radi
def delete_elgamal_keys(name, email, key_size, KeyID, timestamp):
    # Check if the keys exist
    if os.path.exists(f'Kljucevi/{name}_{email}_private_key_elgamal_{key_size}_{timestamp}.pem'):
        if KeyID and email:
        # Delete the private key file
            os.remove(f'Kljucevi/{name}_{email}_private_key_elgamal_{key_size}_{timestamp}.pem')

    if os.path.exists(f'Kljucevi/{name}_{email}_public_key_elgamal_{key_size}_{timestamp}.pem'):
        if KeyID and email:
        # Delete the public key file
            os.remove(f'Kljucevi/{name}_{email}_public_key_elgamal_{key_size}_{timestamp}.pem')


#Radi ne pitaj kako
def elgamal_encrypt(plaintext, public_key):
    p = public_key.p
    g = public_key.g
    y = public_key.y
    k = random.randint(1, int(p) - 2)
    c1 = int(pow(g, k, p))
    s = int(pow(y, k, p))
    c2 = (plaintext * int(s)) % int(p)
    return (c1,c2)


#Radi ne pitaj kako
def elgamal_decrypt(ciphertext, private_key):
    p = int(private_key.p)
    x = int(private_key.x)
    c1, c2 = ciphertext
    s = int(pow(c1, x, p))
    plaintext = (c2 * number.inverse(s, p)) % p
    return plaintext

#Testiranje
# Example usage:
# Generate keys
# elgamal_key = generate_elgamal_keys("Nemanja Krcmar", "nemanja@gmail.com", 1024)
#
# PR = import_privte_elgamal_keys_from_pem("Nemdsa@gmail.com")
# PU = import_public_elgamal_keys_from_pem("Nemdsa@gmail.com")

#
# plaintext = 42
#
# # Encryption
# ciphertext = elgamal_encrypt(plaintext, PU)
# print("Ciphertext:", ciphertext)
#
# # Decryption
# decrypted_text = elgamal_decrypt(ciphertext, PR)
# print("Decrypted text:", decrypted_text)
