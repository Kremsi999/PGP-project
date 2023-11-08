import AES
import ThreeDES
import ZIP
from SHA_ONE import sha1_hash
import RSA
#SLANJE
msg = "Hello World!"
hashed = sha1_hash(msg)
PKSign = RSA.import_private_key("nemanja@gmail.com")
signature = RSA.sign_message(hashed, PKSign)
firstPart = (signature, msg)
Zipped = ZIP.zip_object(firstPart)
Ks = ThreeDES.generate_key()
string = Ks.decode('utf-8', errors='ignore')
PUEncrypt = RSA.import_public_key("nikolica123@gmail.com")
encryption = RSA.encrypt_message(str(Ks), PUEncrypt) #KLJUC
symetricEncryption = ThreeDES.encrypt(Zipped, Ks)#TEXT
bytes1 = (len(encryption))
bytes2 = (len(symetricEncryption))
porukaZaSlanje = (symetricEncryption, encryption)
poruka = ZIP.tuple_to_radix64(porukaZaSlanje)





#PRIJEM
otpakovano = ZIP.radix64_to_tuple(poruka, bytes2, bytes1)
symetricEncryptionOtpakovano = otpakovano[0]#TEXT
encryptionOtpakovano = otpakovano[1]#KLJUC
PRDecrypt = RSA.import_private_key("nikolica123@gmail.com")
string1 = RSA.decrypt_message(encryptionOtpakovano, PRDecrypt)
Ks1 = string1[2:-1]
string2 = Ks1.decode("unicode_escape").replace("\\\\", "\\")
Ks2 = string2.encode("latin1")
decryption = ThreeDES.decrypt(symetricEncryptionOtpakovano, Ks2)
Unzipped = ZIP.unzip_object(decryption)
hes = sha1_hash(Unzipped[1])
verifikacija = RSA.verify_signature(sha1_hash(Unzipped[1]), Unzipped[0], PKSign.public_key())
hes = sha1_hash(Unzipped[1])
if verifikacija == hes:
    print(Unzipped[1])


# porukaPrijem = porukaZaSlanje
# podelaPoruke = porukaPrijem.split(";")
# encryption = podelaPoruke[1]
# symetricEncryption = podelaPoruke[0]

