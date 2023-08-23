from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


#Najgluplja stvar generise 160-bit hash code
def sha1_hash(msg):
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(msg.encode('utf-8'))
    hashed_msg = digest.finalize()
    return hashed_msg.hex()

