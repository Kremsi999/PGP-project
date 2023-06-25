# PGP-project
Simulating PGP protocol in Python with cryptography and pycryptodome modules with a GUI developed using customtkinter module


In the GUI you have 3 parts of the app
  1.Key generation
  2.Message sending
  3.Message receiving

In the first part the user inserts his information (Name and email),
type of keys used for signing and crypting (RSA or DSA with ElGamal encryption),
key sizes and after the data is inserted you can generate the public and private
keys. You can also just enter your email and you will see your private KeyRing 
generated in a table. When you do either steps the public KeyRing is also generated.

Second part, you choose a file to send, a type of symetric encryption (AES128, 3DES)
and a private key for signing and a receivers public key for encryption.

The third part select the place where you would like for the message to be saved. The 
unpacking is done in the back in the app with all information needed for decryption
held in the message itself.
