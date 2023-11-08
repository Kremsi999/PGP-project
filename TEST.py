import pickle
import struct
import tkinter as tk
from tkinter import ttk

import DSA
from ElGamal import import_privte_elgamal_keys_from_pem, elgamal_encrypt, elgamal_decrypt, generate_elgamal_keys, import_public_elgamal_keys_from_pem
import RSA
import AES
import ZIP
from SHA_ONE import sha1_hash
import ThreeDES

import customtkinter as ctk
from customtkinter import filedialog

from KeyRings import generatePublicRing, generatePrivateRing, privateKeyRing, publicKeyRing

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

#Ovo je tvoje i moje smece koje treba da se sredi

class App(ctk.CTk):


    def __init__(self):
        super().__init__()


        #Definisanje prozora
        self.title("ZP Projekat 2023")
        self.geometry(f"{1200}x{900}")
        #self.attributes("-fullscreen", True)

        #self.grid_columnconfigure(0, weight=1)
        #self.grid_columnconfigure(1, weight=1)
        #self.grid_columnconfigure(2, weight=1)
        #glavni frame
        self.GlavniFrame = ctk.CTkFrame(self, width=2000, height=650)
        self.GlavniFrame.grid(padx=20, pady=20, sticky="nsew")
        #prvi frame
        self.podaciFrame = ctk.CTkFrame(self.GlavniFrame, width=233, height=650)
        self.podaciFrame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        #Ime
        self.imeLabela = ctk.CTkLabel(self.podaciFrame, text="Ime: ", fg_color="transparent", font=("Arial", 16))
        self.imeLabela.grid(row=0, column=0, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.ime = ctk.CTkTextbox(self.podaciFrame, height=1, font=("Arial", 16))
        self.ime.grid(row=0, column=1, columnspan=2, padx=(0, 20), pady=(20, 0), sticky="nsew")
        #email
        self.emailLabela = ctk.CTkLabel(self.podaciFrame, text="Email: ", fg_color="transparent", font=("Arial", 16))
        self.emailLabela.grid(row=1, column=0, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.email = ctk.CTkTextbox(self.podaciFrame, height=1, font=("Arial", 16))
        self.email.grid(row=1, column=1, columnspan=2, padx=(0, 20), pady=(20, 0), sticky="nsew")
        #Algoritam za generisanje javnog i privatnog kljuca
        self.izborAlgoritma = ctk.CTkFrame(self.podaciFrame)
        self.izborAlgoritma.grid(row=2, columnspan=3, padx=20, pady=(20, 0), sticky="nsew")
        self.algoLabela = ctk.CTkLabel(self.izborAlgoritma, text="Izbor enkripcije: ", fg_color="transparent", font=("Arial", 16))
        self.algoLabela.grid(row=0, column=0, padx=(20, 20), pady=(0, 0), sticky="nsew")
        self.algoVar = ctk.IntVar(value=0)
        self.RSA = ctk.CTkRadioButton(master=self.izborAlgoritma, variable=self.algoVar, value=0, text="RSA")
        self.RSA.grid(row=1, column=0, pady=10, padx=20, sticky="n")
        self.DSA = ctk.CTkRadioButton(master=self.izborAlgoritma, variable=self.algoVar, value=1, text="DSA/ElGamal")
        self.DSA.grid(row=2, column=0, pady=10, padx=20, sticky="n")
        #Izbor kljuca
        self.velicinaKljucaLabela = ctk.CTkLabel(self.podaciFrame, text="Velicina kljuca: ", fg_color="transparent", font=("Arial", 16))
        self.velicinaKljucaLabela.grid(row=3, column=0, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.velicinaKljucaIzbor = ctk.CTkOptionMenu(self.podaciFrame, values=["1024", "2048"])
        self.velicinaKljucaIzbor.grid(row=3, column=1, columnspan=2, padx=(0, 20), pady=(20, 0), sticky="nsew")
        #Postavljanje lozinke
        self.Lozinka = ctk.CTkLabel(self.podaciFrame, text="Lozinka: ", fg_color="transparent", font=("Arial", 16))
        self.Lozinka.grid(row=4, column=0, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.loz = ctk.CTkEntry(self.podaciFrame, height=1, show="*", font=("Arial", 16))
        self.loz.grid(row=4, column=1, columnspan=2, padx=(0, 20), pady=(20, 0), sticky="nsew")
        #Generisanje kljuca
        self.Posalji = ctk.CTkButton(self.podaciFrame, command=self.kreirajKljuc, text="Generisi kljuceve")
        self.Posalji.grid(row=5, column=0, padx=20, pady=10, columnspan=3)
        #Uvezi kljuc
        self.Uvezi = ctk.CTkButton(self.podaciFrame, command=self.uveziKljuc, text="Uvezi kljuceve")
        self.Uvezi.grid(row=6, column=0, padx=20, pady=10, columnspan=3)

        # drugi frame
        self.slanjeFrame = ctk.CTkFrame(self.GlavniFrame, width=233, height=650)
        self.slanjeFrame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.Poruka = ctk.CTkButton(self.slanjeFrame, command=self.open_file, text="Izabrati Poruku za Slanje")
        self.Poruka.grid(row=1, column=0, padx=20, pady=10, columnspan=3)

        self.izborAlgoritma1 = ctk.CTkFrame(self.slanjeFrame)
        self.izborAlgoritma1.grid(row=3, columnspan=3, padx=20, pady=(20, 0), sticky="nsew")
        self.algoLabela1 = ctk.CTkLabel(self.izborAlgoritma1, text="Izbor enkripcije: ", fg_color="transparent",
                                       font=("Arial", 16))
        self.algoLabela1.grid(row=0, column=0, padx=(20, 20), pady=(0, 0), sticky="nsew")
        self.algoVar1 = ctk.IntVar(value=0)
        self.TripleDES = ctk.CTkRadioButton(master=self.izborAlgoritma1, variable=self.algoVar1, value=0, text="TripleDES")
        self.TripleDES.grid(row=1, column=0, pady=10, padx=20, sticky="n")
        self.AES128 = ctk.CTkRadioButton(master=self.izborAlgoritma1, variable=self.algoVar1, value=1, text="AES128")
        self.AES128.grid(row=2, column=0, pady=10, padx=20, sticky="n")

        self.Lozinka1 = ctk.CTkLabel(self.slanjeFrame, text="Lozinka: ", fg_color="transparent", font=("Arial", 16))
        self.Lozinka1.grid(row=4, column=0, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.loz1 = ctk.CTkEntry(self.slanjeFrame, height=1, show="*", font=("Arial", 16))
        self.loz1.grid(row=4, column=1, columnspan=2, padx=(0, 20), pady=(20, 0), sticky="nsew")


        self.Posalji = ctk.CTkButton(self.slanjeFrame, command=self.salji, text="Posalji")
        self.Posalji.grid(row=5, column=0, padx=20, pady=10, columnspan=3)

        # treci frame
        self.prijemFrame = ctk.CTkFrame(self.GlavniFrame, width=233, height=650)
        self.prijemFrame.grid(row=0, column=2, padx=20, pady=20, sticky="nsew")

        #self.PorukaD = ctk.CTkButton(self.prijemFrame, command=self.open_file, text="Izabrati Poruku za Dekripciju")   #zakomentarisano zato sto se poruka cuva u pozadini(self.poruka)
        #self.PorukaD.grid(row=3, column=0, padx=20, pady=10)

        self.PutanjaCuvanja = ctk.CTkButton(self.prijemFrame, command=self.save_file, text="Izabrati Gde se cuva")
        self.PutanjaCuvanja.grid(row=4, column=0, padx=20, pady=10)
        #Glavni za tabele
        self.GlavniFrame1 = ctk.CTkScrollableFrame(self, width=2000, height=650)
        self.GlavniFrame1.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")

        # cetvrti frame
        self.PrkLista = ctk.CTkFrame(self.GlavniFrame1, width=233, height=650)
        self.PrkLista.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")
        #Tabela
        self.PKTabela = ttk.Treeview(self.PrkLista,
                                     columns=('Timestamp', 'KeyID', 'Public key', 'Private key', 'UserID'),
                                     show='headings')
        self.PKTabela.heading('Timestamp', text='Timestamp')
        self.PKTabela.heading('KeyID', text='KeyID')
        self.PKTabela.heading('Public key', text='Public key')
        self.PKTabela.heading('Private key', text='Private key')
        self.PKTabela.heading('UserID', text='UserID')
        #Podesavanja dimenzija tabele
        self.PKTabela.column('Timestamp', width=200)
        self.PKTabela.column('KeyID', width=200)
        self.PKTabela.column('Public key', width=200)
        self.PKTabela.column('Private key', width=200)
        self.PKTabela.column('UserID', width=200)

        for row in privateKeyRing:
            self.PKTabela.insert('', 'end', values=row)

        #Izaberi i Obrisi
        self.DugmadiFrame = ctk.CTkFrame(self.PrkLista)
        self.DugmadiFrame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.IzaberiPKBtn = ctk.CTkButton(self.DugmadiFrame, text="Izaberi Kljuc", command=self.izaberiKljuc)
        self.ObrisiPKBtn = ctk.CTkButton(self.DugmadiFrame, text="Obrisi Kljuc", command=self.obrisiKljuc)
        #Stavi u frame
        self.PKTabela.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")
        self.IzaberiPKBtn.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.ObrisiPKBtn.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        # peti frame
        self.PukLista = ctk.CTkFrame(self.GlavniFrame1, width=500, height=650)
        self.PukLista.grid(row=2, column=0, padx=20, pady=20, sticky="nsew")
        # Tabela
        self.PUTabela = ttk.Treeview(self.PukLista, columns=('Timestamp', 'KeyID', 'Public key', 'UserID'), show='headings')
        self.PUTabela.heading('Timestamp', text='Timestamp')
        self.PUTabela.heading('KeyID', text='KeyID')
        self.PUTabela.heading('Public key', text='Public key')
        self.PUTabela.heading('UserID', text='UserID')

        for row in publicKeyRing:
            self.PUTabela.insert('', 'end', values=row)

        self.PUTabela.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Izaberi i Obrisi
        self.DugmadiFrame = ctk.CTkFrame(self.PukLista)
        self.DugmadiFrame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.IzaberiPKBtn = ctk.CTkButton(self.DugmadiFrame, text="Izaberi Kljuc", command=self.izaberiKljuc1)
        self.ObrisiPKBtn = ctk.CTkButton(self.DugmadiFrame, text="Obrisi Kljuc", command=self.obrisiKljuc1)
        # Stavi u frame
        self.PUTabela.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")
        self.IzaberiPKBtn.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.ObrisiPKBtn.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")





    #Ovo radi
    def open_file(self):
        filepath = filedialog.askopenfilename(filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        print(filepath)
        if filepath:
            with open(filepath, 'r') as file:
                #poruka koja je ucitana iz txt fajla za sifrovanje
                self.porukazas = file.read()
            print("Uspesno Otvoreno")
            print(self.porukazas)
        else:
            print("Nije ucitan fajl")

    #salje za RSA i DSA/ELGAMAL spojeno
    def salji(self):
        if self.algoVar1.get() == 0: #ovo je za TripleDes
            print("Triple")
            podaci = self.izaberiKljuc()
            password = self.loz1.get()

            if RSA.import_private_key(podaci[4], password) == 404:  #proba da importuje RSA ako nema radi DSA/ElGamal
                print("Triple")
                hashed = sha1_hash(self.porukazas)
                #password = self.loz1.get()
                #podaci = self.izaberiKljuc()
                podaci1 = self.izaberiKljuc1()
                self.PKSign = DSA.import_private_key(podaci[4], password)
                signature = DSA.sign_message(hashed, self.PKSign)
                firstPart = (signature, self.porukazas)
                Zipped = ZIP.zip_object(firstPart)
                Ks = ThreeDES.generate_key()
                string = Ks.decode('utf-8', errors='ignore')
                integer_value = int.from_bytes(Ks, byteorder='big', signed=False)
                PUEncrypt = import_public_elgamal_keys_from_pem(podaci1[3])
                self.PRDecrypt1 = podaci1[3]  # KeyId od publik za ovaj PK,tj njegov mejl da bi se importovao njegov PK za dekripciju
                encryption = elgamal_encrypt(integer_value, PUEncrypt)  # KLJUC
                encryptionBytes = pickle.dumps(encryption)
                symetricEncryption = ThreeDES.encrypt(Zipped, Ks)  # TEXT
                self.bytes1 = (len(encryptionBytes))
                self.bytes2 = (len(symetricEncryption))
                porukaZaSlanje = (symetricEncryption, encryptionBytes)
                self.poruka = ZIP.tuple_to_radix64(porukaZaSlanje)
                print("Poslata poruka")
            else:
                hashed = sha1_hash(self.porukazas)
                #password = self.loz1.get()
                #podaci = self.izaberiKljuc()
                podaci1 = self.izaberiKljuc1()
                self.PKSign = RSA.import_private_key(podaci[4], password)  # teba da se doda pasvord da se salje
                signature = RSA.sign_message(hashed, self.PKSign)
                firstPart = (signature, self.porukazas)
                Zipped = ZIP.zip_object(firstPart)
                Ks = ThreeDES.generate_key()
                string = Ks.decode('utf-8', errors='ignore')
                PUEncrypt = RSA.import_public_key(podaci1[3])
                self.PRDecrypt1 = podaci1[3]  # KeyId od publik za ovaj PK,tj njegov mejl da bi se importovao njegov PK za dekripciju
                encryption = RSA.encrypt_message(str(Ks), PUEncrypt)  # KLJUC
                symetricEncryption = ThreeDES.encrypt(Zipped, Ks)  # TEXT
                self.bytes1 = (len(encryption))
                self.bytes2 = (len(symetricEncryption))
                porukaZaSlanje = (symetricEncryption, encryption)
                self.poruka = ZIP.tuple_to_radix64(porukaZaSlanje)
                print("Poslata poruka")

        else:
            podaci = self.izaberiKljuc()
            password = self.loz1.get()
            if RSA.import_private_key(podaci[4], password) == 404: #proba da importuje RSA ako nema radi DSA/ElGamal
                hashed = sha1_hash(self.porukazas)
                #password = self.loz1.get()
                #podaci = self.izaberiKljuc()
                podaci1 = self.izaberiKljuc1()
                self.PKSign = DSA.import_private_key(podaci[4], password)  # teba da se doda pasvord da se salje
                signature = DSA.sign_message(hashed, self.PKSign)
                firstPart = (signature, self.porukazas)
                Zipped = ZIP.zip_object(firstPart)
                Ks = AES.generate_key()
                string = Ks.decode('utf-8', errors='ignore')
                integer_value = int.from_bytes(Ks, byteorder='big', signed=False)
                PUEncrypt = import_public_elgamal_keys_from_pem(podaci1[3])
                self.PRDecrypt1 = podaci1[3]  # KeyId od publik za ovaj PK,tj njegov mejl da bi se importovao njegov PK za dekripciju
                encryption = elgamal_encrypt(integer_value, PUEncrypt)
                encryptionBytes = pickle.dumps(encryption)
                symetricEncryption = AES.encrypt(Zipped, Ks)  # TEXT
                self.bytes1 = (len(encryptionBytes))
                self.bytes2 = (len(symetricEncryption))
                porukaZaSlanje = (symetricEncryption, encryptionBytes)
                self.poruka = ZIP.tuple_to_radix64(porukaZaSlanje)
                print("Poslata poruka")
            else:
                hashed = sha1_hash(self.porukazas)
                #password = self.loz1.get()
                #podaci = self.izaberiKljuc()
                podaci1 = self.izaberiKljuc1()
                self.PKSign = RSA.import_private_key(podaci[4], password) #teba da se doda pasvord da se salje
                signature = RSA.sign_message(hashed, self.PKSign)
                firstPart = (signature, self.porukazas)
                Zipped = ZIP.zip_object(firstPart)
                Ks = AES.generate_key()
                string = Ks.decode('utf-8', errors='ignore')
                PUEncrypt = RSA.import_public_key(podaci1[3])
                self.PRDecrypt1 = podaci1[3]  # KeyId od publik za ovaj PK,tj njegov mejl da bi se importovao njegov PK za dekripciju
                encryption = RSA.encrypt_message(str(Ks), PUEncrypt)  # KLJUC
                symetricEncryption = AES.encrypt(Zipped, Ks)  # TEXT
                self.bytes1 = (len(encryption))
                self.bytes2 = (len(symetricEncryption))
                porukaZaSlanje = (symetricEncryption, encryption)
                self.poruka = ZIP.tuple_to_radix64(porukaZaSlanje)
                print("Poslata poruka")

    def sacuvajKljuc(self):
        #self.refreshTable1()
        # self.refreshTable2()
        print("Sacuvanj KLjuc")

    #cuva poruku koja je dekriptovana za RSA
    def save_file(self):
        filepath1 = filedialog.asksaveasfilename(filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        print(filepath1)
        if filepath1:
            with open(filepath1, 'w') as file:
                if self.algoVar1.get() == 0:  # ovo je za TripleDes
                    print("Triple")
                    otpakovano = ZIP.radix64_to_tuple(self.poruka, self.bytes2, self.bytes1)
                    symetricEncryptionOtpakovano = otpakovano[0]  # TEXT
                    encryptionOtpakovano = otpakovano[1]  # KLJUC

                    if RSA.import_private_key(self.PRDecrypt1, self.loz1.get()) == 404:#ista fora kao za salji

                        PRDecrypt = import_privte_elgamal_keys_from_pem(self.PRDecrypt1)
                        encryptionOtpakovano = pickle.loads(otpakovano[1])
                        string1 = elgamal_decrypt(encryptionOtpakovano, PRDecrypt)
                        byte_string = string1.to_bytes((string1.bit_length() + 7) // 8, byteorder='big')
                        # Ks1 = byte_string[2:-1]
                        Ks1 = byte_string
                        string2 = Ks1.decode("unicode_escape").replace("\\\\", "\\")
                        Ks2 = string2.encode("latin1")
                        decryption = ThreeDES.decrypt(symetricEncryptionOtpakovano, Ks2)
                        Unzipped = ZIP.unzip_object(decryption)
                        verifikacija = DSA.verify_signature(sha1_hash(Unzipped[1]), Unzipped[0],
                                                            self.PKSign.public_key())
                        hes = sha1_hash(Unzipped[1])
                        if verifikacija == hes:
                            print(Unzipped[1])
                        file.write(Unzipped[1])
                        print("Uspesno Sacuvana Poruka")

                    else:
                        PRDecrypt = RSA.import_private_key(self.PRDecrypt1, self.loz1.get())
                        string1 = RSA.decrypt_message(encryptionOtpakovano, PRDecrypt)
                        Ks1 = string1[2:-1]
                        string2 = Ks1.decode("unicode_escape").replace("\\\\", "\\")
                        Ks2 = string2.encode("latin1")
                        decryption = ThreeDES.decrypt(symetricEncryptionOtpakovano, Ks2)
                        Unzipped = ZIP.unzip_object(decryption)
                        verifikacija = RSA.verify_signature(sha1_hash(Unzipped[1]), Unzipped[0],
                                                            self.PKSign.public_key())
                        hes = sha1_hash(Unzipped[1])
                        if verifikacija == hes:
                            print(Unzipped[1])
                        file.write(Unzipped[1])
                        print("Uspesno Sacuvana Poruka")

                else:
                    otpakovano = ZIP.radix64_to_tuple(self.poruka, self.bytes2, self.bytes1)
                    symetricEncryptionOtpakovano = otpakovano[0]  # TEXT
                    encryptionOtpakovano = otpakovano[1]  # KLJUC

                    if RSA.import_private_key(self.PRDecrypt1, self.loz1.get()) == 404:

                        PRDecrypt = import_privte_elgamal_keys_from_pem(self.PRDecrypt1)
                        encryptionOtpakovano = pickle.loads(otpakovano[1])
                        string1 = elgamal_decrypt(encryptionOtpakovano, PRDecrypt)
                        byte_string = string1.to_bytes((string1.bit_length() + 7) // 8, byteorder='big')
                        # Ks1 = byte_string[2:-1]
                        Ks1 = byte_string
                        string2 = Ks1.decode("unicode_escape").replace("\\\\", "\\")
                        Ks2 = string2.encode("latin1")
                        decryption = AES.decrypt(symetricEncryptionOtpakovano, Ks2)
                        Unzipped = ZIP.unzip_object(decryption)
                        verifikacija = DSA.verify_signature(sha1_hash(Unzipped[1]), Unzipped[0],
                                                            self.PKSign.public_key())
                        hes = sha1_hash(Unzipped[1])
                        if verifikacija == hes:
                            print(Unzipped[1])
                        file.write(Unzipped[1])
                        print("Uspesno Sacuvana Poruka")

                    else:

                        PRDecrypt = RSA.import_private_key(self.PRDecrypt1, self.loz1.get())
                        string1 = RSA.decrypt_message(encryptionOtpakovano, PRDecrypt)
                        Ks1 = string1[2:-1]
                        string2 = Ks1.decode("unicode_escape").replace("\\\\", "\\")
                        Ks2 = string2.encode("latin1")
                        decryption = AES.decrypt(symetricEncryptionOtpakovano, Ks2)
                        Unzipped = ZIP.unzip_object(decryption)
                        verifikacija = RSA.verify_signature(sha1_hash(Unzipped[1]), Unzipped[0],
                                                            self.PKSign.public_key())
                        hes = sha1_hash(Unzipped[1])
                        if verifikacija == hes:
                            print(Unzipped[1])
                        file.write(Unzipped[1])
                        print("Uspesno Sacuvana Poruka")

        else:
            print("Nije selektovan fajl")

    def izaberiKljuc(self):
        selectedRow = self.PKTabela.selection()[0]
        value = self.PKTabela.item(selectedRow, 'values')
        KeyInfo = tuple(value)
        print(KeyInfo)
        return KeyInfo

    def izaberiKljuc1(self):
        selectedRow = self.PUTabela.selection()[0]
        value = self.PUTabela.item(selectedRow, 'values')
        KeyInfo = tuple(value)
        print(KeyInfo)
        return KeyInfo

    def obrisiKljuc(self):
        selectedRow = self.PKTabela.selection()[0]
        values = self.PKTabela.item(selectedRow, 'values')
        #print(values)
        for i in privateKeyRing:
            #print(int(values[1]))
            #print((i[1]))
            if int(values[1]) == int(i[1]):
                #print(int(values[1]))
                #print((i[1]))
                privateKeyRing.remove(i)

        #delete_dsa_keys(name, email, key_size)
        self.PKTabela.delete(selectedRow)

    def obrisiKljuc1(self):
        selectedRow = self.PUTabela.selection()[0]
        values = self.PUTabela.item(selectedRow, 'values')
        print(values)
        for i in publicKeyRing:
            if int(values[1]) == int(i[1]):
                publicKeyRing.remove(i)
        #delete_dsa_keys(name, email, key_size)
        self.PUTabela.delete(selectedRow)

    def delete_all_rows(self):
        for item in self.PKTabela.get_children():
            self.PKTabela.delete(item)
        for item in self.PUTabela.get_children():
            self.PUTabela.delete(item)

    def kreirajKljuc(self):
        name = self.ime.get("0.0", "end").rstrip("\n")
        email = self.email.get("0.0", "end").rstrip("\n")
        passphrase = self.loz.get()
        keysize = int(self.velicinaKljucaIzbor.get())
        if self.algoVar.get() == 0:
            RSA.generate_rsa_keys(name, email, keysize, passphrase)
        else:
            DSA.generate_dsa_keys(name, email, keysize, passphrase)
            generate_elgamal_keys(name, email, keysize, passphrase)

        self.delete_all_rows()

        for row in privateKeyRing:
            self.PKTabela.insert('', 'end', values=row)

        for row in publicKeyRing:
            self.PUTabela.insert('', 'end', values=row)

    def uveziKljuc(self):
        password = (self.loz.get())
        email = self.email.get("0.0", "end").rstrip("\n")
        generatePrivateRing(email, password) #treba da se doda password za gnerisanje
        generatePublicRing()

        self.delete_all_rows()

        for row in privateKeyRing:
            self.PKTabela.insert('', 'end', values=row)

        for row in publicKeyRing:
            self.PUTabela.insert('', 'end', values=row)


if __name__ == "__main__":
    app = App()
    app.mainloop()
