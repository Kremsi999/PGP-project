#ovde bi trebalo da se istestiruja sve funkcije i nacini kako funkcionisu reci aaaa
#sta radi:
    #1. Ceo RSA i DSA bi trebalo da rade
    #2. ElGamal moram jos da smislim kako da cuvam podatke za kljuc pa da ih importujem/exportujem
    #3. Prsteni rade
    #4. Ostale algoritme simetricne nisam proveravao nakon sto sa drkao ovde trebalo bi da rade
    #5. SHA i ZIP rade
    #6. Treba uraditi strukturu poruke i GUI

# E sad sustinska ideja je ova startuje se program svi javni kljucevi se odmah ucitaju u
# tabele. Nakon unosa email-a unosimo sve njegove privatne kljuceve iz foldera Kljucevi.
# Kada generise svoje kljuceve samo ih dodajemo u niz tuple-ova (nalaze se u KeyRings.py)
# kada se to uradi generisemo poruku (Za sada neka bude textbox u koji upisujemo string kao
# poruku) pa posle ako ostane vremene dodacemo da unesemo file jer nzm kako bih ga cuvao
# tu on bira da li ce autentikaciju samo ili samo tajnost ili oba i bira koje algoritme
# ce da koristi. Tu bi mogao da napravim filter za tabelu kada izabere opcije. Onda
# napravimo poruku i sacuvamo je samo bleji nzm kako bih poslao poruku samom sebi (pisem
# ovo u 6am nemoj da me drkas). Elem to su 2/3 posla sad samo uradimo bukvalno inverziju
# svega ovoga i kada lik unese kljuceve program u pozadini desifruje i u textbox mu
# ispisemo plaintext. E msm da je toto idem da spavam a ovo tebi saljem da gledas dok
# ne budem bio tu oko 9 uvece cu ti se pridruziti i peglacu jos jednu celu noc. Trebalo
# bi da zavrsimo rok je do 3 u ponedeljak voleo bih do 2 da zavrsimo xD. Sacu da ti
# komentarisem ceo kod da se ne cimas kakva su ovo spanska sela.
#Ozbiljno cim vidis ovo kreni da radis jer smo malo knap mozemo braniti u avgustu iskreno ne zelim mrzi me da mi jos
#jedan dan u avgustu crkne. Cimaj me u toku dana da ti pomazem koliko mogu