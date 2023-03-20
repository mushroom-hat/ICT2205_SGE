import hashlib
import random
import candidate1, candidate2, candidate3
from Crypto.PublicKey import ECC
from fastecdsa.curve import P256
from fastecdsa.point import Point
import json
import mysql.connector


# steps to decrypt
# 1) during vote tallying process, voting authority will request each candidate to decrypt the combined ciphertexts A,B,C
# 2) Before decryption, voting authority should check if commitment of public key is correct
# 3) schnorr's protocol is used to check if candidate knows the original private key

# curve = ECC.generate(curve='P-256')
# G = curve.pointQ

def savePG(p,g):
    parameters_json = {
    "p": p,
    "g": g
    }
    with open('parameters.json', 'w') as fp:
        json.dump(parameters_json, fp)

    fp.close()

def getGeneratorValue():
    f = open('parameters.json')
    data = json.load(f)
    return data["g"]

def getPrimeValue():
    f = open('parameters.json')
    data = json.load(f)
    return data["p"]



x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
G = Point(x, y, curve=P256)

# function to add all ciphertexts in DB

def sqlConnect():
    # Creating connection object
    ct1 = 909458317,997369242
    ct2 = 909458317,997369242
    ct3 = 909458317,997369242

    try:
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="P@ssw0rd123",
            database = "pythonlogin"

        )
        print("MySQL Database connection successful")
        cursor = mydb.cursor()
        cursor.execute("SELECT * from accounts;")
        for account in cursor:
            ciphertext1 = int(account[4].split(",")[0]),int(account[4].split(",")[1])
            ciphertext2 = int(account[5].split(",")[0]),int(account[5].split(",")[1])
            ciphertext3 = int(account[6].split(",")[0]),int(account[6].split(",")[1])
            res = additive(ct1, ciphertext1)
            ct1 = res
            res2 = additive(ct2, ciphertext2)
            ct2 = res2
            res3 = additive(ct3, ciphertext3)
            ct3 = res3

        return ct1, ct2, ct3

    except Exception as e:
        print(e)


def main():
    ct1, ct2, ct3 = sqlConnect()

    # ct1 = 11621525,125256832
    # ct2 = 3365497144,845845285
    # ct3 = 909458317,997369242
    can1_hash, can2_hash, can3_hash = getHash()


    # add shnorrs protocol here, allows Candidates to prove that they know value x

    # add shnorrs protocol here, allows Candidates to prove that they know value x
    pub_key, A = candidate1.generateA(G)
    mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()
    c = generate_challenge()

    # hash verification, ensure that the public key commitment is correct
    if [mx, my] == can1_hash:
        print("Hash verification of Shnorr public key for Candidate 1 is correct")
        m = candidate1.accept_challenge(c)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(c, G, pub_key, signature):
            res1 = candidate1.decrypt(ct1[0])
            res2 = candidate2.decrypt(ct1[0])
            res3 = candidate3.decrypt(ct1[0])

            votes = decrypt(ct1[1], res1 * res2 * res3)
            print("Candidate 1 Total Votes: " + str(votes))
            # decrypt(res[0], res[1], pk1 + pk2 + pk3)

    # add shnorrs protocol here, allows Candidates to prove that they know value x
    pub_key, A = candidate2.generateA(G)
    mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()

    # hash verification, ensure that the public key commitment is correct
    if [mx, my] == can2_hash:
        print("Hash verification of Shnorr public key for Candidate 2 is correct")
        m = candidate2.accept_challenge(c)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(c, G, pub_key, signature):
            res1 = candidate1.decrypt(ct2[0])
            res2 = candidate2.decrypt(ct2[0])
            res3 = candidate3.decrypt(ct2[0])

            votes = decrypt(ct2[1], res1 * res2 * res3)
            print("Candidate 2 Total Votes: " + str(votes))

    # add shnorrs protocol here, allows Candidates to prove that they know value x
    pub_key, A = candidate3.generateA(G)
    mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()

    # hash verification, ensure that the public key commitment is correct
    if [mx, my] == can3_hash:
        print("Hash verification of Shnorr public key for Candidate 3 is correct")
        m = candidate3.accept_challenge(c)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(c, G, pub_key, signature):
            res1 = candidate1.decrypt(ct3[0])
            res2 = candidate2.decrypt(ct3[0])
            res3 = candidate3.decrypt(ct3[0])

            votes = decrypt(ct3[1], res1 * res2 * res3)
            print("Candidate 3 Total Votes: " + str(votes))


# get hash for candidate's public key to check against commitment, for schnorr verification protocol later
def getHash():
    hash1x, hash1y = candidate1.getEllipticParameters(G)
    hash2x, hash2y = candidate2.getEllipticParameters(G)
    hash3x, hash3y = candidate3.getEllipticParameters(G)
    return [hash1x, hash1y], [hash2x, hash2y], [hash3x, hash3y]


# accepts value A from Prover/Candidate (Schnorr)
# generate challenge for schnorr
def generate_challenge():
    challenge = random.randint(0, 115792089210356248762697446949407573529996955224135760342422259061068512044369)  # 80 is the bit length of the challenge c
    return challenge

# Signature verification
def schnorr_verify(challenge,generator_point,pub_key, signature):
    A, m = signature
    # A + c*p = r*G + c*(G*x) = G(r+cx) = G * m
    lhs = A + (challenge * pub_key)
    rhs = m * generator_point
    # print(lhs)
    # print(rhs)
    return lhs == rhs

# get each candidate to decrypt their own ciphertexts, e.g., candidate 1 will decrypt a,b, 2 will decrypt a2, b2
def candidateDecrypt(ciphertext, candidateNo):
    '''
    Each candidate will calculate the value of a^-x, where x is their own private key. This way, there is no need to reveal their private keys.
    After calculation, each value of a^-x can be combined to a^-(x1+x2+x3). This value will be used in the final decryption of the ciphertext
    '''
    a, b = ciphertext
    c = generate_challenge()
    if verifySchnorr(c, candidateNo):
        res1 = candidate1.decrypt(a)
        res2 = candidate2.decrypt(a)
        res3 = candidate3.decrypt(a)

        votes = decrypt(b, res1 * res2 * res3)
        print("Candidate" + candidateNo + " Total Votes: " + str(votes))


# function to determine that candidates knows the value of their private key
def verifySchnorr(challenge, candidateNo):
    if candidateNo == 1:
        pub_key, A = candidate1.generateA()
        m = candidate1.accept_challenge(challenge)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(challenge, G, pub_key, signature):
            return True


    if candidateNo == 2:
        pub_key, A = candidate2.generateA()
        m = candidate2.accept_challenge(challenge)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(challenge, G, pub_key, signature):
            return True

    if candidateNo == 3:
        pub_key, A = candidate3.generateA()
        m = candidate3.accept_challenge(challenge)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(challenge, G, pub_key, signature):
            return True


# function to determine that candidates uses the correct public key
def verifyCommitment(candidateNo):
    # get commitment values of public key for each candidate
    can1_hash, can2_hash, can3_hash = getHash()
    if candidateNo == 1:
        pub_key, A = candidate1.generateA()
        mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
        my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()

        # hash verification, ensure that the public key commitment is correct
        if [mx, my] == can1_hash:
            print("Hash verification of Shnorr public key for Candidate 1 is correct")
            return True

    elif candidateNo == 2:
        pub_key, A = candidate2.generateA()
        mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
        my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()

        # hash verification, ensure that the public key commitment is correct
        if [mx, my] == can2_hash:
            print("Hash verification of Shnorr public key for Candidate 2 is correct")
            return True

    else:
        pub_key, A = candidate3.generateA()
        mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
        my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()

        # hash verification, ensure that the public key commitment is correct
        if [mx, my] == can3_hash:
            print("Hash verification of Shnorr public key for Candidate 3 is correct")
            return True

# add both encrypted ciphertext together
def additive(ct1, ct2):
    a1, b1 = ct1
    a2, b2 = ct2
    a = (a1 * a2) % getPrimeValue()
    b = (b1 * b2) % getPrimeValue()
    #print(f"\nEncrypted (v1)\na={a1}\nb={b1}")
    #print(f"\nEncrypted (v2)\na={a2}\nb={b2}")
    #print(f"\nAfter homomorphic encryption\na={a}\nb={b}")
    return a, b  # returns added ciphertexts


#  decrypt after voting process ends, for tallying votes
#  decrypts each column for now only (a,b) in [(a,b), (a1,b1), (a2,b2)]
def decrypt(b,combined_res):
    # will have to request all 3 candidate's a^-x, then multiply them together
    # original v_r = (b * libnum.invmod(pow(a, combined_pk, p), p)) % p
    #v_r = (b * libnum.invmod(combined_res % p, p)) % p
    v_r = (b * (combined_res % getPrimeValue())) % getPrimeValue()  # combined_res = a^-x1 * a^-x2 * a^-x3 = a^-(x1+x2+x3)

    print("\nResult: ", v_r)

    # Now search for g^i
    for i in range(0, 2 ** 64):
        if (pow(getGeneratorValue(), i, getPrimeValue()) == v_r):
            return i


if __name__ == "__main__":
    main()