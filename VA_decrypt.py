import hashlib
import random
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
# Generator Point used for schnorr's verification https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
G = Point(x, y, curve=P256)

def getGeneratorValue():
    f = open('parameters.json')
    data = json.load(f)
    return data["g"]

def getPrimeValue():
    f = open('parameters.json')
    data = json.load(f)
    return data["p"]

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



def sqlConnect():
    # Creating connection object

    ct1 = 0
    ct2 = 0
    ct3 = 0
    try:
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="P@ssw0rd123",
            database = "pythonlogin"

        )
        print("MySQL Database connection successful")
        cursor = mydb.cursor()
        cursor.execute("SELECT * from accounts WHERE id=1;")
        for account in cursor:
            ct1 = int(account[3].split(",")[0]),int(account[3].split(",")[1])
            ct2 = int(account[4].split(",")[0]),int(account[4].split(",")[1])
            ct3 = int(account[5].split(",")[0]),int(account[5].split(",")[1])

        cursor.execute("SELECT * from accounts EXCEPT SELECT * from accounts WHERE id=1;")

        for account in cursor:
            ciphertext1 = int(account[3].split(",")[0]),int(account[3].split(",")[1])
            ciphertext2 = int(account[4].split(",")[0]),int(account[4].split(",")[1])
            ciphertext3 = int(account[5].split(",")[0]),int(account[5].split(",")[1])
            res = additive(ct1, ciphertext1)
            ct1 = res
            res2 = additive(ct2, ciphertext2)
            ct2 = res2
            res3 = additive(ct3, ciphertext3)
            ct3 = res3

        return ct1, ct2, ct3

    except Exception as e:
        print(e)

# accepts value A from Prover/Candidate (Schnorr)
# generate challenge for schnorr
def generate_challenge():
    challenge = random.randint(0, 115792089210356248762697446949407573529996955224135760342422259061068512044369)  # 80 is the bit length of the challenge c
    return challenge

# function to determine that candidates knows the value of their private key
def verifySchnorr(pub_key, A, challenge, response, candidateNo):
    if candidateNo == 1:
        signature = A, response
        if schnorr_final_step(challenge, G, pub_key, signature):
            return True


    if candidateNo == 2:
        signature = A, response
        if schnorr_final_step(challenge, G, pub_key, signature):
            return True

    if candidateNo == 3:
        signature = A, response
        if schnorr_final_step(challenge, G, pub_key, signature):
            return True


# Signature verification
def schnorr_final_step(challenge,generator_point,pub_key, signature):
    A, m = signature

    # A + c*p = r*G + c*(G*x) = G(r+cx) = G * m
    lhs = (challenge * pub_key) + m * generator_point
    print(lhs)
    rhs = A
    # print(lhs)
    # print(rhs)
    return lhs == rhs

# function to determine that candidates uses the correct public key
def verifyCommitment(candidateNo, pub_key, hash):

    mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()
    # hash verification, ensure that the public key commitment is correct
    if [mx, my] == hash:
        return True


def main():

    # Prover (Candidate) will generate the value A and send to Verifier
    # at this stage, the verifier will also receive the commitment hash of the prover's public key. This public key will be used later on for schnorr's verification

    print("[+] Vote Tallying process will now begin")
    print("[-] =====================================================================")


    print("[-] =====================================================================")
    print("[+] Commencing Verification of Schnorr's Protocol")
    print("[+] Retrieve public key and A from each candidate")
    print("[+] Input Candidate 1's public key & A value")
    pub1 = input("Public Key: ")
    cox1 = int(pub1.split(" ")[0])
    coy1 = int(pub1.split(" ")[1])
    public_key1 = Point(cox1, coy1, curve=P256)

    A1 = input("A: ")
    tmp1 = int(A1.split(" ")[0])
    tmp2 = int(A1.split(" ")[1])
    A1 = Point(tmp1, tmp2, curve=P256)

    print("[+] Input Candidate 2's public key & A value")
    pub2 = input("Public Key: ")
    cox2 = int(pub2.split(" ")[0])
    coy2 = int(pub2.split(" ")[1])
    public_key2 = Point(cox2, coy2, curve=P256)

    A2 = input("A: ")
    tmp1 = int(A2.split(" ")[0])
    tmp2 = int(A2.split(" ")[1])
    A2 = Point(tmp1, tmp2, curve=P256)


    print("[+] Input Candidate 3's public key & A value")
    pub3 = input("Public Key: ")
    cox3 = int(pub3.split(" ")[0])
    coy3 = int(pub3.split(" ")[1])
    public_key3 = Point(cox3, coy3, curve=P256)

    A3 = input("A: ")
    tmp1 = int(A3.split(" ")[0])
    tmp2 = int(A3.split(" ")[1])
    A3 = Point(tmp1, tmp2, curve=P256)


    with open('hash_commitments.txt', 'r') as f:
        lines = f.readlines()
        tmp = lines[0].split(" ")
        mx1, my1 = tmp[0], tmp[1]

        tmp = lines[1].split(" ")
        mx2, my2 = tmp[0], tmp[1]

        tmp = lines[2].split(" ")
        mx3, my3 = tmp[0], tmp[1]


    s1 = 0
    s2 = 0
    s3 = 0
    print("[+] Voting Authority will now verify public key used for Schnorr")
    print("=====================================================================")
    if verifyCommitment(1, public_key1, [mx1, my1]):
        s1 = True
        print("Hash verification of Shnorr public key for Candidate 1 is correct")

        if verifyCommitment(2, public_key2, [mx2, my2]):
            s2 = True
            print("Hash verification of Shnorr public key for Candidate 2 is correct")

            if verifyCommitment(3, public_key3, [mx3, my3]):
                s3 = True
                print("Hash verification of Shnorr public key for Candidate 3 is correct")

    print("=====================================================================")
    print("[+] Voting Authority will verify knowledge private key using Schnorr's protocol")
    print("[+] Send Challenge value (C) to candidates")
    challenge = generate_challenge()
    print("[+] C: {}".format(challenge))
    print("=====================================================================")
    print("[+] Candidates will now return the response to the challenge")
    print("[+] Input Candidate 1's response")

    m1 = input()
    print("[+] Input Candidate 2's response")

    m2 = input()

    print("[+] Input Candidate 3's response")
    m3 = input()
    print("=====================================================================")

    schn1 = False
    schn2 = False
    schn3 = False

    if verifySchnorr(public_key1, A1, challenge, int(m1), 1):
        schn1 = True
        print("[+] [+] Schnorr verification for Candidate 1 is successful")

    if verifySchnorr(public_key2, A2, challenge, int(m2), 2):
        schn2 = True
        print("[+] [+] Schnorr verification for Candidate 2 is successful")

    if verifySchnorr(public_key3, A3, challenge, int(m3), 3):
        schn3 = True
        print("[+] [+] Schnorr verification for Candidate 3 is successful")

    if schn1 and schn2 and schn3:
        print("=====================================================================")
        print("[+] Retrieving encrypted votes from DB...")
        ct1, ct2, ct3 = sqlConnect()

        print("Requesting Candidate 1 to decrypt ciphertexts now")
        print("Requesting Candidate 2 to decrypt ciphertexts now")
        print("Requesting Candidate 3 to decrypt ciphertexts now")

        print("Ciphertexts to decrypt:")
        print("=====================================================================")
        print("Requesting all candidates to decrypt Ciphertext 1: {}".format(ct1[0]))
        res1 = int(input("Input Candidate 1's decrypted value: "))
        res2 = int(input("Input Candidate 2's decrypted value: "))
        res3 = int(input("Input Candidate 3's decrypted value: "))
        print("Proceeding to decrypt Candidate 1's votes:")
        votes1 = decrypt(ct1[1], res1 * res2 * res3)
        if votes1:
            print("Decryption Success".format(ct2[0]))
            print("Requesting all candidates to decrypt Ciphertext 2: {}".format(ct2[0]))
            res1 = int(input("Input Candidate 1's decrypted value: "))
            res2 = int(input("Input Candidate 2's decrypted value: "))
            res3 = int(input("Input Candidate 3's decrypted value: "))
            print("Proceeding to decrypt Candidate 2's votes:")
            votes2 = decrypt(ct2[1], res1 * res2 * res3)
            if votes2:
                print("Decryption Success".format(ct2[0]))
                print("Requesting all candidates to decrypt Ciphertext 3: {}".format(ct3[0]))
                res1 = int(input("Input Candidate 1's decrypted value: "))
                res2 = int(input("Input Candidate 2's decrypted value: "))
                res3 = int(input("Input Candidate 3's decrypted value: "))
                print("Proceeding to decrypt Candidate 3's votes:")
                votes3 = decrypt(ct3[1], res1 * res2 * res3)
                if votes3:
                    print("All votes decrypted.")
                    print("Candidate 1" + " Total Votes: " + str(votes1))
                    print("Candidate 2" + " Total Votes: " + str(votes2))
                    print("Candidate 3" + " Total Votes: " + str(votes3))
                    print("=====================================================================")



if __name__ == "__main__":
    main()