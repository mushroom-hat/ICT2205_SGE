from Crypto.Util.number import *
from Crypto import Random
import Crypto
import random
import libnum
import sys
import hashlib
from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.PublicKey import ECC
from fastecdsa.curve import P256
from fastecdsa.point import Point

import candidate1, candidate2, candidate3

curve = ECC.generate(curve='P-256')
x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
G = Point(x, y, curve=P256)

#G = (48439561293906451759052585252797914202762949526041747995844080717082404635286,36134250956749795798585127919587881956611106672985015071877198253568414405109)
def get_generator(p: int):
    while True:
        # Find generator which doesn't share factor with p
        generator = random.randrange(3, p)
        if pow(generator, 2, p) == 1:
            continue
        if pow(generator, p, p) == 1:
            continue
        return generator


bits = 512

# each voter sends [x,y,z]
x1 = 1
y1 = 0
z1 = 0

x2 = 0
y2 = 0
z2 = 1

x3 = 0
y3 = 0
z3 = 1

# generating global p and q
#p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
#g = get_generator(p)
p = 9644018395590835246183437442456263590896403546363358699905042038620885780657221648055258927067788554399199796840639326339802578418381426706447733722073103
g = 1769090854204954238944926379910150389013448441043932449510969393563753205788409944536747839020624254542150273176634833274246404714421960841027254020874956
# # combining all 3 candidates' private keys for decryption at the end of the voting phase
# def combined_private_key(keys):
#     pk = 0
#     for k in keys:
#         pk += k
#     return pk


def initialise_candidates():
    # initialise candidate key generation, returns partial public key
    can1_public_key = candidate1.genKey(p,g)
    can2_public_key = candidate2.genKey(p,g)
    can3_public_key = candidate3.genKey(p,g)

    return can1_public_key * can2_public_key * can3_public_key

# get hash for candidate's public key, for schnorr verification protocol later
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


def main():
    combined_public_key = initialise_candidates()
    with open("combined_public_key.txt", "w") as f:
        f.write(str(combined_public_key))

    can1_hash, can2_hash, can3_hash = getHash()
    #combined_pk = combined_private_key([pk1, pk2, pk3])
    #combined_public_key = pow(g,combined_pk,p)

    with open('combined_public_key.txt') as f:
        lines = f.readlines()
    combined_public_key = int(lines[0])
    print(f"Combined Public key:\ng={g}\nY={combined_public_key}\np={p}\n\n")


    # simulating voting phase here
    ct1 = encrypt(combined_public_key, x1)
    ct2 = encrypt(combined_public_key, x2)
    ct3 = encrypt(combined_public_key, x3)

    res = additive(ct1, ct2)
    res = additive(res, ct3)
    a,b = res

    # simulating voting phase here
    ct1 = encrypt(combined_public_key, y1)
    ct2 = encrypt(combined_public_key, y2)
    ct3 = encrypt(combined_public_key, y3)

    res = additive(ct1, ct2)
    res = additive(res, ct3)
    a1,b1 = res


    # simulating voting phase here
    ct1 = encrypt(combined_public_key, z1)
    ct2 = encrypt(combined_public_key, z2)
    ct3 = encrypt(combined_public_key, z3)

    res = additive(ct1, ct2)
    res = additive(res, ct3)
    a2,b2 = res


    # add shnorrs protocol here, allows Candidates to prove that they know value x
    pub_key, A = candidate1.generateA()
    mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()
    c = generate_challenge()

    # hash verification, ensure that the public key commitment is correct
    if [mx, my] == can1_hash:
        print("Hash verification of Shnorr public key for Candidate 1 is correct")
        m = candidate1.accept_challenge(c)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(c, G, pub_key, signature):
            res1 = candidate1.decrypt(a)
            res2 = candidate2.decrypt(a)
            res3 = candidate3.decrypt(a)

            votes = decrypt(b, res1 * res2 * res3)
            print("Candidate 1 Total Votes: " + str(votes))
            #decrypt(res[0], res[1], pk1 + pk2 + pk3)

    # add shnorrs protocol here, allows Candidates to prove that they know value x
    pub_key, A = candidate2.generateA()
    mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()

    # hash verification, ensure that the public key commitment is correct
    if [mx, my] == can2_hash:
        print("Hash verification of Shnorr public key for Candidate 2 is correct")
        m = candidate2.accept_challenge(c)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(c, G, pub_key, signature):
            res1 = candidate1.decrypt(a1)
            res2 = candidate2.decrypt(a1)
            res3 = candidate3.decrypt(a1)

            votes = decrypt(b1, res1 * res2 * res3)
            print("Candidate 2 Total Votes: " + str(votes))

    # add shnorrs protocol here, allows Candidates to prove that they know value x
    pub_key, A = candidate3.generateA()
    mx = hashlib.sha256(str(int(pub_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(pub_key.y)).encode("utf-8")).hexdigest()

    # hash verification, ensure that the public key commitment is correct
    if [mx, my] == can3_hash:
        print("Hash verification of Shnorr public key for Candidate 3 is correct")
        m = candidate3.accept_challenge(c)  # candidate receives challenge and computes m
        signature = A, m
        if schnorr_verify(c, G, pub_key, signature):
            res1 = candidate1.decrypt(a2)
            res2 = candidate2.decrypt(a2)
            res3 = candidate3.decrypt(a2)

            votes = decrypt(b2, res1 * res2 * res3)
            print("Candidate 3 Total Votes: " + str(votes))

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

def encrypt(combined_public_key, pt):
    r = random.randrange(3, p)
    a1 = pow(g, r, p)
    b1 = (pow(combined_public_key, r, p) * pow(g, pt, p)) % p

    return a1, b1

# add both encrypted ciphertext together

def additive(ct1, ct2):
    a1, b1 = ct1
    a2, b2 = ct2
    a = (a1 * a2) % p
    b = (b1 * b2) % p
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
    v_r = (b * (combined_res % p)) % p  # combined_res = a^-x1 * a^-x2 * a^-x3 = a^-(x1+x2+x3)

    print("\nResult: ", v_r)

    # Now search for g^i
    for i in range(0, 2 ** 64):
        if (pow(g, i, p) == v_r):
            return i


if __name__ == "__main__":
    main()