from Crypto.Util.number import *
from Crypto import Random
import Crypto
import random
import libnum
import sys
import hashlib
import candidate1, candidate2, candidate3

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
v1 = 11
v2 = 1
v3 = 5

# generating global p and q
p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
g = get_generator(p)

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

def main():
    combined_public_key = initialise_candidates()
    #combined_pk = combined_private_key([pk1, pk2, pk3])
    #combined_public_key = pow(g,combined_pk,p)
    print(f"Combined Public key:\ng={g}\nY={combined_public_key}\np={p}\n\n")


    # simulating voting phase here
    ct1 = encrypt(combined_public_key, v1)
    ct2 = encrypt(combined_public_key, v2)
    ct3 = encrypt(combined_public_key, v3)

    res = additive(ct1, ct2)
    res = additive(res, ct3)
    a,b = res
    # add shnorrs protocol here
    res1 = candidate1.decrypt(a)
    res2 = candidate2.decrypt(a)
    res3 = candidate3.decrypt(a)

    decrypt(res[1], res1 * res2 * res3)
    #decrypt(res[0], res[1], pk1 + pk2 + pk3)


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
    print(f"\nEncrypted (v1)\na={a1}\nb={b1}")
    print(f"\nEncrypted (v2)\na={a2}\nb={b2}")
    print(f"\nAfter homomorphic encryption\na={a}\nb={b}")
    return (a,b) # returns added ciphertexts

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
            print("Found: ", i)
            break


if __name__ == "__main__":
    main()