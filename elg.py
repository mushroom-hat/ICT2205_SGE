from Crypto.Util.number import *
from Crypto import Random
import Crypto
import random
import libnum
import sys
import hashlib


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
v1 = 1
v2 = 0
v3 = 0

# generating global p and q
p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
g = get_generator(p)

# simulating three candidates, each having their own pub-key pair
def candidate1():
    private_key = random.randrange(3, p)
    y = pow(g, private_key, p)
    return y, private_key

def candidate2():
    private_key = random.randrange(3, p)
    y = pow(g, private_key, p)
    return y, private_key

def candidate3():
    private_key = random.randrange(3, p)
    y = pow(g, private_key, p)
    return y, private_key

# combining all 3 candidates' private keys for decryption at the end of the voting phase
def combined_private_key(keys):
    pk = 0
    for k in keys:
        pk += k
    return pk


def main():
    y1, pk1 = candidate1()
    y2, pk2 = candidate2()
    y3, pk3 = candidate3()
    combined_pk = combined_private_key([pk1, pk2, pk3])
    #combined_public_key = pow(g,combined_pk,p)
    combined_public_key = y1 * y2 * y3
    
    print(f"Combined Public key:\ng={g}\nY={combined_public_key}\np={p}\n\nCombined Private key\nx={combined_pk}")

    # simulating voting phase here
    ct1 = encrypt(combined_public_key, v1)
    ct2 = encrypt(combined_public_key, v2)
    ct3 = encrypt(combined_public_key, v3)

    res = additive(ct1, ct2)
    res = additive(res, ct3)

    decrypt(res[0], res[1], combined_pk)


def encrypt(combined_public_key, pt):
    r = random.randrange(3, p)
    a1 = pow(g, r, p)
    b1 = (pow(combined_public_key, r, p) * pow(g, pt, p)) % p

    return a1, b1

#  add both encrypted ciphertext together
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
def decrypt(a,b,combined_pk):
    v_r = (b * libnum.invmod(pow(a, combined_pk, p), p)) % p

    print("\nResult: ", v_r)

    # Now search for g^i
    for i in range(0, 2 ** 64):
        if (pow(g, i, p) == v_r):
            print("Found: ", i)
            break


if __name__ == "__main__":
    main()