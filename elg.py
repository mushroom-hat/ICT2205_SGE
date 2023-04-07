from Crypto.Util.number import *
from Crypto import Random
import Crypto
import random
from Crypto.Random import random
from Crypto.PublicKey import ECC
from fastecdsa.curve import P256
from fastecdsa.point import Point
import json

# Generator Point used for schnorr's verification https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
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


bits = 128

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
p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
g = get_generator(p)
# p = 171368984974755882030022627524358975769
# g = 75841540937739416858034135864788500320
# print(p,g)
# p= 63241
# g= 60213
# p = 9644018395590835246183437442456263590896403546363358699905042038620885780657221648055258927067788554399199796840639326339802578418381426706447733722073103
# g = 1769090854204954238944926379910150389013448441043932449510969393563753205788409944536747839020624254542150273176634833274246404714421960841027254020874956
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
    combined_public_key = can1_public_key * can2_public_key * can3_public_key

    parameters_json = {"combined_pub": combined_public_key,
    "p": p,
    "g": g
    }
    with open('parameters.json', 'w') as fp:
        json.dump(parameters_json, fp)

    return combined_public_key


def main():
    # initialise_Candidate requests candidates to set up a public-private key pair and returns their generated public key
    #combined_public_key = initialise_candidates()
    print("P: " + str(p))
    print("G: " + str(g))
    pk1 = int(input("Candidate 1 Public Key: "))
    pk2 = int(input("Candidate 2 Public Key: "))
    pk3 = int(input("Candidate 3 Public Key: "))

    combined_public_key = pk1 * pk2 * pk3

    print("Elgamal Prime and Generator Values sent to Candidates for generation of public-private key pair")
    print("Received Combined Public Key for Encryption of Votes: " + str(combined_public_key))
    with open("combined_public_key.txt", "w") as f:
        f.write(str(combined_public_key))

    #combined_pk = combined_private_key([pk1, pk2, pk3])
    #combined_public_key = pow(g,combined_pk,p)

    with open('combined_public_key.txt') as f:
        lines = f.readlines()
        combined_public_key = int(lines[0])
    print(f"Combined Public key:\ng={g}\nY={combined_public_key}\np={p}\n\n")

    parameters_json = {"combined_pub": combined_public_key,
                       "p": p,
                       "g": g
                       }
    with open('parameters.json', 'w') as fp:
        json.dump(parameters_json, fp)

    print("Generator Point: " + str(x) + " " + str(y))
    print("[+] Enter hash commitment by each candidate")
    print("[+] Input Candidate 1's hash commitment, delimited by space")
    candidate1_hash = input()
    mx1 = candidate1_hash.split(" ")[0]
    my1 = candidate1_hash.split(" ")[1]
    c1 = mx1 + " " + my1

    print("[+] Input Candidate 2's hash commitment, delimited by space")
    candidate2_hash = input()
    mx2 = candidate2_hash.split(" ")[0]
    my2 = candidate2_hash.split(" ")[1]
    c2 = mx2 + " " + my2

    print("[+] Input Candidate 3's hash commitment, delimited by space")
    candidate3_hash = input()
    mx3 = candidate3_hash.split(" ")[0]
    my3 = candidate3_hash.split(" ")[1]

    c3 = mx3 + " " + my3

    with open('hash_commitments.txt', 'w') as f:
        f.write(c1 + "\n")
        f.write(c2 + "\n")
        f.write(c3)


# function to determine that candidates knows the value of their private key

if __name__ == "__main__":
    main()