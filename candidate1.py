import base64
import hashlib
import random
from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


global prime, gen
global private_key
global r, public_key

# Generator point for elliptic curve P-256 and order n
# G = (x, y) = (
#   48439561293906451759052585252797914202762949526041747995844080717082404635286,
#   36134250956749795798585127919587881956611106672985015071877198253568414405109
# )
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

global challenge, G

# generate public key pair once p,g variables are received
def genKey(p,g):
    global private_key
    global prime, gen
    private_key = random.randrange(3, p)
    y = pow(g, private_key, p)  # elgamal public key
    prime = p
    gen = g
    storePrivateKey(private_key)
    storePublicKey(y)
    return y

def storePublicKey(public_key):
    # Save the PEM data to a file
    with open("can1_public_key.txt", "w") as f:
        f.write(str(public_key))


def storePrivateKey(private_key):
    # Serialize the private key to PEM format
    # Save the PEM data to a file
    with open("can1_private_key.txt", "w") as f:
        f.write(str(private_key))

def getPublicKey():
    with open('can1_public_key.txt') as f:
        lines = f.readlines()
    public_key = int(lines[0])
    return public_key

def getPrivateKey():
    with open('can1_private_key.txt') as f:
        lines = f.readlines()
    private_key = int(lines[0])
    return private_key


def getEllipticParameters(generator_pt):
    global G, public_key

    G = generator_pt

    public_key = G * getPrivateKey()  # generate pub key for Schnorr
    print(public_key)
    mx = hashlib.sha256(str(int(public_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(public_key.y)).encode("utf-8")).hexdigest()

    return mx,my

def decrypt(a):
    private_key = getPrivateKey()
    # returns a^-x
    return pow(a, -abs(private_key), prime)


def generateA():
    global challenge
    global r
    r = random.randint(1, n - 1)
    A = r * G  # Point A, sends it over
    return public_key, A


# accepts challenge c and returns message m
def accept_challenge(c):
    private_key = getPrivateKey()
    m = (r + (private_key * c)) % n  # sends it over
    return m
