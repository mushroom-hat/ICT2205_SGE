import argparse
import hashlib
import json
import os
import random
import time

import psutil
from fastecdsa.curve import P256
from fastecdsa.point import Point
# Generator Point used for schnorr's verification https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
G = Point(x, y, curve=P256)

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
global public_key
global challenge,r

def getGeneratorValue():
    f = open('parameters.json')
    data = json.load(f)
    return int(data["g"])

def getPrimeValue():
    f = open('parameters.json')
    data = json.load(f)
    return int(data["p"])


def getPublicKey():
    with open('can1_public_key.txt') as f:
        lines = f.readlines()
    pub = int(lines[0])
    return pub

# def getPrivateKey():
#     with open('../\\files_stored_in_candidates1_encrypted_USB\\can1_private_key.txt') as f:
#         lines = f.readlines()
#     private_key = int(lines[0])
#     return private_key


def decrypt(a):
    private_key = getPrivateKey()
    # returns a^-x
    return pow(a, -abs(private_key), getPrimeValue())


def generateA(G):
    global challenge
    global r
    r = random.randint(1, n - 1)
    A = r * G  # Point A, sends it over
    with open('can1_ECC_PG.txt', 'r') as f:
        lines = f.readlines()
        x = int(lines[0].split(" ")[0])
        y = int(lines[0].split(" ")[1])
    G = Point(x,y,curve=P256)
    public_key = G * getPrivateKey()
    return public_key, A


# accepts challenge c and returns message m
def accept_challenge(c):
    private_key = getPrivateKey()
    m = (r - (private_key * c)) % n  # sends it over
    return m


def getPrivateKey():
    while True:
        # Search for the external storage drive containing the private key file
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts:
                drive_path = partition.mountpoint
                key_file_path = os.path.join(drive_path, 'can1_private_key.txt')
                if os.path.isfile(key_file_path):
                    # Read the private key from the file
                    with open(key_file_path, 'r') as f:
                        lines = f.readlines()
                    private_key = int(lines[0])
                    return private_key
        time.sleep(5)


def main():
    # Handling arguments with argparser
    parser = argparse.ArgumentParser(prog='Elgamal Key Generation for Candidates',
                                   )

    print("[+] Vote Tallying process will now begin")
    print("[+] Generating value A...")
    pub_key, A = generateA(G)
    pub_key = str(int(pub_key.x)) + " " + str(int(pub_key.y))
    print("[+] Return these values to Voting Authority")
    print("[+] pub_key: {}".format(pub_key))
    A = str(int(A.x)) + " " + str(int(A.y))
    print("[+] A: {}".format(A))
    print("=====================================================================")
    print("[+] Voting Authority will now verify public key")
    print("[-] =====================================================================")
    print("[+] Commencing Verification of Schnorr's Protocol")
    print("[-] =====================================================================")
    print("[+] Input the value of Challenge (C) provided by Voting Authority")
    c = input()
    message = accept_challenge(int(c))
    print("=====================================================================")
    print("[+] Return these values to Voting Authority")
    print("[+] Message (M): {}".format(message))
    print("[+] Voting Authority will now verify.")
    print("=====================================================================")
    print("[+] Proceeding to Decryption")
    print("[+] Input the value of ciphertext provided by Voting Authority")
    print("=====================================================================")

    while True:
        a = int(input())
        if a == 0:
            break
        res = decrypt(a)
        print("[+] Return these values to Voting Authority")
        print("[+] Result: {}".format(res))
        print("=====================================================================")

    print("[+] Thank You. Please await results.")

if __name__ == "__main__":
    main()