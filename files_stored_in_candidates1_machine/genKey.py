import argparse
import base64
import hashlib
import random
from Crypto.Hash import SHA256
from Crypto.Random import random
import json
import psutil
global gen
global r, public_key
from fastecdsa.curve import P256
from fastecdsa.point import Point
# Generator point for elliptic curve P-256 and order n
# G = (x, y) = (
#   48439561293906451759052585252797914202762949526041747995844080717082404635286,
#   36134250956749795798585127919587881956611106672985015071877198253568414405109
# )

global challenge

# generate public key pair once p,g variables are received
def genKey(p,g):
    global prime, gen
    private_key = random.randrange(3, p)
    y = pow(g, private_key, p)  # elgamal public key
    prime = p
    gen = g

    # if both keys can be stored
    if storePrivateKey(private_key) and storePublicKey(y):
        print("Public Key: " + str(y))
        return y, private_key

def savePG(p,g):
    parameters_json = {
    "p": p,
    "g": g
    }
    with open('parameters.json', 'w') as fp:
        json.dump(parameters_json, fp)

    fp.close()
    return True

def storePublicKey(public_key):
    # Save the PEM data to a file
    with open("can1_public_key.txt", "w") as f:
        f.write(str(public_key))
    f.close()
    return True


# def storePrivateKey(private_key):
#     # Serialize the private key to PEM format
#     # Save the PEM data to a file
#     with open("../\\files_stored_in_candidates1_encrypted_USB\\can1_private_key.txt", "w") as f:
#         f.write(str(private_key))
#     f.close()
#     return True

def storePrivateKey(private_key):
    # Serialize the private key to PEM format
    def create_privatekey_file(drive_path):
    # Save the PEM data to a file
        with open(drive_path + "can1_private_key.txt", "w") as f:
            f.write(str(private_key))

    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            drive_path = partition.mountpoint
            create_privatekey_file(drive_path)
            return True

def getEllipticParameters(x,y, private_key):
    global public_key

    G = Point(x,y,curve=P256)
    with open("can1_ECC_PG.txt", "w") as f:
        f.write(str(x) + " " + str(y))
    public_key = G * int(private_key)  # generate pub key for Schnorr
    mx = hashlib.sha256(str(int(public_key.x)).encode("utf-8")).hexdigest()
    my = hashlib.sha256(str(int(public_key.y)).encode("utf-8")).hexdigest()
    return mx,my


def main():
    # Handling arguments with argparser
    parser = argparse.ArgumentParser(prog='Elgamal Key Generation for Candidates',
                                   )

    # Error checking for arguments
    parser.add_argument("-p", "--prime", help="Prime Value (P) provided by Voting Authority", required=True)
    parser.add_argument("-g", "--generator", help="Generator Value (G) provided by Voting Authority", required=True)
    args = parser.parse_args()
    public_key, private_key = genKey(int(args.prime), int(args.generator))
    if public_key:  # if successful key storage
        print("[+] Elgamal Keypair generated and stored")
        if savePG(args.prime, args.generator):
            print("[+] Please submit your public key to Voting Authority")

    G = input("Enter generator point provided by Voting Authority: ")
    x = int(G.split(" ")[0])
    y = int(G.split(" ")[1])

    mx, my = getEllipticParameters(x, y, private_key)
    print("[+] Return these values to Voting Authority")
    print("[+] mx my: {} {}".format(mx, my))
    print("[-] =====================================================================")

if __name__ == "__main__":
    main()