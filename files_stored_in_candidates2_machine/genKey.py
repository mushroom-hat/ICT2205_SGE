import argparse
import base64
import hashlib
import random
from Crypto.Hash import SHA256
from Crypto.Random import random
import json

global gen
global r, public_key

# Generator point for elliptic curve P-256 and order n
# G = (x, y) = (
#   48439561293906451759052585252797914202762949526041747995844080717082404635286,
#   36134250956749795798585127919587881956611106672985015071877198253568414405109
# )
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

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
        return y

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
    with open("can2_public_key.txt", "w") as f:
        f.write(str(public_key))
        return True


def storePrivateKey(private_key):
    # Serialize the private key to PEM format
    # Save the PEM data to a file
    with open("../\\files_stored_in_candidates2_encrypted_USB\\can2_private_key.txt", "w") as f:
        f.write(str(private_key))
        return True


def main():
    # Handling arguments with argparser
    parser = argparse.ArgumentParser(prog='Elgamal Key Generation for Candidates',
                                   )

    # Error checking for arguments
    parser.add_argument("-p", "--prime", help="Prime Value (P) provided by Voting Authority", required=True)
    parser.add_argument("-g", "--generator", help="Generator Value (G) provided by Voting Authority", required=True)
    args = parser.parse_args()
    public_key = genKey(int(args.prime), int(args.generator))
    if public_key:  # if successful key storage
        print("[+] Elgamal Keypair generated and stored")
        if savePG(args.prime, args.generator):
            print("[+] Please submit your public key to Voting Authority")


if __name__ == "__main__":
    main()