import hashlib
import random
import candidate1, candidate2, candidate3
from Crypto.PublicKey import ECC

# steps to decrypt
# 1) during vote tallying process, voting authority will request each candidate to decrypt the combined ciphertexts A,B,C
# 2) Before decryption, voting authority should check if commitment of public key is correct
# 3) schnorr's protocol is used to check if candidate knows the original private key

curve = ECC.generate(curve='P-256')
G = curve.pointQ
p = 9644018395590835246183437442456263590896403546363358699905042038620885780657221648055258927067788554399199796840639326339802578418381426706447733722073103
g = 1769090854204954238944926379910150389013448441043932449510969393563753205788409944536747839020624254542150273176634833274246404714421960841027254020874956


# placeholder ciphertexts
total_ct1 = [0,0]
total_ct2 = [0,0]
total_ct3 = [1,0]

# function to add all ciphertexts in DB

def main():
    with open('combined_public_key.txt') as f:
        lines = f.readlines()
    combined_public_key = int(lines[0])

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