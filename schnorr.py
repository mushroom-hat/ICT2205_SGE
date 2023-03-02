import hashlib

from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.PublicKey import ECC
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Here, with Schnorr, we want to prove that as the candidate, we know the value of private key (in this case, we use variable msg since x is taken)
# 1) Candidate generates a random value r
# 2) Candidate computes A using r and sends the value A over to Verifier
# 3) Verifier generates a random value (Challenge C) and sends it over to Candidate
# 4) Candidate calculates message m using m = r + c * x (mod n) and sends it over to Verifier again
# 5) Verifier now checks if m * g == A + (c * pub_key)

# Key generation
curve = ECC.generate(curve='P-256')
x = 5538340842186004418276602080015396902626037490735585464737484133293970374165074486911240944018974489198412599452489132279439794350632948256583324523856874
G = curve.pointQ
pub_key = G * x
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

global challenge

# Signature generation
def schnorr_sign(priv_key):
    global challenge
    r = random.randint(1, n - 1)
    A = r * G  # Point A, sends it over
    # calculate A = H(M || A) where || is concatenation
    challenge = random.randint(0, pow(2,80) - 1)  # 80 is the bit length of the challenge c
    m = (r + (priv_key * challenge)) % n  # sends it over
    return A, m

# Signature verification
def schnorr_verify(signature, pub_key):
    A, m = signature
    global challenge

    lhs = A + (challenge * pub_key)
    rhs = m * G
    print(lhs)
    print(rhs)
    return lhs == rhs

    #    return 1 <= m <= n - 1 and m * G == A + c * pub_key

# Example usage
message = 'Hello, world!'
signature = schnorr_sign(x)
print(f"Signature: {signature}")
valid = schnorr_verify(signature, pub_key)
print(f"Is valid: {valid}")
