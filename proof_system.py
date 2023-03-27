import random
from Crypto.Util import number


def mod_exp(base, exp, mod):
    return pow(base, exp, mod)


"""Change this p and g"""
# Generate fake keys and Elgamal encryption
p = number.getPrime(32)
g = 2

private_key = random.randint(2, p - 2)
print(f"Private Key: {private_key}")
public_key = mod_exp(g, private_key, p)
print(f"Public Key: {public_key}")

number_1 = 123
print(f"Selected Value: {number_1}")

"""The r value must be the same"""
r = random.randint(2, p - 2)

"""Put in your C1 and C2"""
C1 = mod_exp(g, r, p)
print(f"C1: {C1}")
C2 = mod_exp(public_key, r, p) if number_1 == 0 else (mod_exp(public_key, r, p) * number_1) % p
print(f"C2: {C2}")

s2 = random.randint(1, p - 1)
t2 = mod_exp(g, s2, p)

# Verifier
e = random.randint(1, p - 1)

define_number_set = 0
y2 = (s2 + e * (r * (1 - define_number_set))) % (p - 1)
v2 = (mod_exp(g, y2, p) * mod_exp(C1, -e, p)) % p

print(f"T2 and V2: {t2} \n {v2}")
if (t2 == v2):
    print("Zero-knowledge proof successful: number_1 is Zero.")
else:
    print("Zero-knowledge proof failed.")
