import random

global prime,gen
global private_key

# generate public key pair once p,g varibles are received
def genKey(p,g):
    global private_key
    global prime,gen
    pk = random.randrange(3, p)
    y = pow(g, pk, p)
    private_key = pk
    prime = p
    gen = g
    return y

def pk():
    return private_key
def decrypt(a):
    global private_key

    # returns a^-x
    return pow(a, -abs(private_key), prime)
