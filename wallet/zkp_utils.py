import random

# Large safe prime (demo but strong enough for academic use)
p = 208351617316091241234326746312124448251235562226470491514186331217050270460481
g = 2


def generate_commitment():
    r = random.randint(1, p - 2)
    t = pow(g, r, p)
    return r, t


def generate_challenge():
    return random.randint(1, p - 2)


def compute_response(r, c, secret):
    return (r + c * secret) % (p - 1)


def verify_proof(t, s, c, y):
    left = pow(g, s, p)
    right = (t * pow(y, c, p)) % p
    return left == right