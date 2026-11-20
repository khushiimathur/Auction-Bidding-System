"""
Shamir Secret Sharing over GF(p) -- core module (Steps 3-4).

Standalone: no dependency on the lattice commitment / OT / ZK parts.
Secrets are integers (or bytes of at most 32 bytes) smaller than PRIME.
"""

import secrets

# Largest prime below 2^256. Fits any 256-bit key (see generate_key()).
PRIME = 2**256 - 189


class ShamirError(Exception):
    pass


def generate_key(num_bytes: int = 32) -> bytes:
    """Random key that is guaranteed to be a valid secret (< PRIME)."""
    while True:
        k = secrets.token_bytes(num_bytes)
        if int.from_bytes(k, "big") < PRIME:
            return k


def _eval_poly(coeffs, x, p):
    """Horner's method. coeffs[0] is the constant term (the secret)."""
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % p
    return result


def split(secret: int, t: int, n: int, p: int = PRIME):
    """
    Split `secret` into n shares; any t of them reconstruct it.
    Returns a list of (x, y) pairs with x = 1..n.
    """
    if not (1 <= t <= n):
        raise ShamirError("need 1 <= t <= n")
    if n >= p:
        raise ShamirError("n must be smaller than the prime")
    if not (0 <= secret < p):
        raise ShamirError("secret must satisfy 0 <= secret < p")

    # f(x) = secret + a1*x + ... + a_{t-1}*x^{t-1}, coefficients from a CSPRNG
    coeffs = [secret] + [secrets.randbelow(p) for _ in range(t - 1)]
    return [(x, _eval_poly(coeffs, x, p)) for x in range(1, n + 1)]


def reconstruct(shares, p: int = PRIME) -> int:
    """
    Lagrange interpolation at x = 0:
        s = f(0) = sum_i y_i * L_i(0),  L_i(0) = prod_{j!=i} x_j / (x_j - x_i)

    NOTE: plain Shamir cannot tell whether fewer than t shares were given;
    it just returns a wrong value. The caller enforces the threshold
    (the committee protocol does this in Step 6).
    """
    if not shares:
        raise ShamirError("no shares given")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ShamirError("duplicate x values")
    if any(x % p == 0 for x in xs):
        raise ShamirError("x = 0 is not a valid share index")

    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * xj) % p
            den = (den * (xj - xi)) % p
        secret = (secret + yi * num * pow(den, -1, p)) % p
    return secret


# ---- bytes helpers ---------------------------------------------------------

def secret_to_int(secret: bytes) -> int:
    if len(secret) > 32:
        raise ShamirError("secret longer than 32 bytes; share a key instead")
    return int.from_bytes(secret, "big")


def int_to_secret(value: int, length: int = 32) -> bytes:
    return value.to_bytes(length, "big")


def split_bytes(secret: bytes, t: int, n: int):
    return split(secret_to_int(secret), t, n)


def reconstruct_bytes(shares, length: int = 32) -> bytes:
    return int_to_secret(reconstruct(shares), length)
