
import secrets
import random
import numpy as np
from dataclasses import dataclass


# --------------------------------------------------
# Public parameters
# --------------------------------------------------

@dataclass
class PublicParameters:
    A1: np.ndarray
    A2: np.ndarray
    q: int
    n: int
    m: int
    k: int
    sigma: float
    B: float


@dataclass
class Commitment:
    c: np.ndarray


@dataclass
class Opening:
    bid: int
    randomness: np.ndarray


# --------------------------------------------------
# Modular matrix rank
# Checks whether A has a trivial kernel over Zq.
# q must be prime for this implementation.
# --------------------------------------------------

def rank_mod_q(matrix, q):
    matrix = np.array(matrix, dtype=object) % q
    rows, cols = matrix.shape

    rank = 0

    for col in range(cols):
        pivot = None

        for row in range(rank, rows):
            if matrix[row, col] % q != 0:
                pivot = row
                break

        if pivot is None:
            continue

        matrix[[rank, pivot]] = matrix[[pivot, rank]]

        inverse = pow(int(matrix[rank, col]), -1, q)
        matrix[rank] = (matrix[rank] * inverse) % q

        for row in range(rows):
            if row != rank:
                factor = matrix[row, col]
                matrix[row] = (
                    matrix[row] - factor * matrix[rank]
                ) % q

        rank += 1

        if rank == rows:
            break

    return rank


# --------------------------------------------------
# GenCom: Generate public commitment parameters
# --------------------------------------------------

def setup(n=2, k=2, m=8, q=101,
          sigma=1.2, B=6.0):

    if rank_mod_q(np.eye(1, dtype=int), q) != 1:
        raise ValueError("Invalid modulus")

    while True:
        A1 = np.array([
            [secrets.randbelow(q) for _ in range(n)]
            for _ in range(m)
        ], dtype=object)

        A2 = np.array([
            [secrets.randbelow(q) for _ in range(k)]
            for _ in range(m)
        ], dtype=object)

        A = np.concatenate((A1, A2), axis=1)

        if rank_mod_q(A, q) == n + k:
            break

    return PublicParameters(
        A1=A1,
        A2=A2,
        q=q,
        n=n,
        m=m,
        k=k,
        sigma=sigma,
        B=B
    )


# --------------------------------------------------
# Sample randomness r uniformly from Zq^k
# --------------------------------------------------

def sample_randomness(k, q):
    return np.array([
        secrets.randbelow(q) for _ in range(k)
    ], dtype=object)


# --------------------------------------------------
# Sample an approximate discrete Gaussian error.
#
# IMPORTANT:
# Rounding a Gaussian sample is an approximation,
# not an exact implementation of D_sigma.
# --------------------------------------------------

def sample_error(m, sigma):
    secure_random = random.SystemRandom()

    return np.array([
        round(secure_random.gauss(0, sigma))
        for _ in range(m)
    ], dtype=object)


# --------------------------------------------------
# Com: Commit to a bid
#
# C = A1*v + A2*r + e mod q
# --------------------------------------------------

def commit(bid, pp):

    if not isinstance(bid, int) or bid < 0:
        raise ValueError("Bid must be a non-negative integer")

    if bid >= pp.q:
        raise ValueError("Bid must be smaller than q")

    # Encode bid as a vector in Zq^n.
    # Remaining coordinates are zero.
    v = np.zeros(pp.n, dtype=object)
    v[0] = bid

    # Random opening information
    r = sample_randomness(pp.k, pp.q)

    # Error vector
    e = sample_error(pp.m, pp.sigma)

    # Calculate commitment
    c = (
        pp.A1 @ v +
        pp.A2 @ r +
        e
    ) % pp.q

    commitment = Commitment(c=c)
    opening = Opening(
        bid=bid,
        randomness=r
    )

    return commitment, opening


# --------------------------------------------------
# Convert modular residues to centered integers.
# This is needed to calculate the Euclidean norm.
# --------------------------------------------------

def centered_residues(vector, q):

    return np.array([
        int(x) if int(x) <= q // 2
        else int(x) - q
        for x in vector
    ], dtype=object)


# --------------------------------------------------
# Unv: Verify the commitment opening
#
# e' = C - A1*v - A2*r mod q
#
# Accept if ||e'|| <= B
# --------------------------------------------------

def verify(commitment, bid, randomness, pp):

    if not isinstance(bid, int) or bid < 0 or bid >= pp.q:
        return False

    if len(randomness) != pp.k:
        return False

    v = np.zeros(pp.n, dtype=object)
    v[0] = bid

    residual = (
        commitment.c -
        pp.A1 @ v -
        pp.A2 @ randomness
    ) % pp.q

    residual = centered_residues(residual, pp.q)

    norm = np.sqrt(sum(int(x) ** 2 for x in residual))

    return norm <= pp.B
