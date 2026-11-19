"""
Layer 3 + payload layer of the PQ auction OT (reference / test harness).

1-of-N from l = ceil(log2 N) random 1-of-2 OTs (Naor-Pinkas style, random-oracle model):
  sender has ROT pairs (k_i^0, k_i^1), receiver has (r_i, k_i^{r_i})
  receiver sends d_i = c_i XOR r_i  (uniform -> hides c_i)
  sender re-labels K_i^b = pair_i[b XOR d_i]  -> receiver now holds K_i^{c_i}
  key_x = KDF(session, query, N, x, K_1^{x_1} || ... || K_l^{x_l})
  C_x   = AEAD(key_x, M_x, aad = session|query|N|x)
Receiver can only compute key_c.

!! SimROT is TEST ONLY (a trusted dealer). Replace it with the SoftSpokenOT adapter
!! (same interface: get(l) -> sender_pairs, recv_bits, recv_keys). Never reuse a ROT.

pip install cryptography
"""
import os, struct, math
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def lp(*parts: bytes) -> bytes:
    """length-prefixed (unambiguous) encoding"""
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


class SimROT:  # TEST ONLY
    def get(self, l):
        pairs = [(os.urandom(16), os.urandom(16)) for _ in range(l)]
        r = [os.urandom(1)[0] & 1 for _ in range(l)]
        keys = [pairs[i][r[i]] for i in range(l)]
        return pairs, r, keys


def bits(x, l):
    return [(x >> (l - 1 - i)) & 1 for i in range(l)]  # MSB first


def derive_key(session, query, N, x, keys):
    return HKDF(hashes.SHA256(), 32, salt=None,
                info=lp(b"pq-auction-ot-v1", session, query, struct.pack(">I", N),
                        struct.pack(">I", x), *keys)).derive(b"")


def aad(session, query, N, x):
    return lp(session, query, struct.pack(">I", N), struct.pack(">I", x))


class Sender:
    def __init__(self, session, query, payloads, rot_pairs):
        self.s, self.q, self.P, self.N = session, query, payloads, len(payloads)
        self.l = max(1, math.ceil(math.log2(self.N)))
        self.pairs = rot_pairs
        assert len(rot_pairs) == self.l

    def respond(self, d):
        """d = receiver's derandomisation bits. Returns list of N ciphertexts."""
        if len(d) != self.l or any(b not in (0, 1) for b in d):
            raise ValueError("bad message")
        out = []
        for x in range(self.N):
            xb = bits(x, self.l)
            ks = [self.pairs[i][xb[i] ^ d[i]] for i in range(self.l)]
            k = derive_key(self.s, self.q, self.N, x, ks)
            nonce = os.urandom(12)
            out.append(nonce + AESGCM(k).encrypt(nonce, self.P[x], aad(self.s, self.q, self.N, x)))
        return out


class Receiver:
    def __init__(self, session, query, N, c, r, keys):
        if not (0 <= c < N):
            raise ValueError("index out of range")
        self.s, self.q, self.N, self.c = session, query, N, c
        self.l = max(1, math.ceil(math.log2(N)))
        self.r, self.keys = r, keys

    def request(self):
        cb = bits(self.c, self.l)
        return [cb[i] ^ self.r[i] for i in range(self.l)]

    def finish(self, cts, x=None):
        x = self.c if x is None else x  # x != c only used in tests
        k = derive_key(self.s, self.q, self.N, x, self.keys)
        ct = cts[x]
        return AESGCM(k).decrypt(ct[:12], ct[12:], aad(self.s, self.q, self.N, x))


def run(N, c, session=b"auction-1", query=None):
    query = query or os.urandom(8)
    payloads = [f"payload-{i}".encode() for i in range(N)]
    l = max(1, math.ceil(math.log2(N)))
    pairs, r, keys = SimROT().get(l)
    S, R = Sender(session, query, payloads, pairs), Receiver(session, query, N, c, r, keys)
    cts = S.respond(R.request())
    return R, cts, payloads


if __name__ == "__main__":
    for N in [2, 3, 4, 7, 8, 16, 32, 33]:
        for c in range(N):
            R, cts, P = run(N, c)
            assert R.finish(cts) == P[c]
            for x in range(N):  # unselected payloads must NOT decrypt
                if x != c:
                    try:
                        R.finish(cts, x); raise SystemExit(f"LEAK N={N} c={c} x={x}")
                    except InvalidTag:
                        pass
        for bad in (-1, N):
            try:
                run(N, bad); raise SystemExit("accepted invalid index")
            except ValueError:
                pass
    print("all tests passed")
