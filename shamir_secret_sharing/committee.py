"""
Threshold opening via Shamir Secret Sharing -- scheme + committee simulation.

Follows the slides: n auctioneers, threshold t, f(x) = s + a1*x + ... + a_{t-1}*x^{t-1},
secret s = f(0), each committee member holds ONE share, any t shares open the secret.

No share verification yet (planned as a separate module).
"""

from dataclasses import dataclass
from typing import List, Optional

import shamir
from shamir import PRIME, ShamirError


@dataclass(frozen=True)
class Share:
    x: int   # committee member index, 1..n
    y: int   # f(x) mod p

    def as_tuple(self):
        return (self.x, self.y)


class ShamirScheme:
    """(t, n) threshold scheme. Enforces the threshold, which raw
    shamir.reconstruct() does not."""

    def __init__(self, t: int, n: int, p: int = PRIME):
        if not (1 <= t <= n):
            raise ShamirError("need 1 <= t <= n")
        self.t, self.n, self.p = t, n, p

    def deal(self, secret: int) -> List[Share]:
        return [Share(x, y) for x, y in shamir.split(secret, self.t, self.n, self.p)]

    def open(self, shares: List[Share]) -> int:
        if len(shares) < self.t:
            raise ShamirError(
                f"threshold not met: got {len(shares)} shares, need {self.t}")
        if any(not (1 <= s.x <= self.n) for s in shares):
            raise ShamirError("share index outside 1..n")
        return shamir.reconstruct([s.as_tuple() for s in shares], self.p)

    # bytes convenience (e.g. a 32-byte auction secret)
    def deal_bytes(self, secret: bytes) -> List[Share]:
        return self.deal(shamir.secret_to_int(secret))

    def open_bytes(self, shares: List[Share], length: int = 32) -> bytes:
        return shamir.int_to_secret(self.open(shares), length)


class Auctioneer:
    """One committee member. Holds exactly one share and nothing else."""

    def __init__(self, index: int):
        self.index = index
        self._share: Optional[Share] = None
        self.online = True

    def receive_share(self, share: Share):
        if share.x != self.index:
            raise ShamirError("share is not addressed to this auctioneer")
        self._share = share

    def release_share(self, bidding_closed: bool) -> Optional[Share]:
        """Shares are only released after the bidding deadline, and only if
        the node is online."""
        if not bidding_closed or not self.online or self._share is None:
            return None
        return self._share


class Committee:
    def __init__(self, t: int, n: int):
        self.scheme = ShamirScheme(t, n)
        self.nodes = [Auctioneer(i) for i in range(1, n + 1)]
        self.bidding_closed = False

    def deal(self, secret: int):
        """Dealer step: one share per auctioneer."""
        for node, share in zip(self.nodes, self.scheme.deal(secret)):
            node.receive_share(share)

    def close_bidding(self):
        self.bidding_closed = True

    def open(self) -> int:
        """Opening phase: collect shares from whoever responds, reconstruct."""
        shares = [s for node in self.nodes
                  if (s := node.release_share(self.bidding_closed)) is not None]
        return self.scheme.open(shares)


if __name__ == "__main__":
    # Slide scenario: 3-out-of-5
    c = Committee(t=3, n=5)
    secret = int.from_bytes(shamir.generate_key(), "big")
    c.deal(secret)

    try:
        c.open()
    except ShamirError as e:
        print("before deadline:", e)

    c.close_bidding()
    print("all online      :", c.open() == secret)

    c.nodes[0].online = c.nodes[1].online = False
    print("2 nodes offline :", c.open() == secret)

    c.nodes[2].online = False
    try:
        c.open()
    except ShamirError as e:
        print("3 nodes offline :", e)
