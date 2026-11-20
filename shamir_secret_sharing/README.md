# Threshold Opening with Shamir Secret Sharing


## What it does

No single auctioneer should be able to open a bid. So we split a secret into `n` shares, give one share to each auctioneer, and require at least `t` of them to cooperate to get the secret back.

- Any `t` shares recover the secret.
- Fewer than `t` shares reveal nothing about it.

## How it works (short version)

1. Pick a random polynomial of degree `t-1`: `f(x) = s + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)  (mod p)`
2. The secret is `s = f(0)`.
3. Auctioneer `i` gets the point `(i, f(i))`. This is their share.
4. To open, `t` auctioneers combine their points with Lagrange interpolation and get `f(0)`.

Example (3-out-of-5): `f(x) = 5 + 3x + 2x^2` gives shares `(1,10) (2,19) (3,32) (4,49) (5,70)`. Any 3 of them give back `5`.

Why it is post-quantum safe: the scheme is information-theoretic. It does not depend on the discrete log problem, so Shor's algorithm does not affect it.

## Files

| File | Purpose |
|---|---|
| `shamir.py` | Core math: `split` and `reconstruct` |
| `committee.py` | `ShamirScheme` (enforces the threshold), plus `Auctioneer` and `Committee` to simulate the opening |
| `test_shamir.py` | Tests for the core, including the slide example |
| `test_committee.py` | Tests for the committee simulation |
| `benchmark.py` | Measures computation, storage and scalability; writes CSVs and plots to `results/` |

## Requirements

- Python 3.8 or newer
- The code and tests use only the standard library
- `matplotlib` is needed only for the benchmark plots (`pip install matplotlib`)

## How to run

Run these from inside this folder:

```bash
python3 test_shamir.py       # 11 tests
python3 test_committee.py    # 11 tests
python3 committee.py         # small demo
python3 benchmark.py         # benchmarks and plots in results/
```

## How to use it from other modules

```python
from committee import ShamirScheme

scheme = ShamirScheme(t=3, n=5)

shares = scheme.deal(secret_int)        # list of 5 shares, one per auctioneer
secret = scheme.open(shares[:3])        # any 3 shares give the secret back

# for byte strings up to 32 bytes (for example a key):
shares = scheme.deal_bytes(key_bytes)
key    = scheme.open_bytes(shares[:3])
```

- The secret must be smaller than `p = 2^256 - 189`. Use `shamir.generate_key()` to make a valid random 32-byte key.
- `open` raises `ShamirError` if fewer than `t` shares are given.

## Benchmarks (what they measure)

- Share generation time versus `n` and `t`
- Reconstruction time versus `t` (about quadratic)
- Storage: 36 bytes per committee member (32 for the value, 4 for the index)
- Scalability: number of bidders versus total time for different committee sizes

Rerun `benchmark.py` on your own machine and use those numbers in the report.

## Current limitations

1. **No share verification yet.** A wrong or corrupted share is not detected, and the result is silently wrong. (The paper's Feldman check relies on discrete log, so it is not post-quantum safe. A hash-based replacement is planned.)
2. **What the secret represents is not fixed yet.** The module shares any value up to 32 bytes. Whether it is a key protecting `(v, r)` or something else is decided with the commitment module.
3. **It is a simulation.** Auctioneers are Python objects in one program. There is no network, no encryption of shares in transit (planned: ML-KEM / Kyber), and the bidding deadline is just a flag.
4. **The dealer is assumed honest.** The dealer sees the secret and creates the polynomial.

## Status

- [x] Core split and reconstruct
- [x] Threshold enforcement and committee simulation
- [x] Tests (22)
- [x] Benchmarks
- [ ] Share verification (post-quantum)
- [ ] Integration with commitment, OT and ZK modules
