"""
Benchmarks for the slide's "Computational / efficiency pointers".

  1. Share generation  : cost grows with committee size n and degree t-1
  2. Reconstruction    : Lagrange over t shares, roughly quadratic in t
  3. Storage / comms   : share size, per-member storage, total per bid
  4. Scalability       : number of bidders x committee size vs runtime

Run:  python3 benchmark.py
Output: results/*.csv and (if matplotlib is installed) results/*.png
"""

import csv
import math
import os
import secrets
import statistics
import time

import shamir
from shamir import PRIME

OUT = "results"
REPEATS = 5
SHARE_BYTES = 32 + 4   # y is a 256-bit field element, x index stored as 4 bytes


def timeit(fn, repeats=REPEATS):
    """Median wall-clock time of fn() in milliseconds."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.median(samples)


def write_csv(name, header, rows):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"wrote {path}")


def bench_split_vs_n(t=10, ns=(10, 20, 40, 80, 160, 320)):
    rows = []
    for n in ns:
        s = secrets.randbelow(PRIME)
        rows.append((n, t, timeit(lambda: shamir.split(s, t, n))))
    write_csv("split_vs_n.csv", ["n", "t", "split_ms"], rows)
    return rows


def bench_split_vs_t(n=320, ts=(5, 10, 20, 40, 80, 160, 320)):
    rows = []
    for t in ts:
        s = secrets.randbelow(PRIME)
        rows.append((n, t, timeit(lambda: shamir.split(s, t, n))))
    write_csv("split_vs_t.csv", ["n", "t", "split_ms"], rows)
    return rows


def bench_reconstruct_vs_t(ts=(5, 10, 20, 40, 80, 160, 320)):
    rows = []
    for t in ts:
        s = secrets.randbelow(PRIME)
        shares = shamir.split(s, t, t)
        rows.append((t, timeit(lambda: shamir.reconstruct(shares))))
    write_csv("reconstruct_vs_t.csv", ["t", "reconstruct_ms"], rows)

    # empirical growth exponent from a log-log fit (about 2 means quadratic)
    xs = [math.log(t) for t, _ in rows]
    ys = [math.log(ms) for _, ms in rows]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    slope = (sum((x - mx) * (y - my) for x, y in zip(xs, ys))
             / sum((x - mx) ** 2 for x in xs))
    print(f"reconstruction growth exponent in t: {slope:.2f} (2.0 = quadratic)")
    return rows, slope


def bench_storage(configs=((3, 5), (5, 9), (10, 20), (50, 100), (100, 200))):
    rows = []
    for t, n in configs:
        per_member = SHARE_BYTES
        total = n * SHARE_BYTES
        rows.append((t, n, per_member, total))
    write_csv("storage.csv", ["t", "n", "bytes_per_member", "bytes_total_per_bid"], rows)
    return rows


def bench_scalability(bidder_counts=(10, 50, 100, 200), committee=((3, 5), (5, 9), (10, 20))):
    """Total time to deal + open one secret per bidder."""
    rows = []
    for t, n in committee:
        for m in bidder_counts:
            def run():
                for _ in range(m):
                    s = secrets.randbelow(PRIME)
                    shares = shamir.split(s, t, n)
                    assert shamir.reconstruct(shares[:t]) == s
            rows.append((t, n, m, timeit(run, repeats=3)))
    write_csv("scalability.csv", ["t", "n", "bidders", "total_ms"], rows)
    return rows


def make_plots(split_n, split_t, recon, slope, scal):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plots (pip install matplotlib)")
        return

    def save(name):
        plt.tight_layout()
        plt.savefig(os.path.join(OUT, name), dpi=150)
        plt.close()
        print(f"wrote {os.path.join(OUT, name)}")

    plt.figure(figsize=(6, 4))
    plt.plot([r[0] for r in split_n], [r[2] for r in split_n], "o-")
    plt.xlabel("committee size n (t = %d)" % split_n[0][1])
    plt.ylabel("share generation time (ms)")
    plt.title("Share generation vs committee size")
    plt.grid(alpha=0.3)
    save("split_vs_n.png")

    plt.figure(figsize=(6, 4))
    plt.plot([r[1] for r in split_t], [r[2] for r in split_t], "o-")
    plt.xlabel("threshold t (n = %d)" % split_t[0][0])
    plt.ylabel("share generation time (ms)")
    plt.title("Share generation vs threshold")
    plt.grid(alpha=0.3)
    save("split_vs_t.png")

    plt.figure(figsize=(6, 4))
    plt.plot([r[0] for r in recon], [r[1] for r in recon], "o-")
    plt.xlabel("number of shares t")
    plt.ylabel("reconstruction time (ms)")
    plt.title("Lagrange reconstruction vs t (log-log slope %.2f)" % slope)
    plt.xscale("log")
    plt.yscale("log")
    plt.grid(alpha=0.3, which="both")
    save("reconstruct_vs_t.png")

    plt.figure(figsize=(6, 4))
    for t, n in sorted({(r[0], r[1]) for r in scal}):
        pts = [r for r in scal if (r[0], r[1]) == (t, n)]
        plt.plot([p[2] for p in pts], [p[3] for p in pts], "o-", label=f"{t}-of-{n}")
    plt.xlabel("number of bidders")
    plt.ylabel("deal + open time (ms)")
    plt.title("Scalability: bidders x committee size")
    plt.legend()
    plt.grid(alpha=0.3)
    save("scalability.png")


if __name__ == "__main__":
    split_n = bench_split_vs_n()
    split_t = bench_split_vs_t()
    recon, slope = bench_reconstruct_vs_t()
    bench_storage()
    scal = bench_scalability()
    make_plots(split_n, split_t, recon, slope, scal)
    print("done")
