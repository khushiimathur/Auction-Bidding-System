## 1. Mathematical Foundation

The proposed commitment scheme replaces elliptic-curve group operations with modular matrix-vector operations and a small error vector.

### 1.1 Public Parameters

The scheme uses the following parameters:

| Symbol | Description |
|---|---|
| $q$ | Modulus |
| $n$ | Message dimension |
| $k$ | Randomness dimension |
| $m$ | Commitment dimension |
| $A_1$ | Public message matrix |
| $A_2$ | Public randomness matrix |
| $v$ | Encoded bid vector |
| $r$ | Randomness vector |
| $e$ | Error vector |
| $\sigma$ | Gaussian sampling parameter |
| $B$ | Maximum permitted error norm |

The public matrices are defined as:

$$
A_1 \in \mathbb{Z}_q^{m \times n}
$$

$$
A_2 \in \mathbb{Z}_q^{m \times k}
$$

The combined matrix is:

$$
A = [A_1 \mid A_2]
$$

### 1.2 Commitment Generation

For a private bid represented as a vector $v$, the bidder generates:

1. A random vector:

$$
r \leftarrow \mathbb{Z}_q^k
$$

2. An error vector sampled from a discrete Gaussian distribution:

$$
e \leftarrow D_\sigma^m
$$

The commitment is calculated as:

$$
\boxed{C = A_1v + A_2r + e \pmod q}
$$

The bidder publishes $C$ while keeping the bid and randomness private.

### 1.3 Opening Verification

When the bidder reveals the bid and randomness, the verifier calculates:

$$
e' = C - A_1v - A_2r \pmod q
$$

The residual is converted into centered integer representatives, and its Euclidean norm is calculated.

The opening is accepted if:

$$
\boxed{\|e'\|_2 \leq B}
$$

Otherwise, the opening is rejected.

---

## 2. Algorithmic Workflow

### Algorithm 1: Parameter Generation (`GenCom`)

**Input:** Scheme parameters.

**Output:** Public commitment parameters.

1. Select dimensions $n,m,k$, modulus $q$, Gaussian parameter $\sigma$, and error bound $B$.
2. Generate public matrix $A_1$.
3. Generate public matrix $A_2$.
4. Construct the combined matrix:

$$
A = [A_1 \mid A_2]
$$

5. Check the required matrix condition.
6. Return the public parameters.

### Algorithm 2: Commitment Generation (`Com`)

**Input:** Public parameters and private bid.

**Output:** Commitment and private opening information.

1. Encode the bid into a message vector $v$.
2. Sample randomness $r$.
3. Sample the error vector $e$.
4. Calculate:

$$
C = A_1v + A_2r + e \pmod q
$$

5. Publish $C$.
6. Securely retain $v$ and $r$ for the opening phase.

### Algorithm 3: Opening Verification (`Unv`)

**Input:** Commitment $C$, revealed bid $v$, randomness $r$, and public parameters.

**Output:** Accept or reject.

1. Calculate the residual:

$$
e' = C - A_1v - A_2r \pmod q
$$

2. Convert the residual into centered integer representatives.
3. Calculate its Euclidean norm.
4. Check whether:

$$
\|e'\|_2 \leq B
$$

5. Accept if the condition holds; otherwise reject.

---

## 3. Bid Encoding

The current prototype represents a non-negative integer bid as:

$$
v = [\text{bid},0,\ldots,0]^T
$$

For example, a bid of 75 with $n=2$ is represented as:

$$
v =
\begin{bmatrix}
75 \\
0
\end{bmatrix}
$$

The current implementation restricts the bid to values smaller than $q$.

---

## 4. Commitment Calculation

The commitment is calculated through modular matrix multiplication:

```python
c = (
    pp.A1 @ v +
    pp.A2 @ r +
    e
) % pp.q
```

This implements:

$$
C = A_1v + A_2r + e \pmod q
$$

## 5. Opening Verification

The verifier reconstructs the residual:

```python
residual = (
    commitment.c -
    pp.A1 @ v -
    pp.A2 @ randomness
) % pp.q
```

The residual is converted into centered integer representatives, and its Euclidean norm is compared against the threshold $B$.

$$
\|e'\|_2 =
\sqrt{\sum_{i=1}^{m}(e'_i)^2}
$$

The opening is accepted when:

$$
\|e'\|_2 \leq B
$$

---

## 6. Comparison with Pedersen Commitment

The classical Pedersen commitment is:

$$
C = vG + rH
$$

The proposed lattice-based commitment is:

$$
C = A_1v + A_2r + e \pmod q
$$

The primary difference is the underlying mathematical structure:

- Pedersen uses group operations and relies on the discrete logarithm assumption for binding.
- LPCom uses modular matrices, randomness and a small error vector, with binding based on lattice hardness assumptions.
