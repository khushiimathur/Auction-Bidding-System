# RSign batch orchestration

The backend now contains the repeated-execution RSign control flow and
verification. A signature contains `r = hash_output_count` first messages,
challenges, and Protocol 2 responses. `ComputeRSignRepetitionCount(lambda, d)`
returns the least integer `r` for which `d^r >= 2^lambda`; callers must
configure the hash output count with the chosen `r`.

Signing creates all first-message states for one attempt, encodes the complete
commitment transcript, derives the challenge vector, and computes the
challenge-dependent `f` lifts. It makes one rejection-provider call for the
run-major concatenated `f` vector. After that accepts, it computes each
response lift without reducing coefficients modulo `q`, concatenates the
`(z, z_b, z_c)` blocks run-major, and makes one global response rejection
call. Either rejection restarts every execution; first messages, states,
transcripts, challenges, and responses are attempt-local. The challenges must
precede `f` rejection because the `f` lifts depend on their monomial
challenges.

The dimensions and squared center bounds passed to the rejection provider are:

| Vector | Dimension | `K^2` | Target `s^2` |
|---|---:|---:|---:|
| `f` | `r*k*(beta-1)*d` | `k*r` | `144*d^2*k*r` |
| responses | `3*r*m*d` | `3*B^2*m*d*r` | `432*B^2*m*d*r` |

`Protocol2ProverState` now has batch-safe staging functions: compute
challenge-dependent `f` lifts, compute unreduced response lifts (consuming the
state), and encode a response only after the caller's global rejection has
accepted. The standalone `RespondProtocol2Proof` API still performs its
original single-run rejection steps.

## Required injected implementations and limitations

There is deliberately no built-in Section 6 Gaussian or batch-rejection
provider. The raw repeated-run sampling laws and exact rejection parameters
remain unresolved; target output widths alone do not establish the input laws.
`RSign` requires providers to affirm Section 6 support and throws
`UnsupportedRSignConfiguration` when they do not. A Gaussian provider can
adapt the existing exact `D_s` sampler only after a justified raw scale profile
is available. A rejection provider must implement the specified global
probability with the exact parameterization; the target scale and `K^2` are
provided as rational integers, without approximating irrational quantities.
The supplied test providers are deterministic orchestration doubles, not
cryptographic implementations.

Transcript serialization remains supplied through `RSignTranscriptEncoder`.
It must bind the commitment key, message, ring, and every first message in a
canonical encoding. The hash-to-challenges implementation must satisfy the
paper's required challenge distribution; the interface validates output
count and challenge membership but does not prove uniformity or independence.
The concrete hiding/binding properties of the auxiliary commitment are also
provider assumptions.

The focused `rsign_batch_test` checks run-major dimensions and lifts, a
coordinate-independent global decision per vector, full-batch restarts,
fresh commitments and challenges after aborts, verification, and failure
propagation. Passing those tests verifies orchestration only—not exact
sampling, rejection correctness, constant-time behavior, production security,
or cryptographic readiness. Rejection loops have no runtime bound.
