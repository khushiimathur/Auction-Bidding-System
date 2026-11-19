"""
Interactive 1-out-of-N OT layer demonstrator.

"""
import math
import os
import struct
import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def lp(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


class SimROT:
    """TEST ONLY: trusted dealer generates correlated random OT material."""
    def get(self, l):
        pairs = [(os.urandom(16), os.urandom(16)) for _ in range(l)]
        r = [os.urandom(1)[0] & 1 for _ in range(l)]
        keys = [pairs[i][r[i]] for i in range(l)]
        return pairs, r, keys


def bits(x, l):
    return [(x >> (l - 1 - i)) & 1 for i in range(l)]


def derive_key(session, query, N, x, keys):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=lp(b"pq-auction-ot-v1", session, query,
                struct.pack(">I", N), struct.pack(">I", x), *keys)
    ).derive(b"")


def aad(session, query, N, x):
    return lp(session, query, struct.pack(">I", N), struct.pack(">I", x))


class Sender:
    def __init__(self, session, query, payloads, rot_pairs):
        self.s, self.q, self.P, self.N = session, query, payloads, len(payloads)
        self.l = max(1, math.ceil(math.log2(self.N)))
        self.pairs = rot_pairs
        if len(rot_pairs) != self.l:
            raise ValueError("ROT material length mismatch")

    def respond(self, d):
        if len(d) != self.l or any(b not in (0, 1) for b in d):
            raise ValueError("Invalid request bits")
        out = []
        for x in range(self.N):
            xb = bits(x, self.l)
            ks = [self.pairs[i][xb[i] ^ d[i]] for i in range(self.l)]
            key = derive_key(self.s, self.q, self.N, x, ks)
            nonce = os.urandom(12)
            out.append(nonce + AESGCM(key).encrypt(
                nonce, self.P[x], aad(self.s, self.q, self.N, x)))
        return out


class Receiver:
    def __init__(self, session, query, N, c, r, keys):
        if not 0 <= c < N:
            raise ValueError("Selection out of range")
        self.s, self.q, self.N, self.c = session, query, N, c
        self.l = max(1, math.ceil(math.log2(N)))
        self.r, self.keys = r, keys

    def request(self):
        cb = bits(self.c, self.l)
        return [cb[i] ^ self.r[i] for i in range(self.l)]

    def decrypt_index(self, cts, x):
        key = derive_key(self.s, self.q, self.N, x, self.keys)
        ct = cts[x]
        return AESGCM(key).decrypt(
            ct[:12], ct[12:], aad(self.s, self.q, self.N, x))


def run_demo(payloads, chosen_index):
    N = len(payloads)
    session, query = b"auction-demo-session", os.urandom(8)
    l = max(1, math.ceil(math.log2(N)))
    pairs, r, keys = SimROT().get(l)
    sender = Sender(session, query, payloads, pairs)
    receiver = Receiver(session, query, N, chosen_index, r, keys)
    request_bits = receiver.request()
    ciphertexts = sender.respond(request_bits)
    return receiver, ciphertexts, request_bits, l


st.set_page_config(page_title="1-out-of-N OT Demonstrator", page_icon="🔐", layout="wide")
st.title("🔐 1-out-of-N Oblivious Transfer")
st.caption("Interactive Layer-3 + payload prototype for the PQ auction project")
st.warning(
    "This Prototype uses SimROT, a trusted-dealer test substitute. "
    "It demonstrates the selection, key-derivation and AEAD payload layer only. "
)

with st.expander("Protocol idea", expanded=False):
    st.markdown("""
    1. Sender prepares N payloads.
    2. Receiver chooses index c.
    3. Receiver sends dᵢ = cᵢ XOR rᵢ.
    4. Sender derives a separate key for each index and encrypts every payload.
    5. Receiver derives the selected key and decrypts its payload.
    6. Attempts to decrypt other payloads fail AEAD authentication.

    SimROT supplies correlated random OT material through a trusted dealer inside
    this single-process demonstration. A real deployment must replace it with a
    compatible, independently reviewed OT primitive.
    """)

if "result" not in st.session_state:
    st.session_state.result = None

sender_col, receiver_col = st.columns(2, gap="large")
with sender_col:
    st.subheader("1. Sender — auctioneer")
    N = st.number_input("Number of payloads (N)", 2, 16, 4, 1)
    payloads = []
    for i in range(int(N)):
        payloads.append(st.text_input(
            f"Payload M{i}", value=f"Encrypted bid payload {i}",
            key=f"payload_{i}").encode("utf-8"))

with receiver_col:
    st.subheader("2. Receiver — bidder")
    choice = st.selectbox("Choose one payload index", list(range(int(N))))
    l = max(1, math.ceil(math.log2(int(N))))
    st.info(f"Receiver chooses **c = {choice}** (binary: **{format(choice, f'0{l}b')}**)")
    st.caption("In a real OT protocol, the receiver's choice should remain hidden from the sender.")

if st.button("▶ Run 1-out-of-N demonstration", type="primary", use_container_width=True):
    receiver, cts, d, l = run_demo(payloads, int(choice))
    st.session_state.result = {
        "receiver": receiver, "cts": cts, "d": d, "l": l,
        "payloads": payloads, "choice": int(choice), "N": int(N)
    }

res = st.session_state.result
if res:
    st.divider()
    st.subheader("3. Protocol execution")
    m1, m2, m3 = st.columns(3)
    m1.metric("Messages (N)", res["N"])
    m2.metric("Binary OT instances (ℓ)", res["l"])
    m3.metric("Chosen index (c)", res["choice"])
    st.markdown("**Receiver request bits**")
    st.code("d = " + " ".join(map(str, res["d"])))
    st.caption("dᵢ = cᵢ XOR rᵢ")

    st.markdown("**Sender's encrypted collection**")
    st.dataframe([
        {"Index": i, "Ciphertext size (bytes)": len(ct),
         "Ciphertext preview": ct[:12].hex() + "…",
         "Selected": "← receiver choice" if i == res["choice"] else ""}
        for i, ct in enumerate(res["cts"])
    ], use_container_width=True, hide_index=True)

    st.subheader("4. Receiver decryption and verification")
    checks, selected_plaintext = [], None
    for i in range(res["N"]):
        try:
            plaintext = res["receiver"].decrypt_index(res["cts"], i)
            if i == res["choice"]:
                selected_plaintext = plaintext
                checks.append({"Index": i, "Outcome": "SUCCESS — selected payload recovered"})
            else:
                checks.append({"Index": i, "Outcome": "Unexpected success — investigate"})
        except InvalidTag:
            checks.append({"Index": i, "Outcome": "Rejected — authentication failed"})
    st.dataframe(checks, use_container_width=True, hide_index=True)
    if selected_plaintext is not None:
        st.success("Recovered selected payload: " +
                   selected_plaintext.decode("utf-8", errors="replace"))
    st.caption(
        "Failed decryptions demonstrate key separation in this test harness; "
        "in a real OT protocol, the receiver cannot derive keys for unselected payloads."
    )
    if st.button("Clear run and generate fresh random material"):
        st.session_state.result = None
        st.rerun()

st.divider()
st.subheader("5. Mapping to the research architecture")
st.markdown("""
| Research layer | Prototype implementation |
|---|---|
| Base 1-out-of-2 OT / ROT | SimROT trusted-dealer test substitute |
| 1-out-of-N selection | Binary decomposition, ℓ = ceil(log₂ N) |
| Key derivation | HKDF-SHA256 |
| Payload protection | AES-256-GCM |
| Auction payload | Demonstrative labels; replace with actual ciphertext bytes |

""")
