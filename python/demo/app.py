import json
import math
import subprocess
import sys
from pathlib import Path

import streamlit as st

AUCTION_EXECUTABLE_NAME = (
    "lrs_auction_cli.exe" if sys.platform == "win32" else "lrs_auction_cli"
)
KEYGEN_EXECUTABLE_NAME = (
    "lrs_keygen_cli.exe" if sys.platform == "win32" else "lrs_keygen_cli"
)

st.set_page_config(
    page_title="Post-Quantum Sealed-Bid Auction",
    page_icon="🔐",
    layout="wide",
)

DEMO_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = DEMO_DIR.parents[1]
BUILD_DIR = REPOSITORY_ROOT / "build" / "python_demo"

SERVER_EXCEPTIONS = (subprocess.CalledProcessError, OSError, RuntimeError,
                    json.JSONDecodeError)

# --------------------------------------------------------------------------
# Backend process management (shared by the Playground and Auction pages).
# Streamlit reruns this whole script on every interaction, so any real
# cryptographic state (a ring, OTS keys, accepted signatures) has to live
# in the long-running C++ process, not in Python. get_auction_server()
# keeps exactly one such process per browser session.
# --------------------------------------------------------------------------


@st.cache_resource
def build_auction_cli():
    subprocess.run(
        ["cmake", "-S", str(DEMO_DIR), "-B", str(BUILD_DIR)],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["cmake", "--build", str(BUILD_DIR), "--target", "lrs_auction_cli", "--config", "Release"],
        check=True, capture_output=True, text=True,
    )
    for executable in (BUILD_DIR / AUCTION_EXECUTABLE_NAME,
                      BUILD_DIR / "Release" / AUCTION_EXECUTABLE_NAME):
        if executable.is_file():
            return executable
    raise RuntimeError("CMake completed but the auction server executable was not found.")


def get_server():
    """Launches the persistent backend process the first time any page
    actually needs it (not merely because the app loaded), and keeps it
    in session_state. If a previously launched process is found to have
    exited, this flags auction_state_lost / playground_state_lost
    instead of silently starting a replacement and pretending nothing
    happened."""
    process = st.session_state.get("server_process")
    if process is not None and process.poll() is None:
        return process
    if process is not None:
        if st.session_state.get("current_auction_id") is not None:
            st.session_state["auction_state_lost"] = True
        if st.session_state.get("pg_ring"):
            st.session_state["playground_state_lost"] = True
        st.session_state["current_auction_id"] = None
        st.session_state["pg_ring"] = None
    executable = build_auction_cli()
    process = subprocess.Popen(
        [str(executable)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
    )
    st.session_state["server_process"] = process
    return process


def send_command(*fields):
    process = get_server()
    line = " ".join(str(field) for field in fields)
    process.stdin.write(line + "\n")
    process.stdin.flush()
    response_line = process.stdout.readline()
    if not response_line:
        raise RuntimeError("the backend process did not respond (it may have crashed)")
    return json.loads(response_line)


def error_detail(error):
    if isinstance(error, subprocess.CalledProcessError) and error.stderr:
        return error.stderr.strip()
    return str(error)


def reset_app():
    process = st.session_state.get("server_process")
    if process is not None and process.poll() is None:
        process.terminate()
    st.session_state.clear()


# --------------------------------------------------------------------------
# Small visual helpers
# --------------------------------------------------------------------------

PALETTE = {
    "bg": "#f7f9fc",
    "panel": "#ffffff",
    "panel_border": "#dbe3ef",
    "node": "#eef3fb",
    "node_border": "#c3d4ec",
    "accent": "#2563eb",
    "accent_soft": "#e4ecfc",
    "teal": "#0d9488",
    "text": "#0f172a",
    "text_dim": "#64748b",
    "good": "#0d9488",
    "bad": "#dc2626",
}


def inject_theme():
    st.markdown(
        f"""
        <style>
        .stApp {{ background: {PALETTE['bg']}; }}
        .pq-badge {{
            display:inline-block; padding:4px 12px; border-radius:999px;
            font-size:12px; font-weight:600; letter-spacing:.02em;
        }}
        .pq-badge-good {{ background: rgba(20,184,166,.15); color:{PALETTE['good']}; border:1px solid rgba(20,184,166,.4); }}
        .pq-badge-bad {{ background: rgba(240,83,107,.15); color:{PALETTE['bad']}; border:1px solid rgba(240,83,107,.4); }}
        .pq-badge-neutral {{ background: rgba(143,163,196,.12); color:{PALETTE['text_dim']}; border:1px solid {PALETTE['panel_border']}; }}
        .pq-card {{
            background:{PALETTE['panel']}; border:1px solid {PALETTE['panel_border']};
            border-radius:14px; padding:18px 20px; margin-bottom:10px;
            box-shadow: 0 1px 3px rgba(15,23,42,.06);
        }}
        .pq-step-progress {{
            display:flex; gap:8px; margin:6px 0 18px;
        }}
        .pq-step-dot {{
            flex:1; height:6px; border-radius:999px; background:{PALETTE['panel_border']};
        }}
        .pq-step-dot.done {{ background:{PALETTE['good']}; }}
        .pq-step-dot.current {{ background:{PALETTE['accent']}; }}
        .pq-card h4 {{ margin:0 0 6px 0; font-size:15px; }}
        .pq-card p {{ margin:0; color:{PALETTE['text_dim']}; font-size:13px; }}
        .pq-step-label {{
            font-family: monospace; font-size:11px; letter-spacing:.08em;
            text-transform:uppercase; color:{PALETTE['accent']};
        }}
        .pq-divider {{ border: none; border-top: 1px solid {PALETTE['panel_border']}; margin: 18px 0; }}
        .pq-mono {{ font-family: monospace; font-size:12.5px; color:{PALETTE['text']}; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def badge(text, kind="neutral"):
    return f'<span class="pq-badge pq-badge-{kind}">{text}</span>'


def render_step_progress(completed_steps, total=4):
    """A thin 4-segment progress bar: segments before the current step
    are 'done' (teal), the current one is 'current' (blue), the rest
    are neutral. Purely visual -- reflects session_state, not a claim
    about backend state."""
    dots = []
    for i in range(1, total + 1):
        if i <= completed_steps:
            cls = "done"
        elif i == completed_steps + 1:
            cls = "current"
        else:
            cls = ""
        dots.append(f'<div class="pq-step-dot {cls}"></div>')
    return f'<div class="pq-step-progress">{"".join(dots)}</div>'


def render_ring_svg(count, highlight=None, fingerprints=None, size=320):
    """A small SVG ring diagram: `count` nodes arranged in a circle,
    optionally highlighting one as the signer. Purely illustrative --
    never itself the source of a cryptographic result."""
    cx = cy = size / 2
    radius = size / 2 - 46
    parts = [f'<circle cx="{cx}" cy="{cy}" r="3" fill="{PALETTE["panel_border"]}"/>']
    for i in range(count):
        angle = -math.pi / 2 + 2 * math.pi * i / count
        x = cx + radius * math.cos(angle)
        y = cy + radius * math.sin(angle)
        is_hl = (i == highlight)
        fill = PALETTE["accent"] if is_hl else PALETTE["node"]
        stroke = PALETTE["accent"] if is_hl else PALETTE["node_border"]
        label = f"#{i}"
        parts.append(
            f'<g>'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="27" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="2"/>'
            f'<text x="{x:.1f}" y="{y+4:.1f}" text-anchor="middle" '
            f'font-size="12" font-family="monospace" fill="{PALETTE["text"]}">{label}</text>'
            f'</g>'
        )
        if is_hl:
            parts.append(
                f'<text x="{x:.1f}" y="{y-38:.1f}" text-anchor="middle" '
                f'font-size="11" font-family="monospace" fill="{PALETTE["accent"]}">signer</text>'
            )
    svg = (
        f'<svg viewBox="0 0 {size} {size}" width="100%" '
        f'style="max-width:{size}px; display:block; margin:0 auto;">'
        + "".join(parts) + "</svg>"
    )
    return svg


def render_link_scenario_svg(ring_size, signer_a, signer_b, linked, size=320):
    """Two message boxes, each with an arrow to the ring member that
    signed it. When signer_a == signer_b the two arrows converge on one
    node (same key); otherwise they diverge to two different nodes
    (different keys). The convergence/divergence IS the explanation --
    not just a differently-highlighted node."""
    cx, cy = size / 2, size / 2 + 34
    radius = size / 2 - 60
    color = PALETTE["bad"] if linked else PALETTE["good"]

    def node_pos(i):
        angle = -math.pi / 2 + 2 * math.pi * i / ring_size
        return cx + radius * math.cos(angle), cy + radius * math.sin(angle)

    parts = []
    for i in range(ring_size):
        x, y = node_pos(i)
        is_target = i in (signer_a, signer_b)
        fill = color if is_target else PALETTE["node"]
        stroke = color if is_target else PALETTE["node_border"]
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="22" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="2"/>'
            f'<text x="{x:.1f}" y="{y+4:.1f}" text-anchor="middle" '
            f'font-size="10" font-family="monospace" fill="{PALETTE["text"] if not is_target else "#ffffff"}">#{i}</text>'
        )

    box_y = 22
    box_w, box_h = 86, 30
    msg1_x, msg2_x = size * 0.22, size * 0.78
    ax, ay = node_pos(signer_a)
    bx, by = node_pos(signer_b)

    parts.insert(0,
        f'<rect x="{msg1_x - box_w/2:.1f}" y="{box_y:.1f}" width="{box_w}" height="{box_h}" rx="8" '
        f'fill="{PALETTE["accent_soft"]}" stroke="{PALETTE["accent"]}"/>'
        f'<text x="{msg1_x:.1f}" y="{box_y + box_h/2 + 4:.1f}" text-anchor="middle" '
        f'font-size="11" font-family="monospace" fill="{PALETTE["accent"]}">Message 1</text>'
        f'<rect x="{msg2_x - box_w/2:.1f}" y="{box_y:.1f}" width="{box_w}" height="{box_h}" rx="8" '
        f'fill="{PALETTE["accent_soft"]}" stroke="{PALETTE["accent"]}"/>'
        f'<text x="{msg2_x:.1f}" y="{box_y + box_h/2 + 4:.1f}" text-anchor="middle" '
        f'font-size="11" font-family="monospace" fill="{PALETTE["accent"]}">Message 2</text>'
        f'<line x1="{msg1_x:.1f}" y1="{box_y+box_h:.1f}" x2="{ax:.1f}" y2="{ay-24:.1f}" '
        f'stroke="{color}" stroke-width="2.5" stroke-dasharray="{"0" if linked else "5,4"}"/>'
        f'<line x1="{msg2_x:.1f}" y1="{box_y+box_h:.1f}" x2="{bx:.1f}" y2="{by-24:.1f}" '
        f'stroke="{color}" stroke-width="2.5" stroke-dasharray="{"0" if linked else "5,4"}"/>'
    )

    label = "SAME ovk" if linked else "DIFFERENT ovk"
    parts.append(
        f'<text x="{cx:.1f}" y="{cy + radius + 42:.1f}" text-anchor="middle" '
        f'font-size="12" font-weight="600" font-family="monospace" fill="{color}">{label}</text>'
    )

    # The diagram's real vertical extent is the message boxes at the top
    # plus the ring (center cy, radius) plus the bottom label -- NOT an
    # arbitrary fraction of the width. Getting this wrong clips the
    # bottom label and/or the lower ring nodes.
    height = cy + radius + 60
    return (
        f'<svg viewBox="0 0 {size} {height:.0f}" width="100%" '
        f'style="max-width:{size}px; display:block; margin:0 auto;">'
        + "".join(parts) + "</svg>"
    )


inject_theme()

# --------------------------------------------------------------------------
# Session-state defaults
# --------------------------------------------------------------------------

for key, default in [
    ("current_auction_id", None),
    ("pg_ring", None),
    ("pg_signer", 0),
    ("pg_sig_id", None),
    ("pg_sig_pk", None),
    ("pg_sig_fp", None),
    ("pg_verify", None),
    ("pg_second_sig_id", None),
    ("pg_link_result", None),
    ("illus_result", None),
    ("link_demo_result", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# --------------------------------------------------------------------------
# Sidebar navigation
# --------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Post-Quantum Auction")
    page = st.radio(
        "Section",
        [
            "Overview",
            "Ring Signatures",
            "Linkability",
            "Cryptographic Playground",
            "Live Auction",
            "Technical Details",
        ],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.button("Reset demo", on_click=reset_app, use_container_width=True)
    st.caption("Resets all pages and stops the backend process.")

    for flag, label in [
        ("auction_state_lost", "Auction server restarted — previous auctions were lost."),
        ("playground_state_lost", "Playground server restarted — previous session was lost."),
    ]:
        if st.session_state.pop(flag, False):
            st.warning(label)


# ==========================================================================
# 1. Overview
# ==========================================================================

if page == "Overview":
    st.title("Post-Quantum Anonymous Sealed-Bid Auction")
    st.caption(
        "A privacy-preserving auction system powered by lattice-based "
        "linkable ring signatures."
    )
    st.write(
        "Participants can submit bids without publicly revealing their "
        "identities. The system verifies anonymous signatures and prevents "
        "repeated submissions within an auction."
    )

    cols = st.columns(3)
    with cols[0]:
        st.markdown(
            '<div class="pq-card"><h4>🕶️ Anonymous Participation</h4>'
            '<p>A bidder proves membership in an eligible group without '
            'revealing which member they are.</p></div>',
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.markdown(
            '<div class="pq-card"><h4>🔒 Post-Quantum Cryptography</h4>'
            '<p>Built on lattice problems (Esgin et al.) believed hard even '
            'for quantum computers.</p></div>',
            unsafe_allow_html=True,
        )
    with cols[2]:
        st.markdown(
            '<div class="pq-card"><h4>🚫 Duplicate Bid Prevention</h4>'
            '<p>A one-time signature tag lets the system detect a repeat '
            'bidder without learning who they are.</p></div>',
            unsafe_allow_html=True,
        )

    st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
    st.markdown("#### How the pieces fit together")
    st.markdown(
        "1. **Ring signature** — proves the signer belongs to an eligible group, anonymously.\n"
        "2. **Linkable ring signature (WCM)** — adds a tag that reveals *only* whether two "
        "signatures came from the same signer, nothing more.\n"
        "3. **Sealed-bid auction** — uses that tag to reject a second bid from the same "
        "signer, while keeping every bidder anonymous."
    )
    st.info("Use the sidebar to explore each layer, then try the live auction.")


# ==========================================================================
# 2. Ring Signatures (illustrative + optional real run)
# ==========================================================================

elif page == "Ring Signatures":
    st.title("Understanding Ring Signatures")
    st.write(
        "A ring signature proves that **someone in an eligible group** signed "
        "a message, without revealing **which** member signed it."
    )

    ring_size = 8
    if "ring_demo_signer" not in st.session_state:
        st.session_state["ring_demo_signer"] = 0
    signer = st.session_state["ring_demo_signer"]

    left, right = st.columns([1.1, 1])
    with left:
        st.markdown(render_ring_svg(ring_size, highlight=signer), unsafe_allow_html=True)
        st.caption(f"Ring of {ring_size} eligible public keys. Member #{signer} will sign.")
        st.caption("Click a member below to choose the secret signer:")
        click_cols = st.columns(4)
        for i in range(ring_size):
            with click_cols[i % 4]:
                is_selected = (i == signer)
                if st.button(f"● #{i}" if is_selected else f"#{i}",
                           key=f"ring_pick_{i}",
                           type="primary" if is_selected else "secondary",
                           use_container_width=True):
                    st.session_state["ring_demo_signer"] = i
                    st.rerun()
    with right:
        st.markdown("**What happens:**")
        st.markdown(
            "1. The ring — every eligible participant's public key — is fixed.\n"
            "2. Member #{0} signs a message using their secret key and the whole ring.\n"
            "3. The verifier checks the signature against the **ring**, not against "
            "any one public key.\n"
            "4. Verification succeeds or fails — it never reveals which member signed."
            .format(signer)
        )
        st.success("Signature Valid — Signer Identity Hidden")
        st.caption(
            "This panel is an illustration. The verifier's own output never names "
            "the signer; a real run below proves this with actual cryptography."
        )

    st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
    st.markdown("#### Run it for real")
    st.caption(
        "Generates a real ring of 8 keys, signs with member #{0} using the real "
        "Esgin ring signature (wrapped in WCM's LRSign/LRVerify), and verifies the "
        "result — using demo-scale parameters (see Technical Details), not mocks."
        .format(signer)
    )
    if st.button("Generate ring, sign, and verify", type="primary"):
        try:
            with st.spinner("Generating ring and signing..."):
                send_command("PLAYGROUND_RESET")
                sign_response = send_command(
                    "PLAYGROUND_SIGN", signer, f"ring-signature-demo-{signer}")
                verify_response = send_command(
                    "PLAYGROUND_VERIFY", sign_response["signature_id"], "none")
            st.session_state["illus_result"] = {
                "accepted": verify_response["accepted"],
                "pk_fingerprint": sign_response["pk_fingerprint"],
                "ovk_fingerprint": sign_response["ovk_fingerprint"],
            }
        except SERVER_EXCEPTIONS as error:
            st.error(f"Backend error: {error_detail(error)}")

    result = st.session_state.get("illus_result")
    if result:
        if result["accepted"]:
            st.markdown(badge("REAL RESULT: SIGNATURE VALID", "good"), unsafe_allow_html=True)
        else:
            st.markdown(badge("REAL RESULT: SIGNATURE REJECTED", "bad"), unsafe_allow_html=True)
        fp_col1, fp_col2 = st.columns(2)
        fp_col1.markdown(f"**Signer's public key** (`pk`)\n\n`{result['pk_fingerprint']}`")
        fp_col2.markdown(f"**One-time key tag** (`ovk`, not identity)\n\n`{result['ovk_fingerprint']}`")
        st.caption(
            "The public key fingerprint identifies which ring member signed "
            "only in the sense that it's public — a real verifier never "
            "learns this from the signature itself; it's shown here only "
            "because you chose the signer above, for your own reference."
        )


# ==========================================================================
# 3. Linkability
# ==========================================================================

elif page == "Linkability":
    st.title("Understanding Linkable Ring Signatures")
    st.write(
        "WCM extends a ring signature with a one-time signature tag (`ovk`). "
        "Two signatures sharing the same tag came from the same signer — "
        "**Link** detects this without learning who that signer is."
    )

    scenario_a, scenario_b = st.columns(2)
    with scenario_a:
        st.markdown("##### Scenario A — same signer")
        st.markdown(render_link_scenario_svg(8, 2, 2, linked=True), unsafe_allow_html=True)
        st.caption("Both messages trace back to the SAME node — one signer, reused key.")
        st.markdown(badge("Link Result: LINKED", "bad"), unsafe_allow_html=True)
        st.caption("Detected as the same signer — rejected as a duplicate in an auction.")
    with scenario_b:
        st.markdown("##### Scenario B — different signers")
        st.markdown(render_link_scenario_svg(8, 2, 5, linked=False), unsafe_allow_html=True)
        st.caption("The two messages trace back to DIFFERENT nodes — two independent signers.")
        st.markdown(badge("Link Result: UNLINKED", "good"), unsafe_allow_html=True)
        st.caption("Different one-time keys — two independent, legitimate signers.")

    st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
    st.markdown("#### Run it for real")
    st.caption("Uses the real `Link` implementation against two freshly produced signatures.")

    same_signer = st.toggle("Use the same signer for both signatures", value=True)
    if st.button("Sign twice and run Link", type="primary"):
        try:
            with st.spinner("Signing twice and checking Link..."):
                send_command("PLAYGROUND_RESET")
                first = send_command("PLAYGROUND_SIGN", 2, "first message")
                second_signer = 2 if same_signer else 5
                second = send_command("PLAYGROUND_SIGN", second_signer, "second message")
                link_response = send_command(
                    "PLAYGROUND_LINK", first["signature_id"], second["signature_id"])
            st.session_state["link_demo_result"] = {
                "outcome": link_response["outcome"],
                "fp_a": first["ovk_fingerprint"],
                "fp_b": second["ovk_fingerprint"],
            }
        except SERVER_EXCEPTIONS as error:
            st.error(f"Backend error: {error_detail(error)}")

    link_result = st.session_state.get("link_demo_result")
    if link_result:
        outcome = link_result["outcome"]
        if outcome == "linked":
            st.markdown(badge("REAL RESULT: LINKED", "bad"), unsafe_allow_html=True)
        elif outcome == "unlinked":
            st.markdown(badge("REAL RESULT: UNLINKED", "good"), unsafe_allow_html=True)
        else:
            st.markdown(badge("REAL RESULT: REJECTED", "bad"), unsafe_allow_html=True)
        st.caption(
            f"Fingerprint A: `{link_result['fp_a']}`  ·  Fingerprint B: `{link_result['fp_b']}`"
        )


# ==========================================================================
# 4. Cryptographic Playground (guided, step-by-step, real backend)
# ==========================================================================

elif page == "Cryptographic Playground":
    st.title("Interactive Cryptographic Playground")
    st.caption(
        "Every action on this page is a real backend operation — real "
        "LRKeygen, LRSign, LRVerify, and Link — at demo-scale parameters "
        "(see Technical Details). Nothing here is simulated."
    )

    completed = sum([
        bool(st.session_state.get("pg_ring")),
        bool(st.session_state.get("pg_sig_id")),
        bool(st.session_state.get("pg_verify")),
        bool(st.session_state.get("pg_link_result")),
    ])
    st.markdown(render_step_progress(completed), unsafe_allow_html=True)

    st.markdown('<span class="pq-step-label">Step 1</span>', unsafe_allow_html=True)
    st.markdown("#### Generate Keys & Form the Ring")
    if st.button("Generate a fresh ring of 8 participants"):
        try:
            with st.spinner("Running real LRKeygen x8..."):
                response = send_command("PLAYGROUND_RESET")
            st.session_state["pg_ring"] = response["ring"]
            st.session_state["pg_sig_id"] = None
            st.session_state["pg_second_sig_id"] = None
            st.session_state["pg_verify"] = None
            st.session_state["pg_link_result"] = None
        except SERVER_EXCEPTIONS as error:
            st.error(f"Backend error: {error_detail(error)}")

    ring = st.session_state.get("pg_ring")
    if not ring:
        st.info("Click the button above to generate real keys before continuing.")
        st.stop()

    ring_col, info_col = st.columns([1, 1.2])
    with ring_col:
        st.markdown(render_ring_svg(len(ring), size=260), unsafe_allow_html=True)
    with info_col:
        st.markdown(badge(f"Ring size: {len(ring)}", "neutral"), unsafe_allow_html=True)
        st.caption(
            "Every node is a real public key, generated just now by "
            "`LRKeygenForTesting`. No signature exists yet — ring formation "
            "happens before any signer is chosen."
        )
        with st.expander("Public key fingerprints"):
            st.table([{"ring_index": i, "public_key_fingerprint": fp} for i, fp in enumerate(ring)])

    st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
    st.markdown('<span class="pq-step-label">Step 2</span>', unsafe_allow_html=True)
    st.markdown("#### Sign a Message")
    sign_col, sign_info_col = st.columns([1, 1.2])
    with sign_col:
        signer_index = st.selectbox("Signer (ring index)", options=list(range(len(ring))), key="pg_signer_select")
        message = st.text_input("Message to sign", value="hello post-quantum world")
        run_sign = st.button("Run real LRSign")
    with sign_info_col:
        st.markdown(render_ring_svg(len(ring), highlight=signer_index, size=220), unsafe_allow_html=True)

    if run_sign:
        try:
            with st.spinner("Signing..."):
                response = send_command("PLAYGROUND_SIGN", signer_index, message)
            st.session_state["pg_sig_id"] = response["signature_id"]
            st.session_state["pg_sig_pk"] = response["pk_fingerprint"]
            st.session_state["pg_sig_fp"] = response["ovk_fingerprint"]
            st.session_state["pg_verify"] = None
        except SERVER_EXCEPTIONS as error:
            st.error(f"Backend error: {error_detail(error)}")

    if st.session_state["pg_sig_id"]:
        st.success(f"Signature #{st.session_state['pg_sig_id']} created.")
        fp_col1, fp_col2 = st.columns(2)
        fp_col1.markdown(f"**Signer's public key** (`pk`)\n\n`{st.session_state.get('pg_sig_pk', '')}`")
        fp_col2.markdown(f"**One-time key tag** (`ovk`)\n\n`{st.session_state['pg_sig_fp']}`")

        st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
        st.markdown('<span class="pq-step-label">Step 3</span>', unsafe_allow_html=True)
        st.markdown("#### Verify — and Try Tampering")
        tamper_choice = st.radio(
            "Verify against:",
            ["Untouched (should PASS)", "Modified message", "Modified signature", "Modified ring"],
            horizontal=False,
        )
        tamper_map = {
            "Untouched (should PASS)": "none",
            "Modified message": "message",
            "Modified signature": "signature",
            "Modified ring": "ring",
        }
        tamper_explanation = {
            "Untouched (should PASS)":
                "Verifies the exact signature against the exact message and ring it was produced with — the honest case.",
            "Modified message":
                "Flips one byte of the signed message before verifying. The signature was computed over the ORIGINAL message, so it no longer matches.",
            "Modified signature":
                "Alters one coefficient inside the signature itself. The proof no longer corresponds to anything the signer actually computed.",
            "Modified ring":
                "Swaps two members in the public ring before verifying. LRVerify recomputes the proof against THIS ring — a different ring means a different check entirely.",
        }
        st.caption(f"→ {tamper_explanation[tamper_choice]}")
        if st.button("Run real LRVerify"):
            try:
                with st.spinner("Verifying..."):
                    response = send_command(
                        "PLAYGROUND_VERIFY", st.session_state["pg_sig_id"],
                        tamper_map[tamper_choice])
                st.session_state["pg_verify"] = response
            except SERVER_EXCEPTIONS as error:
                st.error(f"Backend error: {error_detail(error)}")

        verify = st.session_state.get("pg_verify")
        if verify:
            if verify["accepted"]:
                st.markdown(badge("✓ VERIFIED", "good"), unsafe_allow_html=True)
            else:
                st.markdown(badge("✗ REJECTED", "bad"), unsafe_allow_html=True)
            st.caption(f"Tested against: {verify['tamper_mode']}")

        st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
        st.markdown('<span class="pq-step-label">Step 4</span>', unsafe_allow_html=True)
        st.markdown("#### Test Linkability")
        st.caption("Sign a second message and compare it with the first using real `Link`.")
        link_col, link_info_col = st.columns([1, 1.2])
        with link_col:
            link_signer = st.selectbox(
                "Second signer (same index = expect LINKED)",
                options=list(range(len(ring))), key="pg_link_signer")
            link_message = st.text_input("Second message", value="a different message", key="pg_link_message")
            run_link = st.button("Sign second message and run Link")
        with link_info_col:
            st.markdown(render_ring_svg(len(ring), highlight=link_signer, size=220), unsafe_allow_html=True)

        if run_link:
            try:
                with st.spinner("Signing and linking..."):
                    second = send_command("PLAYGROUND_SIGN", link_signer, link_message)
                    link_response = send_command(
                        "PLAYGROUND_LINK", st.session_state["pg_sig_id"],
                        second["signature_id"])
                st.session_state["pg_second_sig_id"] = second["signature_id"]
                st.session_state["pg_link_result"] = link_response["outcome"]
            except SERVER_EXCEPTIONS as error:
                st.error(f"Backend error: {error_detail(error)}")

        outcome = st.session_state.get("pg_link_result")
        if outcome:
            if outcome == "linked":
                st.markdown(badge("🔗 LINKED", "bad"), unsafe_allow_html=True)
                st.caption("Same one-time key — the system sees these as the same signer.")
            elif outcome == "unlinked":
                st.markdown(badge("UNLINKED", "good"), unsafe_allow_html=True)
                st.caption("Different one-time keys — independent signers.")
            else:
                st.markdown(badge("REJECTED", "bad"), unsafe_allow_html=True)


# ==========================================================================
# 5. Live Auction
# ==========================================================================

elif page == "Live Auction":
    st.title("Live Sealed-Bid Auction")
    st.caption(
        "The application of everything above: real ring formation, real "
        "signing and verification, and real duplicate detection via `Link`."
    )

    try:
        auctions_response = send_command("AUCTIONS")
        known_auctions = (
            auctions_response.get("auctions", []) if auctions_response.get("ok") else []
        )
    except SERVER_EXCEPTIONS:
        known_auctions = []

    metric_cols = st.columns(4)
    total_accepted = 0
    total_rejected = 0
    for entry in known_auctions:
        try:
            detail = send_command("LIST", entry["auction_id"])
            subs = detail.get("submissions", []) if detail.get("ok") else []
            total_accepted += sum(1 for s in subs if s["accepted"])
            total_rejected += sum(1 for s in subs if not s["accepted"])
        except SERVER_EXCEPTIONS:
            pass
    metric_cols[0].metric("Active Auctions", len(known_auctions))
    metric_cols[1].metric("Eligible Participants", 8)
    metric_cols[2].metric("Accepted Bids", total_accepted)
    metric_cols[3].metric("Rejected Submissions", total_rejected)

    st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)

    create_col, select_col = st.columns(2)
    with create_col:
        st.markdown("#### Create Auction")
        new_auction_name = st.text_input("Auction name", value="spring-auction", key="auction_name_input")
        new_auction_desc = st.text_input("Description", value="Sealed-bid item auction", key="auction_desc_input")
        if st.button("Create auction", type="primary"):
            try:
                with st.spinner("Generating ring of 8 bidders (real LRKeygen)..."):
                    response = send_command("CREATE", new_auction_name)
                if response.get("ok"):
                    st.session_state["current_auction_id"] = new_auction_name
                    st.session_state[f"auction_desc_{new_auction_name}"] = new_auction_desc
                    st.success(f"Auction '{new_auction_name}' created with a ring of {response['ring_size']}.")
                else:
                    st.error(f"Could not create auction: {response.get('error')}")
            except SERVER_EXCEPTIONS as error:
                st.error(f"Backend error: {error_detail(error)}")

    with select_col:
        st.markdown("#### Select Auction")
        auction_ids = [a["auction_id"] for a in known_auctions]
        if auction_ids:
            selected = st.selectbox(
                "Active auction", options=auction_ids,
                index=(auction_ids.index(st.session_state["current_auction_id"])
                      if st.session_state["current_auction_id"] in auction_ids else 0),
                key="active_auction_select",
            )
            st.session_state["current_auction_id"] = selected
        else:
            st.caption("No auctions yet — create one on the left.")

    if known_auctions:
        st.markdown("#### Auctions")
        card_cols = st.columns(min(3, len(known_auctions)))
        for i, entry in enumerate(known_auctions):
            with card_cols[i % len(card_cols)]:
                desc = st.session_state.get(f"auction_desc_{entry['auction_id']}", "Sealed-bid item auction")
                st.markdown(
                    f'<div class="pq-card"><h4>{entry["auction_id"]}</h4>'
                    f'<p>{desc}</p>'
                    f'<p style="margin-top:8px;">Ring size {entry["ring_size"]} · '
                    f'{entry["submission_count"]} submission(s)</p></div>',
                    unsafe_allow_html=True,
                )

    active_auction_id = st.session_state["current_auction_id"]
    if active_auction_id:
        st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
        st.markdown(f"### Auction: '{active_auction_id}'")

        try:
            ring_response = send_command("RING", active_auction_id)
            ring_fingerprints = ring_response.get("ring", []) if ring_response.get("ok") else []
        except SERVER_EXCEPTIONS:
            ring_fingerprints = []

        with st.expander(f"Ring formation — {len(ring_fingerprints) or 8} fixed public keys"):
            st.caption(
                "Generated once, at auction creation, before any bid. This is the "
                "exact ring LRSign/LRVerify check every submission's `signer_index` against."
            )
            if ring_fingerprints:
                st.table([{"ring_index": i, "fingerprint": fp} for i, fp in enumerate(ring_fingerprints)])

        st.markdown("#### Submit an Anonymous Bid")
        st.caption(
            "What actually happens on submit: (1) the backend generates an "
            "**LPCom commitment** to your bid amount, (2) your linkable ring "
            "signature signs that commitment together with this auction's "
            "id, (3) the backend runs **LRVerify** on that signature, (4) "
            "**Link** checks it against every prior accepted submission in "
            "this auction, (5) the bid is accepted or rejected."
        )
        step_cols = st.columns(3)
        with step_cols[0]:
            bidder_index = st.selectbox("1. Eligible participant", options=list(range(8)), key="bid_bidder_select")
        with step_cols[1]:
            bid_amount = st.text_input("2. Bid amount", value="100", key="bid_amount_input")
        with step_cols[2]:
            st.write("")
            st.write("")
            submit_clicked = st.button("3. Submit Anonymous Bid", type="primary")

        if submit_clicked:
            progress = st.empty()
            progress.markdown(badge("Generating LPCom commitment and linkable ring signature...", "neutral"), unsafe_allow_html=True)
            try:
                response = send_command("BID", active_auction_id, bidder_index, bid_amount)
                progress.markdown(badge("Verifying signature (LRVerify)...", "neutral"), unsafe_allow_html=True)
                if response.get("ok"):
                    submission = response["submission"]
                    progress.markdown(badge("Checking previous submissions via Link...", "neutral"), unsafe_allow_html=True)
                    progress.empty()
                    if submission["accepted"]:
                        st.success("BID ACCEPTED")
                        st.caption(
                            "LPCom commitment generated · signature verified · "
                            "no duplicate detected via Link · anonymous "
                            "submission recorded."
                        )
                        st.markdown(
                            f'<div class="pq-card"><h4>LPCom commitment (public)</h4>'
                            f'<p class="pq-mono" style="word-break:break-all;">{submission["lpcom_commitment_hex"]}</p>'
                            f'<p style="margin-top:8px;">Auction: <code>{active_auction_id}</code></p>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                        st.caption(
                            "The ring signature above covers THIS commitment vector, "
                            "not the plaintext bid amount — a verifier only ever "
                            "sees the commitment, never the amount, until settlement."
                        )
                    else:
                        st.error("SUBMISSION REJECTED")
                        if "duplicate" in submission["reason"]:
                            st.caption(
                                "DUPLICATE BID REJECTED — signature verification completed, "
                                "but Link detected a previous submission from the same "
                                "signer. Another bid from this signer is not permitted in this auction."
                            )
                        elif "signature failed verification" in submission["reason"]:
                            st.caption("INVALID SIGNATURE — LRVerify rejected this submission.")
                        else:
                            st.caption(submission["reason"])
                else:
                    progress.empty()
                    st.error(f"Bid submission failed: {response.get('error')}")
            except SERVER_EXCEPTIONS as error:
                progress.empty()
                st.error(f"Backend error: {error_detail(error)}")

        st.info(
            "**Honesty note:** in this demo, the bid amount is sent to the "
            "backend process as plain text, which then computes the LPCom "
            "commitment on the bidder's behalf (the same centralized-key "
            "simplification used throughout this demo — see Technical "
            "Details). LPCom hides the bid from anyone who only sees the "
            "public log or the signed commitment; it does **not** hide the "
            "bid from this particular backend process, which sees the "
            "plaintext amount before committing to it. A real deployment "
            "would have each bidder compute their own commitment locally, "
            "before it ever reaches the auctioneer."
        )

        st.markdown("#### Public Submission History")
        st.caption(
            "No bidder identity, no ring index, no plaintext bid amount — only a "
            "pseudonymous one-time-key fingerprint, a hash of the sealed bid, and "
            "the accept/reject outcome."
        )
        try:
            list_response = send_command("LIST", active_auction_id)
            submissions = list_response.get("submissions", []) if list_response.get("ok") else []
        except SERVER_EXCEPTIONS as error:
            submissions = []
            st.error(f"Backend error: {error_detail(error)}")

        accepted_settlement_index = {}
        running_index = 0
        for s in submissions:
            if s["accepted"]:
                accepted_settlement_index[id(s)] = running_index
                running_index += 1

        if submissions:
            rows = [
                {
                    "status": "ACCEPTED" if s["accepted"] else "REJECTED",
                    "ovk_fingerprint": s["ovk_fingerprint"],
                    "lpcom_commitment_hex": s.get("lpcom_commitment_hex", ""),
                    "reason": s["reason"],
                }
                for s in submissions
            ]
            st.table(rows)
        else:
            st.caption("No submissions yet.")

        st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
        with st.expander("Demonstrate auction isolation"):
            st.markdown(
                "Try this: submit as participant #0 above (accepted), submit as "
                "participant #0 again (rejected — duplicate), then create a second "
                "auction and submit as participant #0 there too (accepted — a "
                "different auction has its own ring and keys, so nothing links "
                "against it)."
            )
            st.caption(
                "Each auction maintains its own linkability history. A submission "
                "in one auction never prevents participation in another."
            )

        st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
        st.markdown("#### How a bid flows through the system")
        flow_steps = [
            "Bid Amount", "LPCom Commitment", "WCM Linkable Signature",
            "Signature Verification", "Duplicate Detection (Link)",
            "Accepted Commitment", "Settlement Reveal",
        ]
        flow_html = '<div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin:10px 0;">'
        for i, step in enumerate(flow_steps):
            flow_html += (
                f'<div class="pq-card" style="flex:1; min-width:120px; padding:10px 12px; text-align:center;">'
                f'<p style="color:{PALETTE["text"]}; font-size:12px; font-weight:600; margin:0;">{step}</p></div>'
            )
            if i != len(flow_steps) - 1:
                flow_html += f'<div style="font-size:16px; color:{PALETTE["text_dim"]};">→</div>'
        flow_html += "</div>"
        st.markdown(flow_html, unsafe_allow_html=True)
        st.caption(
            "LPCom hides the committed message under its own stated (and "
            "explicitly experimental, non-security-validated) assumptions — see "
            "Technical Details. Esgin's ring signature provides anonymity "
            "within the ring; WCM's Link adds the duplicate-submission check "
            "on top; settlement is the only stage where the commitment is "
            "opened, and only inside this section, never in the public log above."
        )

        # ------------------------------------------------------------------
        # Settlement & Bid Verification
        # ------------------------------------------------------------------
        st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
        st.markdown("### Settlement & Bid Verification")
        st.caption(
            "A separate, later stage: opening a commitment to check it against "
            "the bid amount actually recorded. This is never run during bidding, "
            "and the opening randomness is never written into the public log above."
        )

        accepted_options = [
            (accepted_settlement_index[id(s)], s["ovk_fingerprint"])
            for s in submissions if s["accepted"]
        ]
        if not accepted_options:
            st.caption("No accepted submissions in this auction yet.")
        else:
            settle_col1, settle_col2 = st.columns(2)
            with settle_col1:
                st.markdown("##### Reveal & verify the real opening")
                chosen = st.selectbox(
                    "Accepted submission (by one-time key tag)",
                    options=accepted_options,
                    format_func=lambda pair: f"#{pair[0]} — ovk {pair[1]}",
                    key="settlement_reveal_select",
                )
                if st.button("Reveal opening and run Unv", key="settlement_reveal_btn"):
                    try:
                        reveal_response = send_command(
                            "OPEN_BID", active_auction_id, chosen[0])
                        if reveal_response.get("ok"):
                            if reveal_response["verified"]:
                                st.markdown(badge("OPENING VALID", "good"), unsafe_allow_html=True)
                            else:
                                st.markdown(badge("OPENING INVALID", "bad"), unsafe_allow_html=True)
                            st.markdown(f"**Revealed bid amount:** `{reveal_response['amount']}`")
                            st.caption(
                                "This amount is shown ONLY in this settlement "
                                "view, computed from the real stored opening — "
                                "never from the public submission log."
                            )
                        else:
                            st.error(f"Reveal failed: {reveal_response.get('error')}")
                    except SERVER_EXCEPTIONS as error:
                        st.error(f"Backend error: {error_detail(error)}")

            with settle_col2:
                st.markdown("##### Test a claimed amount")
                st.caption(
                    "Checks a CLAIMED amount against the real stored commitment "
                    "and the real stored randomness — a genuine lpcom::Unv call, "
                    "not a simulated comparison."
                )
                claim_target = st.selectbox(
                    "Accepted submission",
                    options=accepted_options,
                    format_func=lambda pair: f"#{pair[0]} — ovk {pair[1]}",
                    key="settlement_claim_select",
                )
                claimed_amount = st.text_input(
                    "Claimed bid amount", value="100", key="settlement_claim_amount")
                if st.button("Verify claimed amount", key="settlement_claim_btn"):
                    try:
                        claim_response = send_command(
                            "VERIFY_BID_AMOUNT", active_auction_id, claim_target[0],
                            claimed_amount)
                        if claim_response.get("ok"):
                            if claim_response["verified"]:
                                st.markdown(badge("ACCEPTED — claimed amount matches", "good"), unsafe_allow_html=True)
                            else:
                                st.markdown(badge("REJECTED — claimed amount does not match", "bad"), unsafe_allow_html=True)
                        else:
                            st.markdown(badge("REJECTED — claimed amount does not match", "bad"), unsafe_allow_html=True)
                            st.caption(f"Backend detail: {claim_response.get('error')}")
                    except SERVER_EXCEPTIONS as error:
                        st.error(f"Backend error: {error_detail(error)}")


# ==========================================================================
# 6. Technical Details
# ==========================================================================

elif page == "Technical Details":
    st.title("Technical Details and Parameters")

    tabs = st.tabs(["Parameters", "Esgin Ring Signature", "WCM Linkable Signature",
                    "Architecture", "Limitations"])

    with tabs[0]:
        demo_col, paper_col = st.columns(2)
        with demo_col:
            st.markdown("**Demo-scale parameters**")
            st.caption("Used by the Playground and Live Auction pages for interactivity.")
            st.table([
                {"Parameter": "n", "Value": "1"},
                {"Parameter": "m", "Value": "2"},
                {"Parameter": "degree (d)", "Value": "64"},
                {"Parameter": "k, β", "Value": "3, 2"},
                {"Parameter": "ring size (β^k)", "Value": "8"},
                {"Parameter": "repetitions (r)", "Value": "3"},
                {"Parameter": "φ1, φ2", "Value": "22, 22"},
            ])
            st.warning("Not validated against Section 6.1 security analysis. Demonstration only.")
        with paper_col:
            st.markdown("**Esgin et al. Table 3 — N64 profile**")
            st.caption("Validated end-to-end in tests/test_production_rsign_integration.cpp.")
            st.table([
                {"Parameter": "N", "Value": "64"},
                {"Parameter": "n, m", "Value": "5, 13"},
                {"Parameter": "degree (d)", "Value": "256"},
                {"Parameter": "log₂(q)", "Value": "50"},
                {"Parameter": "k, β", "Value": "2, 8"},
                {"Parameter": "r", "Value": "16"},
                {"Parameter": "λ", "Value": "128"},
            ])
            st.caption("Real signing/verification at this scale takes a few minutes, which is why the interactive pages above use the demo-scale parameters instead.")

        st.markdown("<hr class='pq-divider'>", unsafe_allow_html=True)
        st.markdown("**LPCom bid-amount commitment — experimental parameters**")
        st.caption(
            "Used by the Live Auction page to commit to each bid amount "
            "(Cabarcas, Demirel, Göpfert, Lancrenon, Wunderer — ePrint "
            "2015/628 — Figure 1)."
        )
        st.table([
            {"Parameter": "n (message rank)", "Value": "1"},
            {"Parameter": "k (randomness rank)", "Value": "16"},
            {"Parameter": "m (rows)", "Value": "24"},
            {"Parameter": "q (modulus, prime)", "Value": "257"},
            {"Parameter": "σ² (exact)", "Value": "1024"},
            {"Parameter": "B (norm bound)", "Value": "157"},
        ])
        st.warning(
            "This profile is loosely shaped after the paper's own Figure 2 "
            "asymptotic instantiation, scaled down for a fast demo. It is "
            "**not** a security-validated parameter set — the paper itself "
            "does not claim Figure 2 is concretely optimized either. No "
            "post-quantum security level is claimed for this profile. It is "
            "entirely separate from, and not validated the same way as, "
            "Esgin's named N64 profile above."
        )

    with tabs[1]:
        st.markdown(
            "- **RSetup** — generates the commitment key and challenge set.\n"
            "- **RKeygen** — generates a ring member's lattice key pair.\n"
            "- **RSign** — produces a one-out-of-many proof over the ring.\n"
            "- **RVerify** — checks that proof against the public ring.\n\n"
            "Implemented in `cpp_backend/src/ring_signature/`."
        )
        st.markdown("**Basic algorithm**")
        st.code(
            "RSetup(λ):\n"
            "    ck, H  ← CKeygen(λ)\n"
            "    return (ck, H)\n\n"
            "RKeygen(ck):\n"
            "    r  ← random secret\n"
            "    pk ← Com(0; r)        # lattice commitment to zero\n"
            "    return (pk, sk=r)\n\n"
            "RSign(sk, m, R = {pk_1 .. pk_N}):\n"
            "    proof ← one-out-of-many(sk, R)   # proves pk_i = pk for some i\n"
            "    return σ = (challenge, response)\n\n"
            "RVerify(R, m, σ):\n"
            "    return accept  iff  proof checks out against R and m",
            language="text",
        )

    with tabs[2]:
        st.markdown(
            "- **LRKeygen** — RS.KeyGen + Dilithium5 OTS.KeyGen, masked with `pk = p̂k + H'(ovk)`.\n"
            "- **LRSign** — unmasks the ring, runs RSign, binds the result with an OTS signature.\n"
            "- **LRVerify** — re-masks the ring, runs RVerify, checks the OTS signature.\n"
            "- **Link** — verifies both signatures, then compares their `ovk`.\n\n"
            "Implemented in `cpp_backend/src/lrs/` (Wang–Chen–Ma, ISC 2019)."
        )
        st.markdown("**Basic algorithm**")
        st.code(
            "LRKeygen():\n"
            "    (p̂k, ŝk) ← RS.KeyGen()\n"
            "    (ovk, osk) ← OTS.KeyGen()\n"
            "    pk ← p̂k + H'(ovk)            # public, goes in the ring\n"
            "    return (pk, sk=(ŝk, osk, ovk))\n\n"
            "LRSign(sk, m, R):\n"
            "    R' ← { pk_i − H'(ovk) for pk_i in R }   # unmask\n"
            "    σ̂ ← RS.Sign(ŝk, m, R')\n"
            "    σ̃ ← OTS.Sign(osk, (σ̂, R, ovk))          # bind the tag\n"
            "    return σ = (σ̂, σ̃, ovk)\n\n"
            "LRVerify(R, m, σ=(σ̂, σ̃, ovk)):\n"
            "    R' ← { pk_i − H'(ovk) for pk_i in R }\n"
            "    return RS.Verify(R', m, σ̂) and OTS.Verify(ovk, .., σ̃)\n\n"
            "Link(σ1, σ2):\n"
            "    if not (Verify(σ1) and Verify(σ2)): return REJECTED\n"
            "    return LINKED if σ1.ovk == σ2.ovk else UNLINKED",
            language="text",
        )

    with tabs[3]:
        st.markdown("#### How a bid flows through the system")
        st.markdown(
            f"""
            <div style="display:flex; gap:14px; align-items:stretch; flex-wrap:wrap; margin:10px 0;">
              <div class="pq-card" style="flex:1; min-width:180px;">
                <h4>👤 Bidder</h4>
                <p>LRKeygen → holds (pk, sk)</p>
                <p>LRSign(sk, bid, ring) → signature</p>
              </div>
              <div style="display:flex; align-items:center; font-size:22px; color:{PALETTE['text_dim']};">→</div>
              <div class="pq-card" style="flex:1; min-width:180px;">
                <h4>📡 Auctioneer process</h4>
                <p>LRVerify(ring, bid, signature)</p>
                <p>Link(signature, prior signatures)</p>
              </div>
              <div style="display:flex; align-items:center; font-size:22px; color:{PALETTE['text_dim']};">→</div>
              <div class="pq-card" style="flex:1; min-width:180px; border-color:{PALETTE['accent']};">
                <h4>✅ Decision</h4>
                <p>Accept (new signer) or</p>
                <p>Reject (duplicate / invalid)</p>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="pq-card">
              <h4>Process boundary</h4>
              <p>Streamlit (Python, this page) ⇄ <span class="pq-mono">lrs_auction_cli</span> (C++, persistent process) over a
              line-based protocol: one plain-text command per line in, one JSON response per line out.
              All cryptography — LRKeygen/LRSign/LRVerify/Link — runs in the C++ process; Python never
              touches key material directly.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.caption("See python/demo/auction_cli.cpp for the exact command protocol.")

    with tabs[4]:
        st.markdown(
            "- The aCom auxiliary commitment provider is experimental; its hiding/binding "
            "are conditional assumptions, not a paper security proof.\n"
            "- Demo-scale parameters (Playground, Live Auction) are not validated against "
            "Esgin's Section 6.1 security analysis.\n"
            "- `OneTimeOtsKeyGuard` enforces one-time key use only within a single process; "
            "it is not a substitute for real key-lifecycle management.\n"
            "- `Link` provides WCM's \"one-time linkability\" — a LINKED result means the same "
            "OTS key pair was used, nothing about a shared ring or message.\n"
            "- This demo centralizes every simulated bidder's secret key in one process so "
            "one operator can submit as any of them; a real deployment never would.\n"
            "- A successful verification establishes internal self-consistency of this "
            "pipeline, not a formal security proof of anonymity or unforgeability.\n"
            "- **LPCom's experimental parameters are not security-validated** (see "
            "Parameters tab) — no post-quantum security level is claimed.\n"
            "- **LPCom does not hide the bid from this demo's own backend process.** "
            "The bid amount is sent to the backend as plain text, which computes the "
            "commitment on the bidder's behalf. It hides the bid from anyone who only "
            "sees the public log, the signature, or the commitment — not from the "
            "process that generated the commitment. A real deployment would have each "
            "bidder commit locally before anything reaches the auctioneer."
        )
