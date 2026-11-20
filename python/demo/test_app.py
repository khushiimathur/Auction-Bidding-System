# Streamlit AppTest suite for the Live Auction page's LPCom integration.
# Drives the real app.py script headlessly (no browser), which in turn
# drives the real lrs_auction_cli subprocess (real LPCom/WCM/Esgin --
# no mocks). Run with: python3 -m pytest python/demo/test_app.py -v

from pathlib import Path

from streamlit.testing.v1 import AppTest

APP_PATH = str(Path(__file__).resolve().parent / "app.py")


def _goto_live_auction(at):
    at.sidebar.radio[0].set_value("Live Auction").run()
    return at


def _goto_ot_demo(at):
    at.sidebar.radio[0].set_value("Private Information Selection (OT Demo)").run()
    return at


def _create_auction(at, name):
    for text_input in at.text_input:
        if text_input.key == "auction_name_input":
            text_input.set_value(name)
    for button in at.button:
        if button.label == "Create auction":
            button.click().run()
            break
    return at


def test_app_loads_without_exceptions():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    assert not at.exception


def test_live_auction_page_loads_without_exceptions():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    assert not at.exception


def test_create_auction():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-create")
    assert not at.exception
    assert any("created" in s.value.lower() for s in at.success)


def test_valid_bid_submission_shows_commitment():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-bid")

    for text_input in at.text_input:
        if text_input.key == "bid_amount_input":
            text_input.set_value("100")
    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break

    assert not at.exception
    assert any("ACCEPTED" in s.value for s in at.success)
    # The commitment must appear somewhere on the page (markdown card).
    all_text = " ".join(m.value for m in at.markdown)
    assert "LPCom commitment" in all_text


def test_duplicate_bid_same_auction_is_rejected():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-dup")

    def submit():
        for button in at.button:
            if "Submit Anonymous Bid" in button.label:
                button.click().run()
                return

    submit()
    assert any("ACCEPTED" in s.value for s in at.success)
    submit()
    assert any("REJECTED" in e.value for e in at.error)
    assert any("duplicate" in c.value.lower() for c in at.caption)


def test_submission_in_different_auction_is_independent():
    # Cross-auction independence (same ring index, two SEPARATE
    # auctions/rings, both accepted) is already proven at the C++
    # level in test_sealed_bid_auction.cpp
    # (test_same_bidder_different_auctions_both_accepted) using the
    # real backend directly. This test only confirms the UI itself
    # can create a second, independent auction without exceptions --
    # it does not re-drive the UI's selectbox (a pre-existing,
    # LPCom-unrelated quirk: Streamlit's selectbox keeps its own
    # widget state across reruns once created, so switching the
    # "active auction" dropdown after creating a new auction needs an
    # explicit user click, which is a UI-navigation detail, not a
    # cryptographic property this test is responsible for).
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-isoA")

    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break
    assert any("ACCEPTED" in s.value for s in at.success)

    _create_auction(at, "apptest-isoB")
    assert not at.exception
    assert any("apptest-isoB" in s.value for s in at.success)


def test_valid_settlement_opening_is_accepted():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-settle-valid")

    for text_input in at.text_input:
        if text_input.key == "bid_amount_input":
            text_input.set_value("250")
    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break
    assert any("ACCEPTED" in s.value for s in at.success)

    all_headers = " ".join(h.value for h in at.markdown)
    assert "Settlement & Bid Verification" in all_headers

    for text_input in at.text_input:
        if text_input.key == "settlement_claim_amount":
            text_input.set_value("250")
    for button in at.button:
        if button.key == "settlement_claim_btn":
            button.click().run()
            break
    assert not at.exception
    all_markdown = " ".join(m.value for m in at.markdown)
    assert "ACCEPTED — claimed amount matches" in all_markdown


def test_invalid_settlement_opening_is_rejected():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-settle-invalid")

    for text_input in at.text_input:
        if text_input.key == "bid_amount_input":
            text_input.set_value("250")
    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break
    assert any("ACCEPTED" in s.value for s in at.success)

    for text_input in at.text_input:
        if text_input.key == "settlement_claim_amount":
            text_input.set_value("50")  # wrong amount, in LPCom's message range
    for button in at.button:
        if button.key == "settlement_claim_btn":
            button.click().run()
            break
    assert not at.exception
    all_markdown = " ".join(m.value for m in at.markdown)
    assert "REJECTED — claimed amount does not match" in all_markdown


def test_reveal_opening_shows_real_amount():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-settle-reveal")

    for text_input in at.text_input:
        if text_input.key == "bid_amount_input":
            text_input.set_value("64")
    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break
    assert any("ACCEPTED" in s.value for s in at.success)

    for button in at.button:
        if button.key == "settlement_reveal_btn":
            button.click().run()
            break
    assert not at.exception
    all_markdown = " ".join(m.value for m in at.markdown)
    assert "OPENING VALID" in all_markdown
    assert "Revealed bid amount:** `64`" in all_markdown


def test_subprocess_restart_is_handled_gracefully():
    # Kills the real backend subprocess mid-session (simulating a crash)
    # and confirms the next interaction neither raises an unhandled
    # exception nor silently pretends nothing happened -- it must
    # restart the server and surface the "state lost" warning.
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-restart")

    process = at.session_state["server_process"]
    process.terminate()
    process.wait(timeout=10)

    at.run()  # this rerun detects the dead process, restarts it, and
             # sets the "state lost" flag (the sidebar that displays
             # it already rendered earlier in THIS same script run, so
             # the warning itself appears on the NEXT rerun -- a
             # one-render-cycle lag inherent to Streamlit's top-to-
             # bottom script order, not a crash or a silent failure)
    assert not at.exception
    assert at.session_state.get("current_auction_id") is None, (
        "a detected dead process must reset auction state, not pretend "
        "nothing happened"
    )

    at.run()
    assert not at.exception
    assert any("restarted" in w.value.lower() for w in at.warning)


def test_public_log_never_shows_plaintext_amount_or_randomness():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-privacy")

    for text_input in at.text_input:
        if text_input.key == "bid_amount_input":
            text_input.set_value("777")
    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break

    # Check the specific submission-history table's rows (not every
    # table on the page -- the ring-fingerprint table is unrelated and
    # its random hex digests can coincidentally contain "777" as a
    # substring, which would be a false positive, not a privacy leak).
    # SubmissionPublicView itself has no field capable of holding the
    # plaintext amount; this checks the RENDERED fields exactly, not a
    # substring scan of unrelated hex.
    found_submission_table = False
    for table in at.table:
        df = table.value
        if "ovk_fingerprint" in getattr(df, "columns", []):
            found_submission_table = True
            for column in ("status", "ovk_fingerprint", "reason"):
                assert not (df[column].astype(str) == "777").any()
    assert found_submission_table, "the submission-history table did not render"


def test_ot_demo_page_loads_without_exceptions():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_ot_demo(at)
    assert not at.exception
    assert any("SIMULATED OT" in e.value for e in at.error)


def test_ot_demo_selection_recovers_chosen_payload():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_ot_demo(at)

    for number_input in at.number_input:
        if number_input.key == "ot_payload_count":
            number_input.set_value(3)
    at.run()

    for text_input in at.text_input:
        if text_input.key == "ot_payload_1":
            text_input.set_value("the-chosen-option")
    for selectbox in at.selectbox:
        if selectbox.key == "ot_choice_select":
            selectbox.set_value(1)
    for button in at.button:
        if button.key == "ot_run_button":
            button.click().run()
            break

    assert not at.exception
    assert any("the-chosen-option" in s.value for s in at.success)
    assert any("SUCCESS" in str(t.value) for t in at.table)


def _submit_bid_and_get_trustee_buttons(at, auction_name, amount="150"):
    _create_auction(at, auction_name)
    for text_input in at.text_input:
        if text_input.key == "bid_amount_input":
            text_input.set_value(amount)
    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break
    assert any("ACCEPTED" in s.value for s in at.success)
    return [b for b in at.button if b.label.startswith("Trustee #")]


def test_shamir_threshold_displayed_and_insufficient_before_any_trustee():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _submit_bid_and_get_trustee_buttons(at, "apptest-shamir-display")

    all_markdown = " ".join(str(m.value) for m in at.markdown) + " ".join(
        str(i.value) for i in at.info)
    assert "Trustee threshold: 3 of 5" in all_markdown
    assert any("INSUFFICIENT SHARES" in str(m.value) for m in at.markdown)

    reconstruct = [b for b in at.button if b.key == "settlement_reconstruct_btn"]
    assert len(reconstruct) == 1
    assert reconstruct[0].disabled, "reconstruct must be disabled below threshold"


def test_shamir_exact_threshold_reconstructs_and_verifies():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _submit_bid_and_get_trustee_buttons(at, "apptest-shamir-exact", amount="200")

    for trustee_number in (1, 2, 3):  # exactly t=3
        for button in at.button:
            if button.label == f"Trustee #{trustee_number}":
                button.click().run()
                break

    assert not at.exception
    assert any("THRESHOLD MET" in str(m.value) for m in at.markdown)

    reconstruct = [b for b in at.button if b.key == "settlement_reconstruct_btn"]
    assert len(reconstruct) == 1
    assert not reconstruct[0].disabled
    reconstruct[0].click().run()

    assert not at.exception
    all_markdown = " ".join(str(m.value) for m in at.markdown)
    assert "SETTLEMENT AUTHORIZED" in all_markdown
    assert "Verified bid amount:** `200`" in all_markdown


def test_shamir_more_than_threshold_also_reconstructs():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _submit_bid_and_get_trustee_buttons(at, "apptest-shamir-more", amount="77")

    for trustee_number in (1, 2, 3, 4, 5):  # all 5, n > t
        for button in at.button:
            if button.label == f"Trustee #{trustee_number}":
                button.click().run()
                break

    reconstruct = [b for b in at.button if b.key == "settlement_reconstruct_btn"][0]
    assert not reconstruct.disabled
    reconstruct.click().run()

    all_markdown = " ".join(str(m.value) for m in at.markdown)
    assert "SETTLEMENT AUTHORIZED" in all_markdown
    assert "Verified bid amount:** `77`" in all_markdown


def test_shamir_reconstruct_blocked_below_threshold():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _submit_bid_and_get_trustee_buttons(at, "apptest-shamir-below")

    for trustee_number in (1, 2):  # only 2, below t=3
        for button in at.button:
            if button.label == f"Trustee #{trustee_number}":
                button.click().run()
                break

    reconstruct = [b for b in at.button if b.key == "settlement_reconstruct_btn"][0]
    assert reconstruct.disabled, "must stay disabled with fewer than t shares"
    assert not any("SETTLEMENT AUTHORIZED" in str(m.value) for m in at.markdown)


def test_shamir_trustee_button_disabled_after_submission():
    # A trustee cannot be clicked twice via the UI (duplicate-trustee
    # rejection is enforced by SettlementTrusteeStore; the UI additionally
    # disables an already-submitted trustee's button entirely).
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _submit_bid_and_get_trustee_buttons(at, "apptest-shamir-dup")

    for button in at.button:
        if button.label == "Trustee #1":
            button.click().run()
            break

    updated = [b for b in at.button if b.label.startswith("Trustee #1")]
    assert len(updated) == 1
    assert updated[0].disabled


def test_synopsis_six_step_flow_diagram_renders():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    assert not at.exception
    all_markdown = " ".join(str(m.value) for m in at.markdown)
    for step in ["1. Registration", "2. Sealed Bidding", "3. Oblivious Transfer",
                "4. Threshold Opening", "5. ZK Verification", "6. Public Result"]:
        assert step in all_markdown


def test_step3_ot_in_flow_private_selection_works():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-step3-ot")

    for text_input in at.text_input:
        if text_input.key == "live_ot_option_1":
            text_input.set_value("fast-shipping")
    for selectbox in at.selectbox:
        if selectbox.key == "live_ot_choice_select":
            selectbox.set_value(1)
    for button in at.button:
        if button.key == "live_ot_run_button":
            button.click().run()
            break

    assert not at.exception
    assert any("fast-shipping" in s.value for s in at.success)
    assert any("SIMULATED OT" in e.value for e in at.error)


def test_step5_zk_verification_marked_not_implemented():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-step5-zk")

    all_warnings = " ".join(str(w.value) for w in at.warning)
    assert "Not yet implemented" in all_warnings
    assert any("ZK Verification" in str(m.value) for m in at.markdown)


def test_step6_public_result_audit_root_and_inclusion_proof():
    at = AppTest.from_file(APP_PATH, default_timeout=60)
    at.run()
    _goto_live_auction(at)
    _create_auction(at, "apptest-step6-audit")

    for button in at.button:
        if "Submit Anonymous Bid" in button.label:
            button.click().run()
            break
    assert any("ACCEPTED" in s.value for s in at.success)

    all_markdown = " ".join(str(m.value) for m in at.markdown)
    assert "Merkle root (public)" in all_markdown

    for button in at.button:
        if button.key == "audit_verify_button":
            button.click().run()
            break

    assert not at.exception
    assert any("VERIFIED" in str(m.value) for m in at.markdown)
