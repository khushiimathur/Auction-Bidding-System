
from commitment import setup, commit, verify


def test_valid_opening():

    pp = setup()

    bid = 75

    commitment, opening = commit(bid, pp)

    assert verify(
        commitment,
        opening.bid,
        opening.randomness,
        pp
    )

    print("PASS: Valid opening accepted")


def test_wrong_bid():

    pp = setup()

    commitment, opening = commit(75, pp)

    assert not verify(
        commitment,
        80,
        opening.randomness,
        pp
    )

    print("PASS: Incorrect bid rejected")


def test_wrong_randomness():

    pp = setup()

    commitment, opening = commit(75, pp)

    wrong_randomness = opening.randomness.copy()
    wrong_randomness[0] = (
        wrong_randomness[0] + 1
    ) % pp.q

    assert not verify(
        commitment,
        opening.bid,
        wrong_randomness,
        pp
    )

    print("PASS: Incorrect randomness rejected")


if __name__ == "__main__":
    test_valid_opening()
    test_wrong_bid()
    test_wrong_randomness()
