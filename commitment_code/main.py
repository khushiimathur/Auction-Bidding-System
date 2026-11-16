
from commitment import setup, commit, verify


# 1. Generate public parameters
pp = setup(
    n=2,
    k=2,
    m=8,
    q=101,
    sigma=1.2,
    B=6.0
)

print("Public parameters generated.")

# 2. Bidder chooses a private bid
bid = 75

# 3. Generate commitment and private opening
commitment, opening = commit(bid, pp)

# 4. Publish only the commitment
print("\nPublished commitment:")
print(commitment.c)

# The bidder privately retains:
# opening.bid
# opening.randomness

print("\nBid is sealed. The auction system does not receive the opening.")

# 5. Later, bidder reveals the bid and randomness
is_valid = verify(
    commitment,
    opening.bid,
    opening.randomness,
    pp
)

print("\nOpening verification:", is_valid)

# 6. Demonstrate tampering
tampered_bid = 80

tampered_result = verify(
    commitment,
    tampered_bid,
    opening.randomness,
    pp
)

print("Tampered bid verification:", tampered_result)
