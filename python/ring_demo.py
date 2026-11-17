"""Basic ring formation and membership demo; not cryptographic RSign/RVerify."""


BIDDERS = {
    "B1": "sample-public-key-001",
    "B2": "sample-public-key-002",
    "B3": "sample-public-key-003",
    "B4": "sample-public-key-004",
    "B5": "sample-public-key-005",
}


def main():
    print("Basic ring membership demonstration")
    print("This is not cryptographic RSign/RVerify verification.")
    print("\nAvailable bidders:")
    for bidder_id, public_key in BIDDERS.items():
        print(f"{bidder_id}: {public_key}")

    selected_ids = [
        item.strip().upper()
        for item in input("\nEnter bidder IDs for the ring, separated by commas: ").split(",")
        if item.strip()
    ]
    if not selected_ids:
        print("Ring cannot be empty.")
        return

    invalid_ids = [bidder_id for bidder_id in selected_ids if bidder_id not in BIDDERS]
    if invalid_ids:
        print("Invalid bidder ID(s): " + ", ".join(invalid_ids))
        return

    ring = {bidder_id: BIDDERS[bidder_id] for bidder_id in selected_ids}
    print("\nSelected ring:")
    for bidder_id, public_key in ring.items():
        print(f"{bidder_id}: {public_key}")

    bidder_id = input("\nEnter a bidder ID to check: ").strip().upper()
    if bidder_id not in BIDDERS:
        print(f"Invalid bidder ID: {bidder_id}")
        return

    if BIDDERS[bidder_id] in ring.values():
        print("Bidder belongs to the ring")
    else:
        print("Bidder does not belong to the ring")


if __name__ == "__main__":
    main()
