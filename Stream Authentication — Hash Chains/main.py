import hashlib, string
def compute_root_hash(blocks):
    """ input: list of bytes (where each element is a block of data, e.g., 1KB)
        output: hex string of the final hash h0
    Note: Process the list backwards.
    The last block has no hash appended before hashing.
    All other blocks have the binary digest (32 bytes) of the previous step appended. """
    b = b""

    # Process from last index down to 0
    for i in range(len(blocks) - 1, -1, -1):
        block_bytes = bytes.fromhex(blocks[i])
        if b:
            data = block_bytes + b
        else:
            data = block_bytes
        b = hashlib.sha256(data).digest()

    return b.hex()

def verify_stream(blocks, trusted_h0):
    """
    input:
        blocks: list of bytes (as received by the client)
        trusted_h0: hex string of the trusted root hash
    output:
        boolean: True if every single block in the chain is valid, False otherwise.

    Logic:
    1. Verify B_0 || h_1 matches trusted_h0.
    2. Extract h_1 from the data.
    3. Verify B_1 || h_2 matches h_1.
    4. Repeat.
    """
    expected = trusted_h0.lower()

    for i, block in enumerate(blocks):
        if i < len(blocks) - 1: # every block except the last
            data, next_hash = block
            data = bytes.fromhex(data + next_hash)
            computed = hashlib.sha256(data).hexdigest()

            if computed.lower() != expected:
                return False
            expected = next_hash

        else: # last block
            data = block
            data = bytes.fromhex(data)
            computed = hashlib.sha256(data).hexdigest()

            if computed.lower() != expected:
                return False

    return True


if __name__ == "__main__":
    # Testcase 1:
    # Expected root hash: 7efaf53af572f7680607a3ac24b441ad3966784e50dda32613405a0847a0433e
    #
    blocks_hex = [
        "48656c6c6f20",  # "Hello "
        "576f726c64",  # "World"
        "21"  # "!"
    ]

    root_hash = compute_root_hash(blocks_hex)
    print("Root hash:",root_hash)
    print("Checking: ","7efaf53af572f7680607a3ac24b441ad3966784e50dda32613405a0847a0433e")

    # Testcase 2:
    # Stream Data (Data received by the Client)
    # Stream Data (Data received by the Client)
    stream_data_hex = [
        # Block 0: Data "Security" + Hash of the next block
        ("5365637572697479", "e760f249914465825e27d0c6f6110637307eac934fc225749bfe75324df5db2e"),
        # Block 1: Data " is " + Hash of the next block
        ("20697320","c960563f683a14202dc212ae6554753a03c6cd6ab9df8c27ebd818ba848ab9ef"),
        "46756e"  # Block 2: Data "Fun" (No trailing hash)
    ]
    trusted_root = "f11afac36abee3f8be106bc53226012250cad05b2d3ee621bb5857ff94d92d65"

    verify = verify_stream(stream_data_hex, trusted_root)
    if verify: print("Stream Valid")
    else: print("String Tampered")
