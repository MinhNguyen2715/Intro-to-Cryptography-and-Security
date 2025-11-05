def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences (truncate to shorter length)."""
    return bytes(x ^ y for x, y in zip(a, b))

def OTP(key: bytes, msg: bytes) -> str:
    """Return XOR result as hex string."""
    c = xor_bytes(key, msg)
    return c.hex()

# Build lookup reference table for printable character pairs
upper = [chr(i) for i in range(65, 91)]
lower = [chr(i) for i in range(97, 123)]

alphabets = upper + lower + [" "]

ref = dict()
for c1 in alphabets:
    for c2 in alphabets:
        if OTP(bytes([ord(c1)]), bytes([ord(c2)])) not in ref:
            ref[OTP(bytes([ord(c1)]), bytes([ord(c2)]))] = []
            ref[OTP(bytes([ord(c1)]), bytes([ord(c2)]))].append((c1, c2))
        else:
            ref[OTP(bytes([ord(c1)]), bytes([ord(c2)]))].append((c1, c2))

def ManyTimePad_attack(ciphertexts, target):
    # Compute XOR of every ciphertext with the target (hex strings)
    xored = []
    for c in ciphertexts:
        xored.append(OTP(bytes.fromhex(c[:len(target)]), bytes.fromhex(target)))

    # Initialize storage for discovered plaintexts and target guess
    plaintexts = [["_" for _ in range(len(target)//2)] for _ in ciphertexts]
    res = ["_" for _ in range(len(target)//2)]
    res = ["_" for _ in range(len(target)//2)]
    index = 0

    while index < len(target) // 2:
        print("\n" + "=" * 60)
        print("Menu:")
        print("1. Add a character to a plaintext")
        print("2. Add a character to the target (propagate)")
        print("3. Lookup possible target characters")
        print("4. Delete the latest character")
        print("5. Print all plaintexts and target guess")
        print("6. Enter/Continue target plaintext (from current index)")
        print("7. Exit")
        print("=" * 60)
        choice = input("Enter choice: ")

        if choice == "1":
            # Add a character to one plaintext, propagate to target and to other plaintexts
            while True:
                plaintexts_id = input("Choose which plaintext to decrypt (0-" + str(len(ciphertexts) - 1) + "): ")
                if 0 <= int(plaintexts_id) < len(ciphertexts):
                    chars = input("Characters: ")
                    tmp = index
                    for offset, char in enumerate(chars):
                        idx = tmp + offset
                        plaintexts[int(plaintexts_id)][idx] = char
                        res[idx] = chr(int(xored[int(plaintexts_id)][idx * 2:idx * 2 + 2], 16) ^ ord(
                            plaintexts[int(plaintexts_id)][idx]))
                        for i in range(len(xored)):
                            plaintexts[i][idx] = chr(int(xored[i][idx * 2:idx * 2 + 2], 16) ^ ord(res[idx]))
                            if offset == len(chars) - 1:
                                print("Plaintext " + str(i) + ": " + "".join(plaintexts[i]))
                    index += 1
                    print("Current guess: " + "".join(res))
                    break
                elif int(plaintexts_id) < 0 or int(plaintexts_id) > len(ciphertexts):
                    print("Invalid plaintext id.")

        elif choice == "2":
            # Add a character to the target, propagate to all plaintexts
            chars = input("Characters: ")
            tmp = index
            for offset, char in enumerate(chars):
                idx = tmp + offset
                res[idx] = char
                for i in range(len(xored)):
                    plaintexts[i][idx] = chr(int(xored[i][idx * 2:idx * 2 + 2], 16) ^ ord(res[idx]))
                    if offset == len(chars) - 1:
                        print("Plaintext " + str(i) + ": " + "".join(plaintexts[i]))
            index += 1
            print("Current guess: " + "".join(res))


        elif choice == "3":
            # Lookup possible target characters at current index
            count = {}
            print("*" * 120)
            print("Possible choices: ")
            for i in range(len(xored)):
                key = xored[i][index*2:index*2+2]
                if key not in ref:
                    continue
                for c1, c2 in ref[key]:
                    count[c1] = count.get(c1, 0) + 1
            # show candidates that appear in all ciphertexts
            print(*[k for k, v in count.items() if v == len(xored)])
            print("*" * 120)

        elif choice == "4":
            # Delete latest character (move cursor back)
            if index > 0:
                index -= 1
                res[index] = "_"
                for i in range(len(plaintexts)):
                    plaintexts[i][index] = "_"
            for i in range(len(xored)):
                print("Plaintext " + str(i) + ": " + "".join(plaintexts[i]))
            print("Current guess: " + "".join(res))

        elif choice == "5":
            for i in range(len(xored)):
                print("Plaintext " + str(i) + ": " + "".join(plaintexts[i]))
            print("Current guess: " + "".join(res))

        elif choice == "6":
            if 'res' not in locals() or res is None:
                res = ["_"] * (len(target) // 2)
            if 'index' not in locals() or index is None:
                index = 0

            guess = input("Enter target plaintext from current index:\n")

            start = index
            for off, ch in enumerate(guess):
                pos = start + off
                if pos >= len(res):
                    break
                res[pos] = ch  # keep '_' if user types it

            end = min(start + len(guess), len(res))
            for pos in range(start, end):
                ch = res[pos]
                if ch == "_":  # skip unknown positions
                    continue
                for i in range(len(xored)):
                    if pos * 2 + 2 <= len(xored[i]):
                        byte_val = int(xored[i][pos * 2:pos * 2 + 2], 16)
                        plaintexts[i][pos] = chr(byte_val ^ ord(ch))

            for pos in range(end, len(res)):
                res[pos] = "_"  # keep target unknown
                for i in range(len(xored)):
                    if pos < len(plaintexts[i]):
                        plaintexts[i][pos] = "_"
            index = end

            print("*" * 120)
            for i in range(len(plaintexts)):
                print(f"Plaintext {i}:   {''.join(plaintexts[i])}")
            print("Current guess: " + "".join(res))
            print("*" * 120)

        elif choice == "7":
            print("Exiting...")
            return res

        else:
            print("Unknown choice. Try again.")

    return res

def recover_key_from_target(target_hex: str, res) -> bytes:
    target_bytes = bytes.fromhex(target_hex)
    res_str = "".join(res)
    key = bytearray(len(target_bytes))
    for i, ch in enumerate(res_str):
        if ch != "_":
            key[i] = target_bytes[i] ^ ord(ch)
        else:
            key[i] = 0x00  # unknown placeholder
    return bytes(key)

def format_key_hex(key: bytes) -> str:
    return "".join("??" if b == 0 else f"{b:02x}" for b in key)

def decrypt_with_key(ct_hex: str, key: bytes) -> str:
    """Decrypt ct_hex using key (only up to key length). Non-printable bytes shown as ·"""
    c = bytes.fromhex(ct_hex)
    out = []
    for i in range(min(len(c), len(key))):
        p = c[i] ^ key[i]
        out.append(chr(p) if 32 <= p < 127 else "·")
    return "".join(out)

if __name__ == "__main__":
    ciphertexts = [
        '315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e',
        '234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f',
        '32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb',
        '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa',
        '3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070',
        '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4',
        '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce',
        '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3',
        '271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027',
        '466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83'
    ]
    target = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"

    res = ManyTimePad_attack(ciphertexts, target)
    print("The target is:","".join(res))

    key = recover_key_from_target(target, res)
    print("Recovered key (hex):", format_key_hex(key))
    print("\nSample decrypts using recovered key:")
    for i, ct in enumerate(ciphertexts):
        print(f"Plaintext {i}: {decrypt_with_key(ct, key)}")
