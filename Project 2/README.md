# Implementation of AES in Cipher Block Chaining mode (CBC) and Counter Mode (CTR)

## CBC Mode - Decryption logic
1. Convert inputs
- Key and ciphertext are provided in hexadecimal.
- Convert both to bytes using `bytes.fromhex()`

2. Extract IV
- The first 16 bytes of the ciphertext are the Initialization Vector (IV).
- Remaining bytes are the encrypted message.

3. Block Decryption (Manual CBC)
- Decrypt each 16-byte ciphertext block using AES-ECB.
- XOR the decrypted block with the previous ciphertext block (IV for the first block).

Formula:
$$
X_1 = \operatorname{Dec}(k, Y_1) \oplus IV
$$

$$
X_i = Dec(k, Y_i) \oplus Y_{i-1} \quad \forall i \ge 2
$$

4. Combine and unpad
- Concatenate all plaintext blocks
- Remove PKCS5 padding using ```unpad(plaintext, 16)```.

```
def AES_CBC_Decrypt(cipher):
    key = bytes.fromhex(cipher[1])
    c = bytes.fromhex(cipher[0])

    iv, ciphertext = c[:16],c[16:]
    aes = AES.new(key, AES.MODE_ECB) # use ECB for manually implement CBC

    plaintext = b""
    previous = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = aes.decrypt(block)
        plaintext_block = bytes(a ^ b for a, b in zip(decrypted, previous))
        plaintext += plaintext_block
        previous = block

    return unpad(plaintext,16)
```

## CTR Mode - Decryption logic
1. Convert inputs
- Key and ciphertext are provided in hexadecimal.
- Convert both to bytes using `bytes.fromhex()`

2. Extract IV
- The first 16 bytes of the ciphertext are the Initialization Vector (IV).
- Remaining bytes are the encrypted message.

3. Keystream Generation
- For each block:

- Encrypt the counter using AES-ECB (CTR uses encryption, not decryption).

- XOR the resulting keystream with the ciphertext block to recover plaintext.

- Increment the counter (+1, modulo 2<sup>128</sup>).

Formula:
$$
X_i = Y_i \oplus E(k, \text{counter}_i)
$$
$$
\text{counter}_{i+1} = \text{counter}_i + 1
$$

4. Combine: Concatenate all plaintext blocks

```
def increment_counter(iv: bytes) -> bytes:
    value = int.from_bytes(iv, byteorder='big')
    value = (value + 1) % (1 << 128)
    return value.to_bytes(16, byteorder='big')
```

```
def AES_CTR_Decrypt(cipher):
    key = bytes.fromhex(cipher[1])
    c = bytes.fromhex(cipher[0])

    iv, ciphertext = c[:16],c[16:]
    aes = AES.new(key, AES.MODE_ECB) # use ECB for manually implement ECB

    plaintext = b""
    counter = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        encrypted = aes.encrypt(counter)
        plaintext_block = bytes(a ^ b for a, b in zip(encrypted, block))
        plaintext += plaintext_block
        counter = increment_counter(counter)

    return plaintext
```

# Plaintexts
**Question 1:** Basic CBC mode encryption needs padding.\
**Question 2:** Our implementation uses rand. IV\
**Question 3:** CTR mode lets you build a stream cipher from a block cipher.\
**Question 4:** Always avoid the two time pad!
