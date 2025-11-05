import Crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# def PKCS5_Unpad(data: bytes, block_size = 16) -> bytes:
#     pad_len = data[-1] # get -(the length of the padding)
#     return data[:-pad_len]

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

def increment_counter(iv: bytes) -> bytes:
    value = int.from_bytes(iv, byteorder='big')
    value = (value + 1) % (1 << 128)
    return value.to_bytes(16, byteorder='big')

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

def print_text(b: bytes):
    print(b.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    q1 = ["4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", "140b41b22a29beb4061bda66b6747e14"]
    q2 = ["5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253","140b41b22a29beb4061bda66b6747e14"]
    q3 = ["69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329","36f18357be4dbd77f050515c73fcf9f2"]
    q4 = ["770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451","36f18357be4dbd77f050515c73fcf9f2"]

    # CBC
    res1 = AES_CBC_Decrypt(q1)
    print_text(res1)
    res2 = AES_CBC_Decrypt(q2)
    print_text(res2)

    # CTR
    res3 = AES_CTR_Decrypt(q3)
    print_text(res3)
    res4 = AES_CTR_Decrypt(q4)
    print_text(res4)






