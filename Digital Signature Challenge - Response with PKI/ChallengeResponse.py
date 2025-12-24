import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_key_pair():
    """Generates an RSA 2048-bit key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def key_to_pem_str(key, is_private=False):
    """Converts a Key object to a PEM string."""
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return pem.decode('utf-8')

def sign_data(private_key, data_dict):
    """Signs a dictionary using PSS + SHA256."""
    data_str = json.dumps(data_dict, sort_keys=True)
    signature = private_key.sign(
        data_str.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

class CryptoHelper:
    @staticmethod
    def load_pem_public_key(pem_str):
        """
        Loads a key from a string.
        """
        return serialization.load_pem_public_key(
            pem_str.encode("utf-8")
        )

    @staticmethod
    def load_pem_private_key(pem_str):
        """
        Loads a key from a string.
        """
        return serialization.load_pem_private_key(
            pem_str.encode("utf-8"),
            password=None
        )

    @staticmethod
    def sign(private_key, data):
        """
        Returns a Hex signature (Using PSS + SHA256).
        """
        data = data.encode()
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256()
        )
        return signature.hex()

    @staticmethod
    def verify(public_key, data, signature_hex):
        """
        :return true or false
        """
        try:
            signature_bytes = bytes.fromhex(signature_hex)
            public_key.verify(
                signature_bytes,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

class Prover:
    def __init__(self, sk, cert):
        """
        Stores the user’s Private Key and Certificate.
        """
        self.sk = sk
        self.cert = cert

    def solve_challenge(self, nonce):
        """
        Signs the random string (nonce) received from the Server.
        """
        return CryptoHelper.sign(self.sk, nonce)

class Verifier:
    def __init__(self, ca_public_key_pem):
        """
        initialized with the CA Public Key -> Root of Trust
        """
        self.root_of_trust = ca_public_key_pem

    def verify_session(self, prover, nonce):
        """
        1.	Get the Certificate from the Prover.
        2.	Verify Certificate: Use the stored CA Public Key to verify the signature on the Certificate.
            (If invalid, return False immediately).
        3.	Extract the User’s Public Key from the Certificate.
        4.	Verify Challenge: Verify the Prover’s signature on the nonce using the extracted User Public Key.
        """
        cert = prover.cert
        info_bytes = json.dumps(cert["info"], sort_keys=True).encode("utf-8")
        cert_valid = CryptoHelper.verify(self.root_of_trust, info_bytes, cert["signature"])
        if not cert_valid:
            print("Certificate invalid")
            return False
        print("Certificate valid")

        user_pub = CryptoHelper.load_pem_public_key(cert["info"]["public_key"])

        sig = prover.solve_challenge(nonce)  # hex string
        sig_valid = CryptoHelper.verify(user_pub, nonce.encode("utf-8"), sig)
        if not sig_valid:
            print("Signature invalid")
            return False
        print("Signature valid")
        return True

if __name__ == "__main__":
    # 1. Create CA (Certificate Authority)
    ca_priv, ca_pub = generate_key_pair()

    # 2. Create User (Alice)
    alice_priv, alice_pub = generate_key_pair()

    # 3. Create Attacker (Bob)
    bob_priv, bob_pub = generate_key_pair()

    # 4. Issue Certificate for Alice
    alice_info = {
        "id": "Alice",
        "public_key": key_to_pem_str(alice_pub)
    }
    alice_signature = sign_data(ca_priv, alice_info)

    alice_cert = {
        "info": alice_info,
        "signature": alice_signature
    }

    # --- OUTPUT ---
    dataset = {
        # *** THIS IS THE ROOT OF TRUST FOR THE VERIFIER ***
        "CA_PUBLIC_KEY": key_to_pem_str(ca_pub),

        "ALICE_PRIVATE_KEY": key_to_pem_str(alice_priv, is_private=True),
        "ALICE_CERTIFICATE": alice_cert,

        "BOB_PRIVATE_KEY": key_to_pem_str(bob_priv, is_private=True),
        "BOB_PUBLIC_KEY": key_to_pem_str(bob_pub)
    }

    c = CryptoHelper()
    ca_pk = c.load_pem_public_key(dataset["CA_PUBLIC_KEY"])
    alice_sk = c.load_pem_private_key(dataset["ALICE_PRIVATE_KEY"])
    alice_cert = dataset["ALICE_CERTIFICATE"]
    bob_pk = c.load_pem_public_key(dataset["BOB_PUBLIC_KEY"])
    bob_sk = c.load_pem_private_key(dataset["BOB_PRIVATE_KEY"])

    print("Scenario 1: Successful Login (Alice)")
    a_p = Prover(alice_sk,alice_cert)
    v = Verifier(ca_pk)
    alice_session = v.verify_session(a_p,"nonce_123")
    print(alice_session)
    print()

    print("Scenario 2: Impersonation Attack (Bob)")
    b_p = Prover(bob_sk,alice_cert)
    bob_session = v.verify_session(b_p,"nonce456")
    print(bob_session)

