import hashlib

class Prover:
    def __init__(self, seed: str, count: int):
        """
        seed (str): secret key
        count (int): initial counter N
        """
        self.seed = seed
        self.count = count

    def hash_once(self, data):
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def hash_k_times(self, data, k):
        res = data
        for _ in range(k):
            res = self.hash_once(res)
        return res

    def get_token(self):
        """
        Logic:
          1) t = Hash^(count)(seed)
          2) count -= 1
          3) return t
        """

        t = self.hash_k_times(self.seed, self.count)
        self.count -= 1
        return t.hex() if type(t) != str else t

    def prepare_reseed(self, new_seed, new_count):
        """
        Logic:
            1. Generate 'auth_token' using get_token() (from the OLD chain).
            2. Calculate 'new_anchor' = Hash^(new_count + 1)(new_seed).
            3. Update self.seed and self.count to the NEW values.
            4. Return (auth_token, new_anchor).
        """
        auth_token = self.get_token()  # OLD chain token (hex-string)
        new_anchor = self.hash_k_times(new_seed, new_count + 1)

        # switch to new chain
        self.seed = new_seed
        self.count = new_count

        return auth_token, new_anchor

class Verifier:
    def __init__(self, initial_vk):
        """
        Input:
            initial_vk (str): The initial verification key H^(N+1)(k).
        """
        self.vk = initial_vk

    def verify(self, token: str) -> bool:
        """
        Logic:
            1. Compute h = SHA256(token).
            2. Check if h == self.vk.
            3. If True: Update self.vk = token; Return True.
            4. If False: Return False.
        """
        h = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if h == self.vk:
            self.vk = token
            return True
        return False

    def handle_reseed(self, auth_token, new_anchor):
        """
        Logic:
            1. Call self.verify(auth_token).
            2. If returns True:
                Overwrite self.vk = new_anchor.
                Return True.
            3. Else: Return False.
        """
        if self.verify(auth_token):
            self.vk = new_anchor
            return True
        return False


def run_test_case_1():
    seed = "hust"
    n = 2
    h1 = hashlib.sha256(seed.encode()).hexdigest()
    h2 = hashlib.sha256(h1.encode()).hexdigest()
    h3 = hashlib.sha256(h2.encode()).hexdigest()

    print("H1: ",h1)
    print("H2: ",h2)
    print("H3: ",h3)

    p = Prover(seed, n)
    v = Verifier(h3)
    t = p.get_token()

    print("Prover generates: ",t)
    print(v.verify(t))

def run_simulation():
    k = "A"
    n = 5
    p = Prover(k,n)
    h6 = hashlib.sha256(k.encode()).hexdigest()
    for _ in range(n):
        h6 = hashlib.sha256(h6.encode()).hexdigest()

    print("Prover sends H^5:",end=" ")
    t = p.get_token()
    attack = t
    v = Verifier(p.hash_k_times(k,n+1))

    print("Accept" if v.verify(t) else "Reject")

    print("Prover sends H^4:",end=" ")
    t = p.get_token()
    print("Accept" if v.verify(t) else "Reject")

    print("Attacker sends H^5 again:",end=" ")
    print("Accept" if v.verify(attack) else "Reject")

    # Reseed:
    print("\nReseed")
    p = Prover("A", 3)
    v = Verifier(p.hash_k_times("A", 4))

    auth_token, new_anchor = p.prepare_reseed("B", 3)
    print("auth_token:", auth_token)
    print("new_anchor:", new_anchor)

    accepted = v.handle_reseed(auth_token, new_anchor)
    print("reseed accepted?", accepted)

    token_B = p.get_token()
    print("Accept" if v.verify(token_B) else "Reject")

if __name__ == "__main__":
    # Testcase 1:
    print("Testcase 1:")
    run_test_case_1()

    # Testcase 2:
    print("\nTestcase 2:")
    run_simulation()










