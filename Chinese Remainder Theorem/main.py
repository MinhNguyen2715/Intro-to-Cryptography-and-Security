import sys, timeit
sys.setrecursionlimit(5000)

def extended_euclid(a, b):
    if b == 0:
            return a,1,0
    else:
        d_prime, x_prime, y_prime = extended_euclid(b, a % b)
        d = d_prime
        x = y_prime
        y = x_prime - (a//b) * y_prime
        return d,x,y

def mod_inv(a,n):
    d, x, y = extended_euclid(a, n)
    if d != 1:
        raise ValueError(f"The modular inverse of {a} modulo {n} does not exist")
    else:
        return x%n

def rsa_decrypt(a,b,n): # Normal RSA
    a %= n
    if b == 0:
        return 1
    elif b == 1:
        return a
    r = rsa_decrypt(a,b//2,n)
    r = (r*r) % n
    if b%2 == 1:
        r = (r*a) % n
    return r

def rsa_decrypt_crt(y, d, p, q):
    # Transformation to the CRT Domain
    y_p = y % p
    y_q = y % q

    # Exponentiation in the CRT Domain
    d_p = d % (p-1)
    d_q = d % (q-1)

    x_p = rsa_decrypt(y_p, d_p, p)
    x_q = rsa_decrypt(y_q, d_q, q)

    # Inverse Transformation (Recombination)
    c_p = mod_inv(q,p)
    c_q = mod_inv(p,q)
    x = ((q*c_p)*x_p + (p*c_q)*x_q) % (p*q)

    return x

def generate_rsa_keys(p, q, e=65537):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inv(e, phi)
    return n, e, d

if __name__ == "__main__":
    def test_large(p, q, y):
        n,e,d = generate_rsa_keys(p,q)

        print("Large primes")
        print(f"p = {p} \nq = {q} \nd = {d} \ny = {y}")
        print("Normal:", timeit.timeit(lambda: rsa_decrypt(y, d, n), number=100))
        print("CRT   :", timeit.timeit(lambda: rsa_decrypt_crt(y, d, p, q), number=100))
        print()

    def test_small(p, q, y):
        n, e, d = generate_rsa_keys(p, q)

        print("Small primes:")
        print(f"p = {p} \nq = {q} \nd = {d} \ny = {y}")
        print("Normal:", timeit.timeit(lambda: rsa_decrypt(y, d, n), number=100))
        print("CRT   :", timeit.timeit(lambda: rsa_decrypt_crt(y, d, p, q), number=100))
        print()

    test_data_small = [1234567890123456789012345686998765432109876543210987654347, 9876543210987654321098765432312345678901234567890123456887, 1234567890123456789074210561205601326503650]

    test_data_large = [
675396536902650684056720485602509939728587661796715084085667433389879726656744315347168370445021924831594801005792227502567369722817839756055300498126113077545760765648363127338284030508700959764961070707658375942531467936150680537080369558278866854030604940793042456294445702529125036927224999993007,
807598540975055226792556370648134825414020828011935532123742715984753410293186573518995494571328631044029394542556352230735365689988665897126079184290983975020420208227584847477115865942927702104721931735003907148416696118747630537041942314340434076603552924583623369516835774723284468285190528378881,
2739730260265669309592286752770118779080529719185423722564305255937687730016596090138709799614069881729378743536172450025213728873318682909042036750764469655206500570121669762602939719933756760910760072409531488952002277033340106120860787231925409092]

    test_small(*test_data_small)
    test_large(*test_data_large)

