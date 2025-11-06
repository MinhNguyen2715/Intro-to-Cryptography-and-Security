import pandas as pd
import sys
sys.setrecursionlimit(5000)

def extended_euclid(a, b):
    res = []
    def eea(a, b):
        if b == 0:
            res.append([a, b, "-", a, 1, 0])
            return a,1,0

        else:
            d_prime, x_prime, y_prime = eea(b, a % b)
            d = d_prime
            x = y_prime
            y = x_prime - (a//b) * y_prime
            res.append([a,b,a//b,d,x,y])
            return d,x,y

    d,x,y = eea(a,b)
    res.reverse()
    return d,x,y,res

def mod_inv(a,n):
    d, x, y, res = extended_euclid(a, n)
    if d != 1:
        raise ValueError(f"The modular inverse of {a} modulo {n} does not exist")
    else:
        return x%n

def mod_exp(a,b,n):
    a %= n
    if b == 0:
        return 1
    elif b == 1:
        return a
    r = mod_exp(a,b//2,n)
    r = (r*r) % n
    if b%2 == 1:
        r = (r*a) % n
    return r

def mod_exp2(a, b, n):
    result = 1
    a %= n
    while b > 0:
        if b & 1: # bitwise AND for LSB
            result = (result * a) % n
        a = (a * a) % n
        b >>= 1
    return result

def mod_exp3(a, b, n):
    result = 1
    a %= n
    for i in range(b.bit_length(),-1,-1):
        result = (result*result) % n
        if (b >> i) & 1:
            result = (result * a) % n
    return result

if __name__ == "__main__":
    # EEA
    first = 5
    second = 12
    d, x, y, res = extended_euclid(first, second)

    df = pd.DataFrame(res, columns=["a", "b", "a//b", "d", "x", "y"])
    print(df)

    # Modular inverse
    a = 340282366920938463463374607431768211457
    n = 6277101735386680763835789423207666416102355444464034512896
    print(mod_inv(a,n))

    # Modular exponential
    a = 340282366920938463463374607431768211457
    b = (1 << 2048) + (1 << 1024) + 65537 # = 2^2048 + 2^1024 + 65537
    n = 6277101735386680763835789423207666416102355444464034512896

    print(mod_exp(a, b, n))
    # Checking
    print(pow(a, b, n))

