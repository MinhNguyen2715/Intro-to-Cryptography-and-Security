# Explanation of Many-Time Pad Attack

## 🧩 The Many-Time Pad Vulnerability

Suppose we have two ciphertexts $Y_1$ and $Y_2$:

$$
Y_1 = X_1 \oplus K
$$
$$
Y_2 = X_2 \oplus K
$$

If we apply XOR to both ciphertexts:

$$
Y_1 \oplus Y_2 = X_1 \oplus K \oplus X_2 \oplus K = X_1 \oplus X_2
$$

Assume that plaintexts consist only of uppercase letters, lowercase letters, and spaces.  
Consider what happens when two plaintext characters are XORed together:

| ⊕ | A–Z (65–90) | a–z (97–122) | Space (32) |
|:--|:-------------:|:-------------:|:------------:|
| **A–Z (65–90)** | ≤ 32 | ≤ 64 | ≥ 65 |
| **a–z (97–122)** | ≤ 64 | ≤ 32 | ≥ 65 |
| **Space (32)** | ≥ 65 | ≥ 65 | 0 |

*Using ASCII encoding in decimal.*

From the table, we can see that when XORing a **space** with any letter (upper or lower case), the result is a number ≥ 65 — that’s the only case when this happens.

---

## 🧠 Example

Suppose we have three plaintexts:

```
Happy birthday
Crypto is fun
Euler algorithm
```


They are all encrypted with the same key using the **One-Time Pad**.  
We can visualize this by splitting each message into columns:

|   | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **X₁** | H | a | p | p | y | (space) | b | i | r | t | h | d | a | y |   |
| **X₂** | C | r | y | p | t | o | (space) | i | s | (space) | f | u | n |   |   |
| **X₃** | E | u | l | e | r | (space) | a | l | g | o | r | i | t | h | m |

Consider the 10th column:

$$
X_1[9] \oplus X_2[9] = 84
$$
$$
X_2[9] \oplus X_3[9] = 79
$$

We can confirm that $X_2[9]$ is a **space**, which allows us to recover one character of the key:

$$
K[6] = X_0[6] \oplus Y_0[6]
$$

With enough ciphertexts all encrypted using the same key, we can recover the key — or at least partial parts of it — by identifying likely spaces.  
Even if we don’t recover the full key, partial decryption often provides enough clues to deduce the remaining text by hand.

---

## 🧩 Conclusion

The idea behind attacking the **Many-Time Pad** is:

$$
\text{If } X_i[k] \oplus X_j[k] \ge 65 \ \forall i \ne j  
\Rightarrow X_i[k] \text{ or } X_j[k] \text{ is a space.}
$$

---

> **Key insight:**  
> Reusing a One-Time Pad key (the “many-time pad”) breaks perfect secrecy — XORing ciphertexts cancels out the key, revealing direct relationships between plaintexts.
