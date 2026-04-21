from Crypto.Util.number import inverse, long_to_bytes
from sympy import factorint

"""
RSA walkthrough with theory links per step:

1) Factoring n into (p, q)
   - Integer factorization: https://en.wikipedia.org/wiki/Integer_factorization
   - RSA security assumption (RSA problem): https://en.wikipedia.org/wiki/RSA_problem

2) Computing ϕ(n) = (p-1)(q-1)
   - Euler's totient function: https://en.wikipedia.org/wiki/Euler%27s_totient_function
   - RSA (cryptosystem) overview: https://en.wikipedia.org/wiki/RSA_(cryptosystem)

3) Computing d = e^{-1} mod ϕ(n)
   - Modular multiplicative inverse: https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
   - Extended Euclidean algorithm (how inverses are found): https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

4) Decrypting m = c^d mod n
   - RSA decryption relation: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
   - Modular exponentiation: https://en.wikipedia.org/wiki/Modular_exponentiation

5) Converting integer m to bytes / text
   - PyCryptodome long_to_bytes: http://pycryptodome-master.readthedocs.io/en/latest/src/util/util.html
   - Endianness / big-endian representation: https://en.wikipedia.org/wiki/Endianness
   - UTF-8 (common default for decode): https://en.wikipedia.org/wiki/UTF-8
"""


def main() -> None:
    # Given values
    n = 43941819371451617899582143885098799360907134939870946637129466519309346255747

    # Step 1: Factor n to recover p and q (breaks RSA if n is factorable).
    # Uncomment two lines bellow to use factorint result
    # factors = factorint(n)
    # p, q = list(factors)
    p = 205237461320000835821812139013267110933
    q = 214102333408513040694153189550512987959
    print("Prime factors:")
    print("p =", p)
    print("q =", q)

    # Step 2: Compute Euler's totient for n = p*q: ϕ(n) = (p-1)(q-1).
    phi_n = (p - 1) * (q - 1)
    print("Phi(n) =", phi_n)

    # Step 3: Find the private exponent d as the modular inverse of e modulo ϕ(n).
    e = 65537
    d = inverse(e, phi_n)
    print("Private key (d):", d)

    # Step 4: RSA decryption is modular exponentiation: m = c^d mod n.
    c = 9002431156311360251224219512084136121048022631163334079215596223698721862766
    plaintext = pow(c, d, n)

    # Step 5: Convert the integer message representative to bytes, then decode to text.
    flag = long_to_bytes(plaintext)
    print(flag.decode())
    print("Decrypted Plaintext:", flag)


if __name__ == "__main__":
    main()
