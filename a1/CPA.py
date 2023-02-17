from .PRF import PRF


class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        """
        self.n = security_parameter
        self.p = prime_field
        self.g = generator
        self.k = key
        self.prf = PRF(security_parameter, generator, prime_field, key)

    def enc(self, message: int, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack
        :param message: m
        :type message: int
        :param random_seed: r
        :type random_seed: int
        """
        r = bin(self.prf.evaluate(random_seed))[2:].zfill(self.n)
        m = bin(message)[2:].zfill(self.n)
        c = [str(int(m[i]) ^ int(r[i])) for i in range(self.n)]
        c = ''.join(c)
        return c

    def dec(self, cipher: str, random_seed: int) -> int:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        r = bin(self.prf.evaluate(random_seed))[2:].zfill(self.n)
        m = [str(int(cipher[i]) ^ int(r[i])) for i in range(self.n)]
        m = ''.join(m)
        return int(m, 2)

