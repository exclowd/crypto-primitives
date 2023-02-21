from ..PRF.PRF import PRF


class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int, mode="CTR"):
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

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack
        :param message: m
        :type message: int
        :param random_seed: r
        :type random_seed: int
        """
        blocks = [message[i:i + self.n] for i in range(0, len(message), self.n)]
        res = bin(random_seed)[2:].zfill(self.n)
        for i, block in enumerate(blocks):
            seed = (random_seed + i + 1) % (1 << self.n)
            r = bin(self.prf.evaluate(seed))[2:].zfill(self.n)
            c = [str(int(block[i]) ^ int(r[i])) for i in range(self.n)]
            res += ''.join(c)
        return res

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        blocks = [cipher[i:i + self.n] for i in range(self.n, len(cipher), self.n)]
        random_seed = int(cipher[:self.n], 2)
        res = ""
        for i, block in enumerate(blocks):
            seed = (random_seed + i + 1) % (1 << self.n)
            r = bin(self.prf.evaluate(seed))[2:].zfill(self.n)
            c = [str(int(block[i]) ^ int(r[i])) for i in range(self.n)]
            res += ''.join(c)
        return res
