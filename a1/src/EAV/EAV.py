from ..PRG.PRG import PRG


class Eavesdrop:
    def __init__(self, security_parameter: int, key: int, expansion_factor: int,
                 generator: int, prime_field: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param key: k, uniformly sampled key
        :type key: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        """
        self.n = security_parameter
        self.k = key
        self.l = expansion_factor
        self.prg = PRG(self.n, generator, prime_field, self.l)
        self.g = self.prg.generate(self.k).zfill(self.l)

    def enc(self, message: str) -> str:
        """
        Encrypt Message against Eavesdropper Adversary
        :param message: message encoded as bit-string
        :type message: str
        """
        assert (len(message) == self.l)
        c = [str(int(self.g[i]) ^ int(message[i])) for i in range(self.l)]
        return ''.join(c)

    def dec(self, cipher: str) -> str:
        """
        Decipher ciphertext
        :param cipher: ciphertext encoded as bit-string
        :type cipher: str
        """
        assert (len(cipher) == self.l)
        m = [str(int(self.g[i]) ^ int(cipher[i])) for i in range(self.l)]
        return ''.join(m)
