from ..PRF.PRF import PRF


class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.n = security_parameter
        self.k1, self.k2 = keys[0], keys[1]
        self.prf = PRF(self.n, generator, prime_field, self.k1)
        self.prf2 = PRF(self.n, generator, prime_field, self.k2)
        self.l = expansion_factor

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: m (with length l(n).n)
        :type message: str
        """
        blocks = [message[i:i + self.n] for i in range(0, len(message), self.n)]
        t = 0
        for block in blocks:
            ts = bin(t)[2:].zfill(self.n)
            xor = ''.join([str(int(tt) ^ int(b)) for tt, b in zip(ts, block)])
            t = self.prf.evaluate(int(xor, 2))
        return self.prf2.evaluate(t)

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        return self.mac(message) == tag
