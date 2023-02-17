from .PRG import PRG


class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.k = key
        self.n = security_parameter
        self.prg = PRG(self.n, generator, prime_field, 2 * self.n)

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        x: str = bin(x)[2:].zfill(self.n)
        print("x", x)
        g_x = self.k
        for i in range(self.n):
            g_x = self.prg.generate(g_x)
            # print(g_x)
            if x[i] == '1':
                g_x = g_x[0:self.n]
            else:
                g_x = g_x[self.n:2*self.n]
            # print(g_x)
            g_x = int(g_x, 2)
        return g_x
