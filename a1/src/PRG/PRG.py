class PRG:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int):
        """
        Initialize values here
        :param security_parameter: n (from 1ⁿ)
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        """
        # create a pesudo reandom generator using discrete logarithm
        # and the given parameters
        self.security_parameter = security_parameter
        self.g = generator
        self.p = prime_field
        self.l = expansion_factor

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from `seed`
        :param seed: uniformly sampled seed
        :type seed: int
        """
        x_0 = seed
        output = ""
        for i in range(self.l):
            output += "0" if x_0 < (self.p - 1) // 2 else "1"
            x_i = pow(self.g, x_0, self.p)
            x_0 = x_i
        return output

# 00100101010
# 00010010101 p>>1
