from ..CPA.CPA import CPA
from ..CBC_MAC.CBC_MAC import CBC_MAC

from typing import Optional
from typing import List


class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: List[int],
                 cpa_mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int`
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: int
        """
        self.n = security_parameter
        self.g = generator
        self.p = prime_field
        self.mac_keys = key_mac
        self.cpa_key = key_cpa
        self.cpa = CPA(security_parameter, prime_field, generator, key_cpa)

    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack

        :param message: m
        :type message: str
        :param cpa_random_seed: s
        :type cpa_random_seed: int
        """
        l = len(message) // self.n
        mac = CBC_MAC(self.n, self.g, self.p, l, self.mac_keys)
        e = self.cpa.enc(message, cpa_random_seed)
        t = mac.mac(e)
        t = bin(t)[2:].zfill(self.n)
        return e + t

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        """
        c = cipher[:-self.n]
        t = cipher[-self.n:]
        l = len(c) // self.n
        mac = CBC_MAC(self.n, self.g, self.p, l, self.mac_keys)
        if mac.vrfy(c, int(t, 2)):
            return self.cpa.dec(c)
