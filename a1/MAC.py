from .PRF import PRF
from typing import Tuple


class MAC:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, seed: int):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param seed: k
        :type seed: int
        """
        self.prf = PRF(security_parameter, generator, prime_field, seed)
        assert (security_parameter % 4) == 0
        self.n = security_parameter

    def get_blocks(self, message: str, blocksize: int) -> list:
        """
        Split the message into blocks of size n/4
        :param message: m
        :type message: str
        """
        blocks = [message[i:i + blocksize]
                  for i in range(0, len(message), blocksize)]
        if len(blocks[-1]) < blocksize:
            blocks[-1].ljust(blocksize, '0')
        return blocks

    def mac(self, message: str, random_identifier: int) -> str:
        """
        Generate tag t
        :param random_identifier: r
        :type random_identifier: int
        :param message: message encoded as bit-string
        :type message: str
        """
        l = len(message)
        blocksize = self.n // 4
        blocks = self.get_blocks(message, blocksize)
        r = bin(random_identifier)[2:].zfill(blocksize)
        d = bin(len(blocks))[2:].zfill(blocksize)
        t = r
        for it, block in enumerate(blocks):
            i = bin(it)[2:].zfill(blocksize)
            newblock = r + d + i + block
            fb = self.prf.evaluate(int(newblock, 2))
            t = t + bin(fb)[2:].zfill(self.n)
        return t

    def vrfy(self, message: str, tag: str) -> bool:
        """
        Verify whether the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """
        blocksize = self.n // 4
        blocks = self.get_blocks(message, blocksize)
        r = tag[:blocksize]
        tag = tag[blocksize:]
        tags = [tag[i:i + self.n] for i in range(0, len(tag), self.n)]
        d = bin(len(blocks))[2:].zfill(blocksize)
        for it, block in enumerate(blocks):
            i = bin(it)[2:].zfill(blocksize)
            newblock = r + d + i + block
            fb = self.prf.evaluate(int(newblock, 2))
            if bin(fb)[2:].zfill(self.n) != tags[it]:
                return False
        return True
