from SHA1 import SHA1

class HMAC():
    def __init__(self, hasher, key):
        ''' HMAC comstruction class'''
        self.hasher = hasher()
        self.key = key
        self.bin_key = self.ascii2bin(self.key)
        self.hash_inp_length = 512
        self.ipad = '00110110'*64
        self.opad = '01011100'*64
        self.key_ = '0'*(self.hash_inp_length - len(self.bin_key)) + self.bin_key


    def ascii2bin(self, string):
        '''Convert ascii string to bitstring'''
        return ''.join('{:08b}'.format(ord(char)) for char in string)

    def bin2ascii(self, bn):
        '''Converts binary bitstring to ascii'''
        return ''.join([chr(int(bn[i:i+8], 2)) for i in range(0, len(bn), 8)])

    def hex2bin(self, hx):
        '''Converts hex string to binary string'''
        return ''.join('{:04b}'.format(int(h, 16)) for h in hx)

    def xor_2(self, a, b):
        '''Compute XOR value of given two binary strings'''
        return ''.join(['0' if x == y else '1' for x, y in zip(a, b)])


    def xor(self, *words):
        '''Compute XOR of multiple binary words'''
        first, *words = words
        res = first
        for word in words:
            res = self.xor_2(res, word)
        assert len(res) == len(first)
        return res

    def inner_hash(self):
        '''Compute inner HMAC with ipad'''
        hash_this = self.xor(self.key_, self.ipad)
        # hash_this will be in binary
        hash_this = self.bin2ascii(hash_this) + self.message
        # self.hasher returns hashed output in hex
        return self.hex2bin(self.hasher.compute_hash(hash_this))

    def compute_hmac(self, message):
        '''Compute HMAC of given message'''
        self.message = message
        inner_hashed = self.inner_hash()
        hash_this = self.xor(self.key_, self.opad)
        hash_this = self.bin2ascii(hash_this) + self.bin2ascii(inner_hashed)
        return self.hasher.compute_hash(hash_this)


if __name__ == '__main__':
    hmac = HMAC(SHA1, 'secret_key')      # initializing HMAC object with hasher and password

    test_these = [  'hello world',
                    'Hello world',
                    'hello World',
                    'Hello World']

    for word in test_these:
        print(word, hmac.compute_hmac(word))
