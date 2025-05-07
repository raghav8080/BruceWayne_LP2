class SDES:
    def __init__(self, key):
        self.P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
        self.P8 = [5, 2, 6, 3, 7, 4, 9, 8]
        self.IP = [1, 5, 2, 0, 3, 7, 4, 6]
        self.IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]
        self.EP = [3, 0, 1, 2, 1, 2, 3, 0]
        self.P4 = [1, 3, 2, 0]
        self.S0 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]
        self.S1 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]
        self.key = key
        self.key_list = self.generate_keys()

    def permute(self, bits, pattern):
        return ''.join(bits[i] for i in pattern)

    def left_shift(self, bits, n):
        return bits[n:] + bits[:n]

    def xor(self, a, b, type='04b'):
        return format(int(a, 2) ^ int(b, 2), type)

    def substitute(self, bits, sbox):
        row = int(bits[0]) * 2 + int(bits[3])
        col = int(bits[1]) * 2 + int(bits[2])
        val = sbox[row][col] # for eg. val=2 (10)
        return format(val, '02b') # use format() when you want to convert an integer to a binary string with fixed length
        # returns '10'

    def generate_keys(self):
        perm_key = self.permute(self.key, self.P10)
        left = perm_key[:5]
        right = perm_key[5:]

        left1 = self.left_shift(left, 1)
        right1 = self.left_shift(right, 1)
        k1 = self.permute(left1 + right1, self.P8)

        left2 = self.left_shift(left1, 2)
        right2 = self.left_shift(right1, 2)
        k2 = self.permute(left2 + right2, self.P8)
        
        return [k1, k2]

    def F(self, R, K):
        expanded = self.permute(R, self.EP)
        xored = self.xor(expanded, K, '08b')
        left, right = xored[:4], xored[4:]
        s0_out = self.substitute(left, self.S0)
        s1_out = self.substitute(right, self.S1)
        combined = s0_out + s1_out
        return self.permute(combined, self.P4)

    def encrypt(self, plaintext):
        ip = self.permute(plaintext, self.IP)
        L0, R0 = ip[:4], ip[4:]

        f1 = self.F(R0, self.key_list[0]) # key_list[0] is K1
        R1 = self.xor(L0, f1)
        L1 = R0
        # L1, R1 = R1, L1 # swapped

        f2 = self.F(R1, self.key_list[1]) # key_list[1] is K2
        L2 = self.xor(L1, f2)
        R2 = R1
        # L2, R2 = R2, L2 #  no swapping for round 2

        preoutput = L2 + R2
        return self.permute(preoutput, self.IP_inv)

    def decrypt(self, ciphertext):
        ip = self.permute(ciphertext, self.IP)
        L0, R0 = ip[:4], ip[4:]

        f1 = self.F(R0, self.key_list[1]) # K2
        L1 = self.xor(L0, f1)
        R1 = R0
        L1, R1 = R1, L1 # swapped

        f2 = self.F(R1, self.key_list[0]) # K1
        L2 = self.xor(L1, f2)
        R2 = R1
        # L2, R2 = R2, L2 #  no swapping for round 2

        preoutput = L2 + R2
        return self.permute(preoutput, self.IP_inv)

key = '1100011110' # 10-bit key
plaintext = '00101000' # 8-bit plaintext

sdes = SDES(key)
ciphertext = sdes.encrypt(plaintext)
decrypted = sdes.decrypt(ciphertext)

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted :", decrypted)