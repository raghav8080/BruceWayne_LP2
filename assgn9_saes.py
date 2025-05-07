class SAES:
    def __init__(self, key):
        self.s_box = [
            ['9', '4', 'A', 'B'],
            ['D', '1', '8', '5'],
            ['6', '2', '0', '3'],
            ['C', 'E', 'F', '7'],
        ]
        self.inv_s_box = [
            ['A', '5', '9', 'B'],
            ['1', '7', '8', '5'],
            ['6', '0', '2', '3'],
            ['C', '4', 'D', 'E'],
        ]
        self.M = [['1', '4'], ['4', '1']]  # MixColumn matrix
        self.M_inv = [['-1', '4'], ['4', '-1']] #InvMixColumn matrix
        self.rcon = ['00000000', '10000000','00110000'] #R0,R1,R2
        self.key = key  # 16-bit binary string
        self.key_list = self.generate_keys(self.key)

    def xor(self, a, b, type='016b'):
        return format(int(a, 2) ^ int(b, 2), type)

    def rot_word(self, word):
        return word[4:] + word[:4]

    def sub_word(self, word, sbox):
        return self.nibble_substitution(word, sbox, 8)

    def generate_keys(self, key_bin):
        w = [key_bin[:8], key_bin[8:]] 
        for i in range(2, 6):
            if i % 2 == 0:
                temp = self.sub_word(self.rot_word(w[i - 1]), self.s_box)
                t = self.xor(temp, self.rcon[i // 2], '08b')
                wi = self.xor(t, w[i - 2], '08b')
            else:
                wi = self.xor(w[i - 1], w[i - 2], '08b')
            w.append(wi)
        round_keys = [w[0] + w[1], w[2] + w[3], w[4] + w[5]]
        return round_keys

    def nibble_substitution(self, state, sbox, bin_str_len=16):
        result = ''
        for i in range(0, bin_str_len, 4):
            nibble = state[i:i + 4]  # extract 4 bits
            row_bits = nibble[0:2]   # first 2 bits
            col_bits = nibble[2:4]   # last 2 bits
            
            row = int(row_bits, 2)   # convert to integer
            col = int(col_bits, 2)
            
            hex_value_string = sbox[row][col]   # lookup in the s-box
            binary_value = format(int(hex_value_string, 16), '04b')  # convert back to 4-bit binary string

            result += binary_value  # append to the result string
        return result

    def shift_rows(self, state):
        n = []
        for i in range(0, 16, 4):
            n.append(state[i:i + 4])
        return n[0] + n[3] + n[2] + n[1]  # left shift when encrypting

    def inv_shift_rows(self, state):
        n = []
        for i in range(0, 16, 4):
            n.append(state[i:i + 4])
        return n[0] + n[3] + n[2] + n[1]  # right shift when decrypting

    def gf_mult(self, a, b):
        """Galois field multiplication of a and b in GF(2^4) / x^4 + x + 1
        :param a: First number
        :param b: Second number
        :returns: Multiplication of both under GF(2^4)
        """
        # Initialise
        product = 0

        # Mask the unwanted bits
        a = a & 0x0F
        b = b & 0x0F

        # While both multiplicands are non-zero
        while a and b:
            # If LSB of b is 1
            if b & 1:
                # Add current a to product
                product = product ^ a

            # Update a to a * 2
            a = a << 1

            # If a overflows beyond 4th bit
            if a & (1 << 4):

                # XOR with irreducible polynomial with high term eliminated
                a = a ^ 0b10011

            # Update b to b // 2
            b = b >> 1

        return product

    def mix_columns(self, state):
        n = []
        for i in range(0, 16, 4):
            num = int(state[i:i + 4], 2)
            n.append(num)
        n[1],n[2] = n[2],n[1]
        result = [
            n[0] ^ self.gf_mult(4, n[2]),
            n[2] ^ self.gf_mult(4, n[0]),
            n[1] ^ self.gf_mult(4, n[3]),
            n[3] ^ self.gf_mult(4, n[1]),
        ]
        return ''.join(format(n, '04b') for n in result)

    def inv_mix_columns(self, state):
        n = []
        for i in range(0, 16, 4):
            num = int(state[i:i + 4], 2)
            n.append(num)
        n[1],n[2] = n[2],n[1]
        result =  [
            self.gf_mult(9, n[0]) ^ self.gf_mult(2, n[2]),
            self.gf_mult(9, n[2]) ^ self.gf_mult(2, n[0]),
            self.gf_mult(9, n[1]) ^ self.gf_mult(2, n[3]),
            self.gf_mult(9, n[3]) ^ self.gf_mult(2, n[1]),
        ]
        return ''.join(format(n, '04b') for n in result)

    def add_round_key(self, state, key):
        return self.xor(state, key)

    def encrypt(self, plaintext):
        state = self.add_round_key(plaintext, self.key_list[0])
        state = self.nibble_substitution(state, self.s_box)
        state = self.shift_rows(state)
        state = self.mix_columns(state)
        state = self.add_round_key(state, self.key_list[1])
        state = self.nibble_substitution(state, self.s_box)
        state = self.shift_rows(state)
        ciphertext = self.add_round_key(state, self.key_list[2])
        return ciphertext

    def decrypt(self, ciphertext):
        state = self.add_round_key(ciphertext, self.key_list[2])
        state = self.inv_shift_rows(state)
        state = self.nibble_substitution(state, self.inv_s_box)
        state = self.add_round_key(state, self.key_list[1])
        state = self.inv_mix_columns(state)
        state = self.inv_shift_rows(state)
        state = self.nibble_substitution(state, self.inv_s_box)
        plaintext = self.add_round_key(state, self.key_list[0])
        return plaintext

key = '0010010001110101'
plaintext = '0001101000100011'
saes = SAES(key)
cipher = saes.encrypt(plaintext)
decrypted = saes.decrypt(cipher)

print("Plaintext:", plaintext)
print("Encrypted:", cipher)
print("Decrypted:", decrypted)