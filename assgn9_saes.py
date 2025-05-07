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
            ['1', '7', '8', 'F'],
            ['6', '0', '2', '3'],
            ['C', '4', 'D', 'E'],
        ]
        self.rcon = ['-_-', '10000000','00110000'] #R0,R1,R2. R0 is of no use
        self.key = key  # 16-bit binary string
        self.irreducible_polynomial = 0b10011
        self.key_list = self.generate_keys(self.key)
        self.mix_column_matrix = [ [1, 4], [4, 1] ]
        self.inv_mix_column_matrix = [ [9, 2], [2, 9] ]

    def xor(self, a, b, type='016b'):
        return format(int(a, 2) ^ int(b, 2), type)

    def rot_word(self, word):
        return word[4:] + word[:4]

    def generate_keys(self, key_bin):
        w = [key_bin[:8], key_bin[8:]] 
        for i in range(2, 6):
            if i % 2 == 0:
                temp = self.sub_nib(self.rot_word(w[i - 1]), self.s_box, 8)
                t = self.xor(temp, self.rcon[i // 2], '08b')
                wi = self.xor(t, w[i - 2], '08b')
            else:
                wi = self.xor(w[i - 1], w[i - 2], '08b')
            w.append(wi)
        round_keys = [w[0] + w[1], w[2] + w[3], w[4] + w[5]]
        return round_keys

    def sub_nib(self, state, sbox, bin_str_len=16):
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
        return n[0] + n[3] + n[2] + n[1]  # left shift when encrypting and right shift when decrypting. But since we are on a 2*2 matrix, both left shift and right shift have the same effect

    def gf_mult(self, a, b):
        product = 0
        a = a & 0xF
        b = b & 0xF
        while a and b:
            if b & 1:
                product = product ^ a
            a = a << 1
            if a & (1 << 4):
                a = a ^ self.irreducible_polynomial
            b = b >> 1
        return product

    def mix_columns(self, state, mc):
        n = []
        for i in range(0, 16, 4):
            num = int(state[i:i + 4], 2)
            n.append(num)
        result =  [
            self.gf_mult(mc[0][0], n[0]) ^ self.gf_mult(mc[0][1], n[1]),
            self.gf_mult(mc[1][0], n[0]) ^ self.gf_mult(mc[1][1], n[1]),
            self.gf_mult(mc[0][0], n[2]) ^ self.gf_mult(mc[0][1], n[3]),
            self.gf_mult(mc[1][0], n[2]) ^ self.gf_mult(mc[1][1], n[3]),
        ]
        return ''.join(format(n, '04b') for n in result)

    def add_round_key(self, state, key):
        return self.xor(state, key)

    def encrypt(self, plaintext):
        state = self.add_round_key(plaintext, self.key_list[0])
        state = self.sub_nib(state, self.s_box)
        state = self.shift_rows(state)
        state = self.mix_columns(state, self.mix_column_matrix)
        state = self.add_round_key(state, self.key_list[1])
        state = self.sub_nib(state, self.s_box)
        state = self.shift_rows(state)
        ciphertext = self.add_round_key(state, self.key_list[2])
        return ciphertext

    def decrypt(self, ciphertext):
        state = self.add_round_key(ciphertext, self.key_list[2])
        state = self.shift_rows(state)
        state = self.sub_nib(state, self.inv_s_box)
        state = self.add_round_key(state, self.key_list[1])
        state = self.mix_columns(state, self.inv_mix_column_matrix)
        state = self.shift_rows(state)
        state = self.sub_nib(state, self.inv_s_box)
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