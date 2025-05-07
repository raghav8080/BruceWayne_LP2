def pad_text(text, total_length, pad_char='_'):
    return text + pad_char * (total_length - len(text))

def matrix_fill(text, key):
    cols = len(key)
    rows = -(-len(text) // cols)  # Ceiling division
    padded_text = pad_text(text, rows * cols)
    matrix = [list(padded_text[i*cols:(i+1)*cols]) for i in range(rows)]
    return matrix

def get_column_order(key):
    return sorted(range(len(key)), key=lambda i: key[i])

def single_columnar_encrypt(text, key):
    matrix = matrix_fill(text, key)
    order = get_column_order(key)
    cipher = ''
    for col_idx in order:
        for row in matrix:
            cipher += row[col_idx]
    return cipher

def single_columnar_decrypt(cipher, key):
    cols = len(key)
    rows = len(cipher) // cols
    order = get_column_order(key)

    # Create empty matrix
    matrix = [['' for _ in range(cols)] for _ in range(rows)]

    # Fill columns by order
    k = 0
    for i in range(cols):
        col_idx = order[i]
        for row in range(rows):
            matrix[row][col_idx] = cipher[k]
            k += 1

    # Read row-wise
    plaintext = ''.join(''.join(row) for row in matrix)
    return plaintext.rstrip('_')

def double_columnar_encrypt(text, key1, key2):
    once = single_columnar_encrypt(text, key1)
    return single_columnar_encrypt(once, key2)

def double_columnar_decrypt(cipher, key1, key2):
    once = single_columnar_decrypt(cipher, key2)
    return single_columnar_decrypt(once, key1)

# === Sample Test ===
if __name__ == '__main__':
    plaintext = "we are the best"
    key1 = "heaven"
    key2 = "another"

    print("Original:", plaintext)

    # Single Transposition
    st_cipher = single_columnar_encrypt(plaintext, key1)
    print("Single Transposition Encrypted:", st_cipher)
    print("Decrypted:", single_columnar_decrypt(st_cipher, key1))

    # Double Transposition
    dt_cipher = double_columnar_encrypt(plaintext, key1, key2)
    print("Double Transposition Encrypted:", dt_cipher)
    print("Decrypted:", double_columnar_decrypt(dt_cipher, key1, key2))
