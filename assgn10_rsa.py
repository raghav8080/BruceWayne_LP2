import random

def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    # Calculate d, the modular inverse of e mod phi(n)
    d = mod_inverse(e, phi)

    # Return public and private keypair
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    encrypted_msg = [pow(ord(char), e, n) for char in plaintext]
    return encrypted_msg

def decrypt(private_key, encrypted_msg):
    d, n = private_key
    decrypted_msg = [chr(pow(char, d, n)) for char in encrypted_msg]
    return ''.join(decrypted_msg)

# Example usage:
if __name__ == "__main__":
    while(True):
        p = int(input("Enter P:"))
        if is_prime(p):
           break
    while(True):
        q = int(input("Enter Q:"))
        if is_prime(q):
           break
    public_key, private_key = generate_keypair(p, q)
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    message = input("Enter the message:")
    print("Original Message:", message)

    encrypted_message = encrypt(public_key, message)
    print("Encrypted Message:", encrypted_message)

    decrypted_message = decrypt(private_key, encrypted_message)
    print("Decrypted Message:", decrypted_message)