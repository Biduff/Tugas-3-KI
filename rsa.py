import os
import random
import math

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(i):
    length = math.ceil(i.bit_length() / 8)
    if length == 0:
        length = 1
    return i.to_bytes(length, 'big')

def is_prime_miller_rabin(n, k=10):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        is_composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                is_composite = False
                break
        
        if is_composite:
            return False
            
    return True

def generate_prime(bits):
    while True:
        p = int.from_bytes(os.urandom(bits // 8), 'big')
        p |= (1 << (bits - 1)) | 1
        
        if is_prime_miller_rabin(p):
            return p

def mod_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        
        x2 = x1
        x1 = x
        d = y1
        y1 = y
        
    if temp_phi == 1:
        return d + phi

def generate_key_pair(bits):
    print(f"Membuat prime p ({bits//2} bits)...")
    p = generate_prime(bits // 2)
    print(f"Membuat prime q ({bits//2} bits)...")
    q = generate_prime(bits // 2)
    
    while p == q:
        q = generate_prime(bits // 2)
        
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    
    while math.gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)
        
    d = mod_inverse(e, phi)
    
    return ((n, e), (n, d))


def encrypt(public_key, plaintext_bytes):
    n, e = public_key
    m = bytes_to_int(plaintext_bytes)
    
    if m >= n:
        raise ValueError("Pesan terlalu besar untuk dienkripsi")
        
    c = pow(m, e, n)
    return c

def decrypt(private_key, ciphertext_int):
    n, d = private_key
    m = pow(ciphertext_int, d, n)
    return int_to_bytes(m)
