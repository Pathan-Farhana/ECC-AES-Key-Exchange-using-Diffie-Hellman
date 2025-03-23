import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from sympy import mod_inverse

def scalar_multiply(k, point, a, p):
    if k == 0 or point is None:
        return None
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result

def point_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if P != Q:
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        try:
            m = ((y2 - y1) * mod_inverse(x2 - x1, p)) % p
        except ValueError:
            return None
    else:
        if y1 == 0:
            return None
        try:
            m = ((3 * x1**2 + a) * mod_inverse(2 * y1, p)) % p
        except ValueError:
            return None
    x3 = (m**2 - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def run_ecc_key_exchange(p, a, b, G, label):
    print(f"\nUsing Curve: y^2 = x^3 + {a}x + {b} mod {p} ({label})")
    while True:
        private_key_A = random.randint(1, p-1)
        private_key_B = random.randint(1, p-1)
        public_key_A = scalar_multiply(private_key_A, G, a, p)
        public_key_B = scalar_multiply(private_key_B, G, a, p)
        if public_key_A is not None and public_key_B is not None:
            break
    shared_secret_A = scalar_multiply(private_key_A, public_key_B, a, p)
    shared_secret_B = scalar_multiply(private_key_B, public_key_A, a, p)
    if shared_secret_A is None or shared_secret_B is None:
        raise ValueError("Shared secret computation failed (Point at infinity)")
    assert shared_secret_A == shared_secret_B
    shared_secret = shared_secret_A[0]
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
    message = "Hell0 SRM AP"
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    decipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(decipher.decrypt(ciphertext), AES.block_size).decode()
    print(f"Private Key A: {private_key_A}\nPrivate Key B: {private_key_B}")
    print(f"Public Key A: {public_key_A}\nPublic Key B: {public_key_B}")
    print(f"Shared Secret: {shared_secret}\nAES Key: {aes_key.hex()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}\nDecrypted Message: {decrypted_message}")

curve1 = {'p': 97, 'a': 2, 'b': 3, 'G': (3, 6), 'label': "Curve 1"}
curve2 = {'p': 103, 'a': 1, 'b': 1, 'G': (2, 2), 'label': "Curve 2"}

run_ecc_key_exchange(**curve1)
run_ecc_key_exchange(**curve2)
