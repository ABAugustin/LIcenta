from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def derive_key(shared_secret):
    num_bytes = (shared_secret.bit_length() + 7) // 8
    byte_array = shared_secret.to_bytes(num_bytes, byteorder='big')
    if len(byte_array) < 32:
        byte_array = byte_array.rjust(32, b'\x00')
    aes_key = byte_array[:32]
    return aes_key

def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext  # Prepend IV to ciphertext for transmission

def decrypt_message(key, ciphertext):
    # Extract the 16-byte IV from the beginning of the ciphertext
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]  # The rest is the actual ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
    return plaintext.decode()  # Return plaintext as a decoded string
