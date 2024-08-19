
import random


def putere(number, power):
    binar = bin(power)
    val = number
    for i in range(3, len(binar)):
        val = val * val
        if binar[i] == '1':
            val = val * number
    return val


def cmmdc(a, b):
    if a == 0:
        return b
    return cmmdc(b % a, a)

def generate_e(p,q):
    N=p*q
    PHI = (p - 1) * (q - 1)
    e = random.randint(1, N)
    while cmmdc(e, PHI) != 1:
        e = random.randint(1, N)

    return e

def rsa_encrypt(N ,e , plaintext):
    encrypted_text = ""
    for char in plaintext:
        encrypted_text += chr(putere(ord(char),e)%N)
    return encrypted_text

def generate_d(p,q,e):
    N = p * q
    PHI = (p - 1) * (q - 1)
    k = 0
    for k in range(1, PHI):
        if ((k * PHI) + 1) % e == 0:
            break
    d = (1 + PHI * k) // e

    return d

def rsa_decrypt(p, q, cyphertext, e):
    N = p * q
    d=generate_d(p,q,e)
    decrypted_text = ''.join([chr((putere(char, d) % N)) for char in cyphertext])
    return decrypted_text

