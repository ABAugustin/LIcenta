import os
from Packages.Headers.headers import g_dh,p_dh


def dh_generate_private_key():
    # Generate a random private key in the range [1, p-1]
    return int.from_bytes(os.urandom(64), "big") % p_dh

def dh_generate_public_key(private_key):
    # Calculate public key as g^private_key mod p
    return pow(g_dh, private_key, p_dh)

def compute_shared_secret(public_key, private_key):
    return pow(public_key, private_key, p_dh)