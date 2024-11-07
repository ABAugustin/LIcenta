import os
import threading
import socket
from OpenSSL import crypto
from RSA import *
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta
import pymongo
import threading

# Prime and generator as specified in RFC 3526, 2048-bit MODP Group #14
p_dh = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404D"
        "DEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C2"
        "45E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
g_dh = 2  # The generator for this group is typically 2



server_prt = 1232
p = 29
q = 47
N = p * q
k = 0
e = generate_e(p, q)
