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


server_prt = 1232
p = 29
q = 47
N = p * q
k = 0
e = generate_e(p, q)
