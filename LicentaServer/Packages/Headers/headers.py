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
import struct

# Prime and generator as specified in RFC 3526, 2048-bit MODP Group #14
p_dh = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
           "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD", 16)
g_dh = 2  # The generator for this group is typically 2



server_prt = 1232

