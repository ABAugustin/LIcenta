from warnings import catch_warnings

from Headers.headers import *


def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data)
    
    return cert


def get_grt_cert_pkey_and_id(cert):
    # Extract public key
    public_key = cert.public_key()
    user_id = None
    try:
        for ext in cert.extensions:
            oid = ext.oid
            if oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.1"):
                user_id = ext.value.value.decode('utf-8')
    except AttributeError:
        print("Extension Not Found!")
    except ValueError:
        print("Couldnt Decode Extension!")

    return public_key, user_id
