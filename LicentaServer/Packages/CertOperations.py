import x509

from Packages.Headers.headers import *


def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data)

    return cert



