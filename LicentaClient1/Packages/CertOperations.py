
from Headers.headers import *


def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data)

    return cert


def extract_greeting_cert_extension_data(cert_path, cert_file):
    cert = load_certificate(cert_path+cert_file)
    custom_e_value = ""
    custom_n_value = ""
    custom_user_value = ""
    # Extract extensions
    for ext in cert.extensions:
        oid = ext.oid

        if oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.1"):
            custom_e_value = ext.value.value.decode('utf-8')
            print("Custom Extension e (OID 1.3.6.1.4.1.11129.2.5.1):", custom_e_value)
        elif oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.2"):
            custom_n_value = ext.value.value.decode('utf-8')
            print("Custom Extension n (OID 1.3.6.1.4.1.11129.2.5.2):", custom_n_value)
        elif oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.3"):
            custom_user_value = ext.value.value.decode('utf-8')
            print("Custom Extension id (OID 1.3.6.1.4.1.11129.2.5.3):", custom_user_value)

    return int(custom_n_value), int(custom_e_value), int(custom_user_value)
