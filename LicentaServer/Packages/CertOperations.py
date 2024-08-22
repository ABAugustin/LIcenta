import x509

from Headers.headers import *


def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data)

    return cert


def extract_wg_cert_extension_data(cert_path, cert_file):
    cert = load_certificate(cert_path + cert_file)
    safe_word = ""
    machine_ip = ""
    pub_key = ""
    sub_ip = ""
    port_ip = ""
    told_word = ""
    # Extract extensions
    for ext in cert.extensions:
        oid = ext.oid

        if oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.4"):
            safe_word = ext.value.value.decode('utf-8')
            print("Custom Extension e (OID 1.3.6.1.4.1.11129.2.5.4):", safe_word)

        elif oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.5"):
            machine_ip = ext.value.value.decode('utf-8')
            print("Custom Extension n (OID 1.3.6.1.4.1.11129.2.5.5):", machine_ip)

        elif oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.6"):
            pub_key = ext.value.value.decode('utf-8')
            print("Custom Extension id (OID 1.3.6.1.4.1.11129.2.5.6):", pub_key)

        elif oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.7"):
            sub_ip = ext.value.value.decode('utf-8')
            print("Custom Extension id (OID 1.3.6.1.4.1.11129.2.5.7):", sub_ip)

        elif oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.8"):
            port_ip = ext.value.value.decode('utf-8')
            print("Custom Extension id (OID 1.3.6.1.4.1.11129.2.5.8):", port_ip)

        elif oid == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.5.9"):
            told_word = ext.value.value.decode('utf-8')
            print("Custom Extension id (OID 1.3.6.1.4.1.11129.2.5.9):", told_word)

    safe_word_dec = rsa_decrypt(p,q,safe_word,e)
    machine_ip_dec = rsa_decrypt(p,q,machine_ip,e)
    pub_key_dec = rsa_decrypt(p,q,pub_key,e)
    sub_ip_dec = rsa_decrypt(p,q,sub_ip,e)
    port_ip_dec = rsa_decrypt(p,q,port_ip,e)
    told_word_dec = rsa_decrypt(p, q, told_word, e)

    return safe_word_dec, machine_ip_dec, pub_key_dec, sub_ip_dec, port_ip_dec,told_word_dec

