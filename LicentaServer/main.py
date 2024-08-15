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

p = 29
q = 47
N = p * q
k = 0


def send_certificate(client_socket, cert_dir,user_id):

    #create certificate path ... to be changed
    cert_file ="user_"+str(user_id + 1)+"_cert.pem"
    cert_file_path = os.path.join(cert_dir, cert_file)
    #if certificate doesnt exist, create one

    if not os.path.exists(cert_file_path):
        generate_greeting_certificate_for_user_N(cert_dir,user_id)

    # sending the certificate over to the client
    with open(cert_file_path, 'rb') as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            client_socket.sendall(data)
    print("Server certificate sent to client")

def receive_certificate(client_socket, cert_dir, cert_file="received_client_certificate.crt"):

    #create certificate path ... to be changed
    cert_file_path = os.path.join(cert_dir, cert_file)

    # create and write recv certificate data
    with open(cert_file_path, 'wb') as f:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            f.write(data)
    print("Client certificate received and saved")

def generate_greeting_certificate_for_user_N(cert_dir, user_id):
    user_id += 1

    #generate private key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA,2048)

    #create certificate

    # basic inputs
    cert = crypto.X509()
    cert.get_subject().C = "RO"
    cert.get_subject().ST = "Iasi"
    cert.get_subject().L = "Iasi"
    cert.get_subject().OU = "Licenta"
    cert.get_subject().CN = "tuiasi.ro"

    #custom inputs for RSA as extensions

    #create OIDS for e and n

    oid_custom_e = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.1")
    oid_custom_n = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.2")

    e_rsa = generate_e(p, q)
    n_rsa = N

    #create extensions per RSA
    extensions = [
        x509.Extension(oid_custom_e, False, x509.Integer(e_rsa)),
        x509.Extension(oid_custom_n, False, x509.Integer(n_rsa))
    ]
    #add extensions
    for ext in extensions:
        cert.add_extensions([
            crypto.X509Extension(ext.oid.dotted_string.encode('ascii'), False, str(ext.value).encode('ascii'))
        ])

    #the rest...
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    # Save the private key and certificate to files
    with open("private_key_"+user_id+".pem", "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open("certificate_"+user_id+".pem", "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    print("Private key and certificate with integer extensions created successfully.")

    return user_id

def start_server(cert_dir, host='0.0.0.0', port=12345,user_id = k):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1000)

    print(f"Server listening on {host}:{port}")


    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    #send greeting certificate
    send_certificate(client_socket, cert_dir, user_id)

    #receive rsa encrypted certificate
    #receive_certificate(client_socket, cert_dir)

    client_socket.close()

if __name__ == '__main__':

    start_server('/home/augu/PycharmProjects/LicentaServer/Certificates')