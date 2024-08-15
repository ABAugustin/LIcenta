import os
import threading
import socket
from OpenSSL import crypto
from cryptography import x509

from RSA import *

#def generate_encrypted_client_certificate():


#def extract_rsa_data_and_create_certificate():

def receive_certificate_from_server(server_socket, cert_dir, cert_file="received_server_certificate.crt"):
    cert_file_path = os.path.join(cert_dir, cert_file)
    with open(cert_file_path, 'wb') as f:
        while True:
            data = server_socket.recv(1024)
            if not data:
                break
            f.write(data)
    print("Server certificate received and saved")


def send_certificate_to_server(server_socket, cert_dir, cert_file="client_certificate.crt"):
    cert_file_path = os.path.join(cert_dir, cert_file)

    #if not os.path.exists(cert_file_path):
        #generate_encrypted_client_certificate()
    with open(cert_file_path, 'rb') as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            server_socket.sendall(data)
    print("Client certificate sent to server")

def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    return cert

def extract_rsa_data(cert_path):

    cert = load_certificate(cert_path)
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        print(ext.__str__())
    return None


def connect_to_server(server_ip, server_port, cert_dir):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.connect((server_ip, server_port))
        print(f"Connected to server at {server_ip}:{server_port}")

        # Receive server certificate
        receive_certificate_from_server(server_socket, cert_dir)

        extract_rsa_data("/home/augu/PycharmProjects/LicentaClient1/Certificates/received_server_certificate.crt")

        # Send client certificate
       # send_certificate_to_server(server_socket, cert_dir)

if __name__ == '__main__':
    connect_to_server(
        server_ip="0.0.0.0",
        server_port=12345,
        cert_dir="/home/augu/PycharmProjects/LicentaClient1/Certificates"
    )

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
