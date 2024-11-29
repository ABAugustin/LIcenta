from Headers.headers import *
from Packages.GenerateCerts import *


def send_certificate(server_socket, cert_dir, cert_file):
    cert_file_path = cert_dir + cert_file

    try:
        # Read the certificate
        with open(cert_file_path, 'rb') as f:
            certificate_data = f.read()

        # Send the length of the certificate as 4 bytes (big-endian)
        server_socket.sendall(struct.pack("!I", len(certificate_data)))

        # Send the certificate data
        server_socket.sendall(certificate_data)

        print("Certificate sent successfully.")
    except Exception as e:
        print(f"Error sending certificate: {e}")


def receive_certificate(server_socket, cert_dir, cert_file):
    cert_file_path = os.path.join(cert_dir, cert_file)
    with open(cert_file_path, 'wb') as f:
        while True:
            data = server_socket.recv(1024)
            if not data:
                break
            f.write(data)
    print("Client certificate sent to server")

def clear_buffer(client_socket):
    client_socket.settimeout(0.1)  # Set a short timeout to avoid blocking
    try:
        while True:
            leftover = client_socket.recv(1024)
            if not leftover:
                break
    except socket.timeout:
        pass  # Expected timeout, as no more data is incoming
    finally:
        client_socket.settimeout(None)  # Reset timeout to default

def send_data(client_socket, data):
    try:
        data_length = struct.pack("!I", len(data))
        client_socket.sendall(data_length)
        client_socket.sendall(data)
        print(f"Data of size {len(data)} bytes sent successfully.")
    except Exception as e:
        print(f"Error sending data: {e}")

def receive_data(client_socket):
    try:
        data_length_bytes = client_socket.recv(4)
        if not data_length_bytes:
            print("No data length received, connection closed.")
            return None

        data_length = struct.unpack("!I", data_length_bytes)[0]
        data = b""
        while len(data) < data_length:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            data += chunk

        print(f"Data of size {len(data)} bytes received successfully.")
        return data
    except Exception as e:
        print(f"Error receiving data: {e}")
        return None