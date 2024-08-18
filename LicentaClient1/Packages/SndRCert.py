from Headers.headers import *


def receive_certificate(server_socket, cert_dir, cert_file):
    cert_file_path = os.path.join(cert_dir, cert_file)
    with open(cert_file_path, 'wb') as f:
        while True:
            data = server_socket.recv(1024)
            if not data:
                break
            f.write(data)
    print("Server certificate received and saved")


def send_certificate(server_socket, cert_dir, cert_file):
    cert_file_path = cert_dir + cert_file
    with open(cert_file_path, 'rb') as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            server_socket.sendall(data)
    server_socket.shutdown(socket.SHUT_WR)
    print("Client certificate sent to server")
