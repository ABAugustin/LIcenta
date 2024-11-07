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


def send_dto(server_socket, dto):
    chunk_size = 1024
    for i in range(0, len(dto), chunk_size):
        chunk = dto[i:i + chunk_size]
        server_socket.sendall(chunk)
    server_socket.shutdown(socket.SHUT_WR)
    print("dto sent successfully")

