from Packages.Headers.headers import *



def receive_certificate(client_socket, cert_dir):
    try:
        # Read the length of the certificate (4 bytes)
        cert_length = struct.unpack("!I", client_socket.recv(4))[0]

        # Read the actual certificate data
        certificate_data = b""
        while len(certificate_data) < cert_length:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            certificate_data += chunk

        # Save the certificate
        cert_file_path = cert_dir + "/greeting_certificate.pem"
        with open(cert_file_path, 'wb') as f:
            f.write(certificate_data)

        print("Certificate received and saved.")
    except Exception as e:
        print(f"Error receiving certificate: {e}")




def send_dto(server_socket, dto):
    chunk_size = 1024
    for i in range(0, len(dto), chunk_size):
        chunk = dto[i:i + chunk_size]
        server_socket.sendall(chunk)
    server_socket.shutdown(socket.SHUT_WR)
    print("dto sent successfully")


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