import socket
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from DTOs.WG_DTO import WireguardDTO


def receive_dto_data(client_socket):
    # Collect data in chunks
    data_chunks = []
    while True:
        chunk = client_socket.recv(1024)
        if not chunk:  # End of data
            break
        data_chunks.append(chunk)

    # Join all chunks to form the complete data
    data = b''.join(data_chunks)
    return data

def decrypt_dto_data(encrypted_data, private_key):
    # Decrypt the received encrypted data
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

def extract_wg_dto_data(decrypted_data):
    dto_data = json.loads(decrypted_data.decode("utf-8"))
    dto = WireguardDTO.from_dict(dto_data)
    return dto

def send_dto(server_socket, dto):
    chunk_size = 1024
    for i in range(0, len(dto), chunk_size):
        chunk = dto[i:i + chunk_size]
        server_socket.sendall(chunk)
    server_socket.shutdown(socket.SHUT_WR)
    print("dto sent successfully")
