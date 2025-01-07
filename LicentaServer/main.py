import json
import threading
import os
import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from AES.AESOperations import derive_key, encrypt_message, decrypt_message
from DTOs.DTOOperations import extract_wg_dto_data
from DTOs.PairDTO import PairDTO
from DiffieHellman.DH import dh_generate_private_key, dh_generate_public_key, compute_shared_secret
from Headers.headers import server_prt
from Packages.ConnectionHandler import ConnectionHandler
from Packages.MongoMethods import insert_data_into_db, create_match_safe_words_db, remove_duplicate_pairs, \
    drop_collection, get_pair_data
from Packages.SandRCerts import generate_greeting_certificate, send_certificate, clear_buffer, receive_data, send_data
import time

# Create a global lock for database operations
db_lock = threading.Lock()

def handle_client(client_socket, cert_dir):
    try:
        user_ip_no = connection_handler.toggle_user_id_no()
        user_count_no = connection_handler.toggle_user_count_no()

        # AICI SE GENEREAZA GREETING CERTIFICATE
        private_key = generate_greeting_certificate(cert_dir, user_ip_no, user_count_no)

        # AICI SE TRIMITE GREETING CERTIFICATE
        send_certificate(client_socket, cert_dir, cert_file='/' + str(user_count_no) + "/greeting_certificate.pem")
        print("~~~~~~~~~ A fost trimis certificatul ~~~~~~~~~~~~")
        clear_buffer(client_socket)

        # AICI INCEPE DIFFIE HELLMAN
        server_private_key_dh = dh_generate_private_key()
        server_public_key_dh = dh_generate_public_key(server_private_key_dh)

        encrypted_client_public_key_dh = receive_data(client_socket)
        print("~~~~~~~~~ A fost primita cheia DH client ~~~~~~~~~~~~")
        clear_buffer(client_socket)

        client_public_key_dh_bytes = private_key.decrypt(
            encrypted_client_public_key_dh,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        client_public_key_dh = int.from_bytes(client_public_key_dh_bytes, "big")
        server_public_key_dh_bytes = server_public_key_dh.to_bytes((server_public_key_dh.bit_length() + 7) // 8, "big")
        send_data(client_socket, server_public_key_dh_bytes)
        clear_buffer(client_socket)
        print("~~~~~~~~~ A fost trimis cheia serverului catre client DH ~~~~~~~~~~~~")

        shared_secret = compute_shared_secret(client_public_key_dh, server_private_key_dh)

        # AICI PRIMIM DTO-ul WIREGUARD
        wg_dto_encrypted = receive_data(client_socket)
        clear_buffer(client_socket)

        aes_key = derive_key(shared_secret)
        print("aes key")
        print(aes_key)
        wg_dto_decrypted = decrypt_message(aes_key, wg_dto_encrypted)
        print("data to put in wg")
        print(wg_dto_decrypted)

        wg_dto = extract_wg_dto_data(wg_dto_decrypted)
        safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word = wg_dto.to_tuple()

        # Thread-safe database operations
        with db_lock:
            print("Performing thread-safe database operations...")
            insert_data_into_db(safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word)
            time.sleep(0.1)
            create_match_safe_words_db()
            time.sleep(0.1)
            remove_duplicate_pairs()
            time.sleep(0.1)

        public_key, ip_address, port, endpoint = get_pair_data(pub_key, machine_ip, safe_word, port_ip, told_word)

        print("//////////////////////////////////////////")
        print(public_key, ip_address, port, endpoint)
        print("//////////////////////////////////////////")

        pair_dto = PairDTO(public_key, ip_address, port, endpoint)
        pair_dto_json = json.dumps(pair_dto.to_dict()).encode("utf-8")
        dto_pair_encrypted = encrypt_message(aes_key, pair_dto_json)

        send_data(client_socket, dto_pair_encrypted)
        clear_buffer(client_socket)

        # Drop collection safely
        with db_lock:
            drop_collection()

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        print("Closing client socket")
        client_socket.close()

def start_server(cert_dir, host='0.0.0.0', port=server_prt):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1000)

    print(f"Server listening on {host}:{port}")
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        # Generate greeting certificate
        thread = threading.Thread(target=handle_client, args=(client_socket, cert_dir))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == '__main__':
    connection_handler = ConnectionHandler()
    start_server(cert_dir="/home/augu/Documents/GitHub/LIcenta/LicentaServer/Certificates")
