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

# Create a global lock for database operations
db_lock = threading.Lock()

def handle_client(client_socket, cert_dir):
    user_ip_no = connection_handler.toggle_user_id_no()
    user_count_no = connection_handler.toggle_user_count_no()

    # AICI SE GENEREAZA GREETING CERTIFICATE
    private_key = generate_greeting_certificate(cert_dir, user_ip_no, user_count_no)

    # AICI SE TRIMITE GREETING CERTIFICATE
    send_certificate(client_socket, cert_dir, cert_file='/' + str(user_count_no) + "/greeting_certificate.pem")
    print("~~~~~~~~~ A fost trimis certificatul ~~~~~~~~~~~~")
    clear_buffer(client_socket)

    # AICI INCEPE DIFFIE HELLMAN

    # AICI GENERAM CHEILE PRIVATE SI PUBLICE ALE SERVERULUI PT DH
    server_private_key_dh = dh_generate_private_key()
    server_public_key_dh = dh_generate_public_key(server_private_key_dh)

    # AICI PRIMIM CHEIA CRIPTATA A CLIENTULUI PT DH
    encrypted_client_public_key_dh = receive_data(client_socket)
    print("~~~~~~~~~ A fost primita cheia DH client ~~~~~~~~~~~~")
    clear_buffer(client_socket)

    # AICI DECRIPTAM CHEIA PUBLICA A CLIENTULUI PT DH CU CHEIA PRIVATA A SERVERULUI SSL
    client_public_key_dh_bytes = private_key.decrypt(
        encrypted_client_public_key_dh,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # AICI TRANSFORMAM CHEIA PRIMITA DE LA CLIENT IN INTEGER
    client_public_key_dh = int.from_bytes(client_public_key_dh_bytes, "big")

    # AICI TRIMITEM CHEIA PUBLICA A SERVERULUI DH CATRE CLIENT + BYTES
    server_public_key_dh_bytes = server_public_key_dh.to_bytes((server_public_key_dh.bit_length() + 7) // 8, "big")
    send_data(client_socket, server_public_key_dh_bytes)
    clear_buffer(client_socket)

    print("~~~~~~~~~ A fost trimis cheia serverului catre client DH ~~~~~~~~~~~~")

    # AICI CREAM SHARED SECRET AL DH CU CARE CRIPTAM MAI INCOLO CU AES
    shared_secret = compute_shared_secret(client_public_key_dh, server_private_key_dh)

    # AICI PRIMIM DTO-ul WIREGUARD
    wg_dto_encrypted = receive_data(client_socket)
    clear_buffer(client_socket)

    # AICI DECRIPTAM DTO-ul WIREGUARD CU AES (cu care teoretic e criptat)
    aes_key = derive_key(shared_secret)
    print("aes key")
    print(aes_key)
    wg_dto_decrypted = decrypt_message(aes_key, wg_dto_encrypted)
    print("data to put in wg")
    print(wg_dto_decrypted)

    # AICI EXTRAGEM DATELE DIN JSON LE BAGAM IN DTO SI SEPARAT
    wg_dto = extract_wg_dto_data(wg_dto_decrypted)
    safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word = wg_dto.to_tuple()

    # Database Operations (Thread-Safe)
    with db_lock:
        print("Database operations starting for this client...")
        insert_data_into_db(safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word)
        create_match_safe_words_db()
        remove_duplicate_pairs()
        drop_collection()

        # AICI SE IAU DATELE PAIR_ului
        public_key, ip_address, port, endpoint = get_pair_data(pub_key, machine_ip, safe_word, port_ip, told_word)
        print("Database operations completed.")

    print("//////////////////////////////////////////")
    print(public_key, ip_address, port, endpoint)
    print("//////////////////////////////////////////")

    # AICI SE CREAZA DTO-ul de pair
    pair_dto = PairDTO(public_key, ip_address, port, endpoint)

    # wg_dto -> json -> bytes
    pair_dto_json = json.dumps(pair_dto.to_dict()).encode("utf-8")

    # AICI SE CRIPTEAZA DTO-ul PAIR CU AES
    dto_pair_encrypted = encrypt_message(aes_key, pair_dto_json)

    # AICI SE TRIMITE OBIECTUL DTO CRIPTAT CU AES
    send_data(client_socket, dto_pair_encrypted)
    clear_buffer(client_socket)

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
