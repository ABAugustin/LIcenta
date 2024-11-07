import json
from cryptography.hazmat.primitives.asymmetric import padding
from DTOs.DTOOperations import receive_dto_data, decrypt_dto_data, extract_wg_dto_data, send_dto
from DTOs.PairDTO import PairDTO
from DiffieHellman.DH import dh_generate_private_key, dh_generate_public_key, compute_shared_secret
from Packages.ConnectionHandler import ConnectionHandler
from Packages.MongoMethods import insert_data_into_db, create_match_safe_words_db
from Packages.SandRCerts import *


def handle_client(client_socket, cert_dir, cert_dir_wg, cert_dir_pair):
    user_ip_no = connection_handler.toggle_user_id_no()
    user_count_no = connection_handler.toggle_user_count_no()



    private_key = generate_greeting_certificate(cert_dir, user_ip_no, user_count_no)
    # send greeting certificate
    send_certificate(client_socket, cert_dir, cert_file='/' + str(user_count_no) + "/greeting_certificate.pem")

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Start Diffie Hellman !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    #diffie hellman for session key

    # generate public and private key
    server_private_key_dh = dh_generate_private_key()
    server_public_key_dh = dh_generate_public_key(server_private_key_dh)

    # receive and decrypt client dh key
    encrypted_client_public_key_dh = client_socket.recv(1024)
    client_public_key_dh = int.from_bytes(
        private_key.decrypt(
            encrypted_client_public_key_dh,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ), "big"
    )
    # encrypt and send server dh public key
    encrypted_server_public_key_dh = int.to_bytes(server_public_key_dh, 256, "big")
    client_socket.sendall(encrypted_server_public_key_dh)

    # compute the session key

    shared_secret = compute_shared_secret(client_public_key_dh, server_private_key_dh)

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!! Done Diffie Hellman !!!!!!!!!!!!!!!!!!!!!!!!!!

    #!!!!!!!! receive encrypted wg_dto_encrypted
    # receive
    wg_dto_encrypted = receive_dto_data(client_socket)
    # decrypt
    wg_dto_decrypted =decrypt_dto_data(wg_dto_encrypted, shared_secret)
    # put data into object
    wg_dto = extract_wg_dto_data(wg_dto_decrypted)
    #extract needed data
    safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word = wg_dto.to_tuple()

    #insert data into db
    insert_data_into_db(safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word)

    create_match_safe_words_db()


    # get pair data
    public_key, ip_address, port, endpoint = get_pair_data(pub_key, machine_ip, safe_word, port_ip, told_word)
    # create pair dto
    pair_dto = PairDTO(public_key, ip_address, port, endpoint)

    # wg_dto  -> json -> bytes
    dto_json = json.dumps(pair_dto.to_dict()).encode("utf-8")

    # Encrypt Wg dto with public key from greeting certificate
    dto_pair_encrypted = shared_secret.encrypt(
        dto_json,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    send_dto(client_socket, dto_pair_encrypted)
    client_socket.close()

    #207.180.196.203
def start_server(cert_dir, host='207.180.196.203', port=server_prt):
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

        # generate greeting certificate
        thread = threading.Thread(target=handle_client, args=(client_socket, cert_dir, cert_dir_wg, cert_dir_pair))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == '__main__':
    connection_handler = ConnectionHandler()
    start_server(cert_dir="/home/augu/LIcenta/LicentaServer/Certificates")
