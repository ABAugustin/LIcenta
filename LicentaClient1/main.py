import json

from DTOs.DTOOperations import receive_dto_data, decrypt_dto_data, extract_pair_dto_data
from DTOs.WG_DTO import WireguardDTO
from DiffieHellman.DH import dh_generate_private_key, dh_generate_public_key, compute_shared_secret
from Packages.SndRCert import *
from Wireguard.Wireguard import *


def connect_to_server(server_ip, server_port, cert_dir):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.connect((server_ip, server_port))

        print(f"Connected to server at {server_ip}:{server_port}")

        # receive greeting certificate and extract public key
        receive_certificate(server_socket, cert_dir, cert_file="greeting_certificate.pem")
        grt_cert = load_certificate(cert_dir)
        public_key_server, user_id = get_grt_cert_pkey_and_id(grt_cert)


        #!!!!!!!!!!!!!!!!!!!! ---- Start Diffie Hellman ----- !!!!!!!!!!!!!!!!!!!!!
        #diffie hellman

        #generate public and private key
        client_private_key_dh = dh_generate_private_key()
        client_public_key_dh = dh_generate_public_key(client_private_key_dh)

        client_public_key_dh_bytes = client_public_key_dh.to_bytes((client_public_key_dh.bit_length() + 7) // 8, "big")

        #encrypt dh public key and send to server
        encrypted_client_public_key_dh = public_key_server.encrypt(
            client_public_key_dh_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        server_socket.sendall(encrypted_client_public_key_dh)

        #receive and decrypt server dh key
        encrypted_server_public_key_dh = server_socket.recv(1024)
        server_public_key_dh = int.from_bytes(encrypted_server_public_key_dh, "big")

        #find out the session key
        shared_secret = compute_shared_secret(server_public_key_dh, client_private_key_dh)

        #!!!!!!!!!!!!!!!!!!!! ---- End Diffie Hellman ----- !!!!!!!!!!!!!!!!!!!!!

        #with the obtained public key we can transfer the wg set-up to server

        # set up wg certificate
        safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word = set_up_wireguard(user_id)

        # Create wg dto object
        wg_dto = WireguardDTO(safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word)

        # wg_dto  -> json -> bytes
        dto_json = json.dumps(wg_dto.to_dict()).encode("utf-8")

        # Encrypt Wg dto with public key from greeting certificate
        dto_wg_encrypted = shared_secret.encrypt(
            dto_json,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        send_dto(server_socket, dto_wg_encrypted)

        #receive pairing dto

        pair_dto_encrypted=receive_dto_data(server_socket)
        # decrypt
        pair_dto_decrypted = decrypt_dto_data(pair_dto_encrypted, shared_secret)
        # put data into object
        pair_dto = extract_pair_dto_data(pair_dto_decrypted)
        public_key_pair, ip_address_pair, port_pair, endpoint_pair = pair_dto.to_tuple()
        # set up wg with pair
        final_wireguard_setup(public_key_pair, ip_address_pair, port_pair, endpoint_pair)



    server_socket.close()

if __name__ == '__main__':
    connect_to_server(server_ip="0.0.0.0", server_port=server_prt,
                      cert_dir="/home/augu/Documents/GitHub/LIcenta/LicentaClient1/Certificates")
