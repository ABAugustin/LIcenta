import json


from AES.AESOperations import derive_key, encrypt_message, decrypt_message
from DTOs.DTOOperations import receive_dto_data, decrypt_dto_data, extract_pair_dto_data, clear_buffer
from DTOs.WG_DTO import WireguardDTO
from DiffieHellman.DH import dh_generate_private_key, dh_generate_public_key, compute_shared_secret
from Packages.SndRCert import *
from Wireguard.Wireguard import *


def connect_to_server(server_ip, server_port, cert_dir):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.connect((server_ip, server_port))

        print(f"Connected to server at {server_ip}:{server_port}")

        # AICI PRIMESC CERTIFICATUL SSL DE GREETING
        try:
            receive_certificate(server_socket, cert_dir)
            print("~~~~~~~~~ A fost primit certificatul ~~~~~~~~~~~~")
        except Exception as e:
            # Handle the specific exception
            print(f"An error occurred: {e}")
        grt_cert = load_certificate(cert_dir)
        public_key_server, user_id = get_grt_cert_pkey_and_id(grt_cert)

        # DIFFIE HELLMAN

        #AICI GENEREZ CHEILE DH
        client_private_key_dh = dh_generate_private_key()
        client_public_key_dh = dh_generate_public_key(client_private_key_dh)


        # TRANSFORM CHEIA PUBLICA IN BITI
        client_public_key_dh_bytes = client_public_key_dh.to_bytes((client_public_key_dh.bit_length() + 7) // 8, "big")

        #CRIPTEZ CHEIA PUBLICA DH CU CHEIA PUBLICA SSL SI TRIMIT LA SERVER
        encrypted_client_public_key_dh = public_key_server.encrypt(
            client_public_key_dh_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        clear_buffer(server_socket)

        send_data(server_socket,encrypted_client_public_key_dh)

        clear_buffer(server_socket)

        print("~~~~~~~~~ A fost trimisa cheia DH ~~~~~~~~~~~~")

        #AICI PRIMESC CHEIA PUBLICA A SERVERULUI PT DH
        encrypted_server_public_key_dh = receive_data(server_socket)
        clear_buffer(server_socket)

        print("~~~~~~~~~ A fost primita cheia dh ~~~~~~~~~~~~")

        print("server public key dh dupa primire")
        print(encrypted_server_public_key_dh)

        server_public_key_dh = int.from_bytes(encrypted_server_public_key_dh, "big")
        print("server public key dh")
        print(server_public_key_dh)

        #find out the session key
        shared_secret = compute_shared_secret(server_public_key_dh, client_private_key_dh)
        print("Shared key e")
        print(shared_secret)

        #!!!!!!!!!!!!!!!!!!!! ---- End Diffie Hellman ----- !!!!!!!!!!!!!!!!!!!!!



        #with the obtained public key we can transfer the wg set-up to server

        # set up wg certificate
        safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word = set_up_wireguard(user_id)

        # Create wg dto object
        wg_dto = WireguardDTO(safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word)

        # wg_dto  -> json -> bytes
        dto_json = json.dumps(wg_dto.to_dict()).encode("utf-8")

        # Encrypt Wg dto with public key from greeting certificate
        # !!!!!!!!!!!!!!!!!!!! ---- start AES -----------------------

        aes_key = derive_key(shared_secret)
        dto_wg_encrypted = encrypt_message(aes_key, dto_json)

        # !!!!!!!!!!!!!!!!!!!! ---- end   AES -----------------------
        send_data(server_socket, dto_wg_encrypted)
        clear_buffer(server_socket)

        #receive pairing dto

        pair_dto_encrypted=receive_data(server_socket)
        print("received pair dto data")
        # decrypt
        # !!!!!!!!!!!!!!!!!!!! ---- start AES -----------------------

        pair_dto_decrypted = decrypt_message(aes_key, pair_dto_encrypted)
        print("pair_dto")
        print(pair_dto_decrypted)
        # !!!!!!!!!!!!!!!!!!!! ---- end   AES -----------------------

        # put data into object
        pair_dto = extract_pair_dto_data(pair_dto_decrypted)
        public_key_pair, ip_address_pair, port_pair, endpoint_pair = pair_dto.to_tuple()
        # set up wg with pair
        final_wireguard_setup(public_key_pair, ip_address_pair, port_pair, endpoint_pair)



    server_socket.close()

if __name__ == '__main__':
    connect_to_server(server_ip="207.180.196.203", server_port=server_prt,
                      cert_dir="/home/augu/Documents/GitHub/LIcenta/LicentaClient1/Certificates")
