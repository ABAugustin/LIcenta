from Packages.CertOperations import extract_wg_cert_extension_data
from Packages.ConnectionHandler import ConnectionHandler
from Packages.MongoMethods import insert_data_into_db, create_match_safe_words_db
from Packages.SandRCerts import *


def handle_client(client_socket, cert_dir, cert_dir_wg, cert_dir_pair):
    user_ip_no = connection_handler.toggle_user_id_no()
    user_count_no = connection_handler.toggle_user_count_no()

    generate_greeting_certificate(cert_dir, user_ip_no, user_count_no)
    # send greeting certificate
    send_certificate(client_socket, cert_dir, cert_file='/' + str(user_count_no) + "/greeting_certificate.pem")

    # receive rsa encrypted certificate
    receive_certificate(client_socket, cert_dir_wg, cert_file="CertificateWG_" + str(user_count_no) + ".pem")

    safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word = extract_wg_cert_extension_data(cert_dir_wg,cert_file="/CertificateWG_" + str(user_count_no) + ".pem")


    insert_data_into_db(safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word)

    create_match_safe_words_db()

    generate_pair_certificate(cert_dir_pair, machine_ip, safe_word,pub_key, port_ip, told_word, user_count_no)

    #send_certificate(client_socket, cert_dir_pair, cert_file='/' + str(user_count_no) + "/pair_certificate.pem")

    client_socket.close()

    #207.180.196.203
def start_server(cert_dir, cert_dir_wg, cert_dir_pair, host='207.180.196.203', port=server_prt):
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
    start_server(cert_dir="/home/augu/LIcenta/LicentaServer/Certificates",
                 cert_dir_wg="/home/augu/LIcenta/LicentaServer/CertificatesWG",
                 cert_dir_pair="/home/augu/LIcenta/LicentaServer/CertificatesPair")
