from Packages.SandRCerts import *


def start_server(cert_dir,cert_dir_wg, host='0.0.0.0', port=server_prt, user_id=k, user_count=k):
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1000)

    print(f"Server listening on {host}:{port}")

    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    # generate greeting certificate

    user_count, user_id = generate_greeting_certificate(cert_dir, user_id, user_count)

    # send greeting certificate
    send_certificate(client_socket, cert_dir, cert_file='/' + str(user_count) + "/greeting_certificate.pem")

    # receive rsa encrypted certificate
    receive_certificate(client_socket, cert_dir_wg,cert_file="CertificateWG_"+str(user_count)+".pem")


    client_socket.close()


if __name__ == '__main__':
    start_server(cert_dir="/home/augu/Documents/GitHub/LIcenta/LicentaServer/Certificates",
                 cert_dir_wg="/home/augu/Documents/GitHub/LIcenta/LicentaServer/CertificatesWG")
