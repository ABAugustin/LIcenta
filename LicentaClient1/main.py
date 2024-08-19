from Packages.SndRCert import *
from Packages.GenerateCerts import *


def connect_to_server(server_ip, server_port, cert_dir, cert_dir_wg):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.connect((server_ip, server_port))

        print(f"Connected to server at {server_ip}:{server_port}")

        # Receive server certificate with encrypting data
        receive_certificate(server_socket, cert_dir, cert_file="greeting_certificate.pem")

        # Create wg certificate
        create_wireguard_certificate(cert_dir, cert_dir_wg)

        # Send certificate with wg data encrypted

        send_certificate(server_socket, cert_dir_wg, cert_file="/wgCertificate.pem")

    server_socket.close()

if __name__ == '__main__':
    connect_to_server(server_ip="0.0.0.0", server_port=server_prt,
                      cert_dir="/home/augu/Documents/GitHub/LIcenta/LicentaClient1/Certificates",
                      cert_dir_wg="/home/augu/Documents/GitHub/LIcenta/LicentaClient1/CertificatesWG")
