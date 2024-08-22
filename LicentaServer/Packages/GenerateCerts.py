from Headers.headers import *
from Packages.MongoMethods import get_pair_data


def generate_greeting_certificate(cert_dir, user_ip_no, user_count_no):


    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create subject and issuer (self-signed, so they are the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RO"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Iasi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Iasi"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Licenta"),
        x509.NameAttribute(NameOID.COMMON_NAME, "tuiasi.ro"),
    ])

    # Create custom OIDs for e and n
    oid_custom_e = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.1")
    oid_custom_n = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.2")
    oid_custom_id = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.3")
    e_rsa = str(e)
    n_rsa = str(N)

    # Create custom extensions
    custom_extension_1 = x509.UnrecognizedExtension(oid_custom_e, bytes(e_rsa, 'utf-8'))
    custom_extension_2 = x509.UnrecognizedExtension(oid_custom_n, bytes(n_rsa, 'utf-8'))
    custom_extension_3 = x509.UnrecognizedExtension(oid_custom_id, bytes(str(user_ip_no), 'utf-8'))



    # Build the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(custom_extension_1, critical=False)
        .add_extension(custom_extension_2, critical=False)
        .add_extension(custom_extension_3, critical=False)
        .sign(key, hashes.SHA256())
    )

    # Save the private key and certificate to files

    cert_dir = check_and_create_folder(cert_dir, str(user_count_no))

    with open(os.path.join(cert_dir, "private_key_greetings_cert.pem"), "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ))

    with open(os.path.join(cert_dir, "greeting_certificate.pem"), "wb") as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))

    print("Private key and certificate with integer extensions created successfully.")




def check_and_create_folder(cert_dir, folder_name):
    folder_path = os.path.join(cert_dir, str(folder_name))

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_name}' created in '{cert_dir}'")
    else:
        print(f"Folder '{folder_name}' already exists in '{cert_dir}'")

    return folder_path


def generate_pair_certificate(cert_dir,machine_ip, safe_word , pub_key, port_ip, told_word, user_count_no):
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create subject and issuer (self-signed, so they are the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RO"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Iasi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Iasi"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Licenta"),
        x509.NameAttribute(NameOID.COMMON_NAME, "tuiasi.ro"),
    ])


    print("inaint de apel get pair data")

    print(pub_key)
    print(machine_ip)
    print(safe_word)
    print(port_ip)
    print(told_word)

    #public_key, ip_address, port, endpoint = get_pair_data(pub_key, machine_ip, safe_word, port_ip, told_word)
    get_pair_data(pub_key, machine_ip, safe_word, port_ip, told_word)
    # print(pub_key)
    # print(ip_address)
    # print(port)
    # print(endpoint)
    #
    # # Create custom OIDs
    # oid_custom_1 = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.10")
    # oid_custom_2 = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.11")
    # oid_custom_3 = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.12")
    # oid_custom_4 = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.13")
    #
    # # criptare date cu cert public key (probabil)
    #
    #
    #
    #
    # # Create custom extensions
    # custom_extension_1 = x509.UnrecognizedExtension(oid_custom_1, bytes(public_key, 'utf-8'))
    # custom_extension_2 = x509.UnrecognizedExtension(oid_custom_2, bytes(ip_address, 'utf-8'))
    # custom_extension_3 = x509.UnrecognizedExtension(oid_custom_3, bytes(port, 'utf-8'))
    # custom_extension_4 = x509.UnrecognizedExtension(oid_custom_4, bytes(endpoint, 'utf-8'))
    #
    # # Build the certificate
    # cert = (
    #     x509.CertificateBuilder()
    #     .subject_name(subject)
    #     .issuer_name(issuer)
    #     .public_key(key.public_key())
    #     .serial_number(1000)
    #     .not_valid_before(datetime.utcnow())
    #     .not_valid_after(datetime.utcnow() + timedelta(days=365))
    #     .add_extension(custom_extension_1, critical=False)
    #     .add_extension(custom_extension_2, critical=False)
    #     .add_extension(custom_extension_3, critical=False)
    #     .add_extension(custom_extension_4, critical=False)
    #     .sign(key, hashes.SHA256())
    # )
    #
    # # Save the private key and certificate to files
    #
    # cert_dir = check_and_create_folder(cert_dir, str(user_count_no))
    #
    #
    # with open(os.path.join(cert_dir, "pair_certificate.pem"), "wb") as cert_file:
    #     cert_file.write(cert.public_bytes(Encoding.PEM))
    #
    # print("Private key and certificate with integer extensions created successfully.")

