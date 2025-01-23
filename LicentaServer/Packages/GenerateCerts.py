from Packages.Headers.headers import *


def generate_greeting_certificate(cert_dir, user_ip_no, user_count_no):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RO"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Iasi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Iasi"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Licenta"),
        x509.NameAttribute(NameOID.COMMON_NAME, "tuiasi.ro"),
    ])
    oid_custom_id = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.1")
    custom_extension_1 = x509.UnrecognizedExtension(oid_custom_id, bytes(str(user_ip_no), 'utf-8'))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(custom_extension_1, critical=False)
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
    return key



def check_and_create_folder(cert_dir, folder_name):
    folder_path = os.path.join(cert_dir, str(folder_name))

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print(f"Folder '{folder_name}' created in '{cert_dir}'")
    else:
        print(f"Folder '{folder_name}' already exists in '{cert_dir}'")

    return folder_path



