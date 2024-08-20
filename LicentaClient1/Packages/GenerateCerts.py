from Packages.CertOperations import *
from Headers.headers import *

def generate_wg_certificate(machine_ip, e_val, n_val, pub_key, sub_ip, port_ip, safe_word, cert_dir_wg, told_word):
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


    # Create subject and issuer (self-signed, so they are the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RO"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "User_Location"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "User_Location"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "User_Licenta"),
        x509.NameAttribute(NameOID.COMMON_NAME, "tuiasi.ro"),
    ])

    # Criptare safe-word, machine_ip, pub_key, sub_ip, port_ip

    encrypted_safe_word = rsa_encrypt(n_val, e_val, safe_word)
    encrypted_machine_ip = rsa_encrypt(n_val, e_val, machine_ip)
    encrypted_pub_key = rsa_encrypt(n_val, e_val, pub_key)
    encrypted_sub_ip = rsa_encrypt(n_val, e_val, sub_ip)
    encrypted_port_ip = rsa_encrypt(n_val, e_val, port_ip)
    encrypted_told_word=rsa_encrypt(n_val,e_val,told_word)

    # Create custom OIDs for e and n
    oid_custom_safe_word = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.4")
    oid_custom_machine_id = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.5")
    oid_custom_pub_key = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.6")
    oid_custom_sub_ip = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.7")
    oid_custom_port_ip = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.8")
    oid_custom_told_word = ObjectIdentifier("1.3.6.1.4.1.11129.2.5.9")


    # Create custom extensions
    custom_extension_1 = x509.UnrecognizedExtension(oid_custom_safe_word, bytes(encrypted_safe_word, 'utf-8'))
    custom_extension_2 = x509.UnrecognizedExtension(oid_custom_machine_id, bytes(encrypted_machine_ip, 'utf-8'))
    custom_extension_3 = x509.UnrecognizedExtension(oid_custom_pub_key, bytes(encrypted_pub_key, 'utf-8'))
    custom_extension_4 = x509.UnrecognizedExtension(oid_custom_sub_ip, bytes(encrypted_sub_ip, 'utf-8'))
    custom_extension_5 = x509.UnrecognizedExtension(oid_custom_port_ip, bytes(encrypted_port_ip, 'utf-8'))
    custom_extension_6 = x509.UnrecognizedExtension(oid_custom_told_word, bytes(encrypted_told_word, 'utf-8'))


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
        .add_extension(custom_extension_4, critical=False)
        .add_extension(custom_extension_5, critical=False)
        .add_extension(custom_extension_6, critical=False)
        .sign(key, hashes.SHA256())
    )

    # Save the private key and certificate to files
    with open(os.path.join(cert_dir_wg, "private_key.pem"), "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ))

    with open(os.path.join(cert_dir_wg, "wgCertificate.pem"), "wb") as cert_file:
        cert_file.write(cert.public_bytes(Encoding.PEM))
    print("Private key and certificate with integer extensions created successfully.")

    return 0


def generate_safe_word():
    return random.choice(words)


def run_command_with_sudo(command, password="abelbossu"):
    process = subprocess.Popen(['sudo', '-S'] + command,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True)
    stdout, stderr = process.communicate(password + '\n')
    return stdout, stderr


def create_wireguard_certificate(cert_dir, cert_dir_wg):
    # get machine ip, public wireguard key, sub-ip with port,

    # get machine ip
    machine_ip = subprocess.run(["hostname", "--all-ip-addresses"],
                                capture_output=True, text=True).stdout.strip().split()[0]
    # extract rsa data
    n_val, e_val, id_user = extract_greeting_cert_extension_data(cert_dir, "/greeting_certificate.pem")

    # generate and get wg keys and get wg public key in var

    priv_key = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()

    with open('private', 'w') as public_file:
        public_file.write(priv_key)

    pub_key = subprocess.run(['wg', 'pubkey'], input=priv_key, capture_output=True, text=True).stdout.strip()

    with open('public', 'w') as public_file:
        public_file.write(pub_key)
    # wireguard setup

    command = ["ip", "link", "add", "dev", "wg0", "type", "wireguard"]
    stdout, stderr = run_command_with_sudo(command)

    # sub-ip
    sub_ip = "10.0.0." + str(id_user)

    command = ["ip", "addr", "add", sub_ip + "/24", "dev", "wg0",]
    stdout, stderr = run_command_with_sudo(command)

    command = ["wg", "set", "wg0", "private-key", "./private"]
    stdout, stderr = run_command_with_sudo(command)

    command = ["ip", "link", "set", "wg0", "up"]
    stdout, stderr = run_command_with_sudo(command)

    command = ['wg', 'show', 'wg0']
    stdout, stderr = run_command_with_sudo(command)

    port_ip = re.search(r'listening port:\s+(\d+)', stdout).group(1)


    # generate random word 10 chars
    safe_word = generate_safe_word()

    # --------------------- will be input from user    ---------------------
    told_word = "abelbossu"

    # create wg certificate for server and encrypt with rsa
    generate_wg_certificate(machine_ip, e_val, n_val, pub_key, sub_ip, port_ip, safe_word, cert_dir_wg,told_word)