from Packages.GreetingCertificateOperations import *
from Headers.headers import *

def generate_safe_word():
    return random.choice(words)


def run_command_with_sudo(command, password):
    process = subprocess.Popen(['sudo', '-S'] + command,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True)
    stdout, stderr = process.communicate(password + '\n')
    return stdout, stderr


def set_up_wireguard(user_id,safe_word,told_word,root_password):
    # get machine ip, public wireguard key, sub-ip with port,

    # get machine ip
    machine_ip = subprocess.run(["hostname", "--all-ip-addresses"],
                                capture_output=True, text=True).stdout.strip().split()[0]



    # generate and get wg keys and get wg public key in var

    priv_key = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()

    with open('private', 'w') as public_file:
        public_file.write(priv_key)

    pub_key = subprocess.run(['wg', 'pubkey'], input=priv_key, capture_output=True, text=True).stdout.strip()

    with open('public', 'w') as public_file:
        public_file.write(pub_key)
    # wireguard setup

    command = ["ip", "link", "add", "dev", "wg0", "type", "wireguard"]
    stdout, stderr = run_command_with_sudo(command,root_password)

    # sub-ip
    sub_ip = "10.0.0." + str(user_id)

    command = ["ip", "addr", "add", sub_ip + "/24", "dev", "wg0",]
    stdout, stderr = run_command_with_sudo(command,root_password)

    command = ["wg", "set", "wg0", "private-key", "./private"]
    stdout, stderr = run_command_with_sudo(command,root_password)

    command = ["ip", "link", "set", "wg0", "up"]
    stdout, stderr = run_command_with_sudo(command,root_password)

    command = ['wg', 'show', 'wg0']
    stdout, stderr = run_command_with_sudo(command,root_password)

    port_ip = re.search(r'listening port:\s+(\d+)', stdout).group(1)


    # generate random word 10 chars
    #safe_word = generate_safe_word()
    #safe_word = "abelbossu"

    # --------------------- will be input from user    ---------------------
    #told_word = "abelbossu"


    return safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word

def final_wireguard_setup(public_key_pair, ip_address_pair, port_pair, endpoint_pair,root_passowrd):

    print(public_key_pair)
    print(ip_address_pair)
    print(port_pair)
    print(endpoint_pair)
    command = ["wg", "set", "wg0", "peer", str(public_key_pair),"allowed-ips", str(endpoint_pair) + "/32", "endpoint",str(ip_address_pair)+":"+str(port_pair)]
    stdout, stderr = run_command_with_sudo(command,root_passowrd)



