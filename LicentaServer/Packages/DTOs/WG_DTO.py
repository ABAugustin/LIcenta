class WireguardDTO:

    def __init__(self, safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word):
        self.safe_word = safe_word
        self.machine_ip = machine_ip
        self.pub_key = pub_key
        self.sub_ip = sub_ip
        self.port_ip = port_ip
        self.told_word = told_word
        # Method to display person's details

    def display_info(self):
        print(f"Safe Word: {self.safe_word}")
        print(f"Machine IP: {self.machine_ip}")
        print(f"Public Key: {self.pub_key}")
        print(f"Sub IP: {self.sub_ip}")
        print(f"Port IP: {self.port_ip}")
        print(f"Told Word: {self.told_word}")

    @classmethod
    def from_dict(cls, data):
        return cls(
            safe_word=data.get("safe_word"),
            machine_ip=data.get("machine_ip"),
            pub_key=data.get("pub_key"),
            sub_ip=data.get("sub_ip"),
            port_ip=data.get("port_ip"),
            told_word=data.get("told_word")
        )
    def to_tuple(self):
        return self.safe_word, self.machine_ip, self.pub_key, self.sub_ip, self.port_ip, self.told_word

