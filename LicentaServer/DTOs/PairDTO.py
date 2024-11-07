class PairDTO:
    def __init__(self, public_key, ip_address, port, endpoint):
        self.public_key = public_key
        self.ip_address = ip_address
        self.port = port
        self.endpoint = endpoint

    def to_tuple(self):
        return self.public_key, self.ip_address, self.port, self.endpoint

    def to_dict(self):
        return {
            "public_key": self.public_key,
            "ip_address": self.ip_address,
            "port": self.port,
            "endpoint": self.endpoint
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            public_key=data.get("public_key"),
            ip_address=data.get("ip_address"),
            port=data.get("port"),
            endpoint=data.get("endpoint")
        )
