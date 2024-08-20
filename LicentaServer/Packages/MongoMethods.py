import pymongo


def connect_to_database_clients():
    mongodb_uri = "mongodb://licenta2024:licenta2024@207.180.196.203:27017/"
    client = pymongo.MongoClient(mongodb_uri)
    db = client["DataBaseLicenta"]
    collection = db["ConnectionClients"]

    return collection, client


def connect_to_database_matches():
    mongodb_uri = "mongodb://licenta2024:licenta2024@207.180.196.203:27017/"
    client = pymongo.MongoClient(mongodb_uri)
    db = client["DataBaseLicenta"]
    collection = db["PairedClients"]

    return collection, client


def insert_data_into_db(safe_word, machine_ip, pub_key, sub_ip, port_ip, told_word):
    collection, client = connect_to_database_clients()

    document = {
        "publicKey": str(pub_key),
        "ipAddress": str(machine_ip),
        "securityCodeDest": str(safe_word),
        "port": str(port_ip),
        "endpoint": str(sub_ip),
        "securityCodeExp": str(told_word),
        "checked": "0"
    }
    collection.insert_one(document)
    client.close()


def create_match_safe_words_db():
    coll_clients, client_cli = connect_to_database_clients
    coll_matches, client_matches = connect_to_database_matches()

    documents = list(coll_clients.find())

    paired_documents = []
    visited = set()

    for doc1 in documents:
        if doc1["_id"] in visited:
            continue
        for doc2 in documents:
            if doc2["_id"] in visited or doc1["_id"] == doc2["_id"]:
                continue
            if doc1["securityCodeDest"] == doc2["securityCodeExp"] and doc2["securityCodeDest"] == doc1["securityCodeExp"] and doc1["checked"] == "0" and doc2["checked"] == "0":
                if doc1["port"] == doc2["port"]:
                    doc1["port"] = "10.0.0.1"
                    doc2["port"] = "10.0.0.2"

                coll_clients.update_one(
                    doc1["_id"],
                    {"$set": {"checked": "1"}}
                )
                coll_clients.update_one(
                    doc2["_id"],
                    {"$set": {"checked": "1"}}
                )

                paired_documents.append({"pair_1": doc1, "pair_2": doc2})
                visited.add(doc1["_id"])
                visited.add(doc2["_id"])
                break

    if paired_documents:
        coll_matches.insert_many(paired_documents)

    client_cli.close()
    client_matches.close()
