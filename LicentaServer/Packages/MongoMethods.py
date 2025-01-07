import time
from asyncio import sleep

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
    coll_clients, client_cli = connect_to_database_clients()
    coll_matches, client_matches = connect_to_database_matches()

    documents = list(coll_clients.find())

    paired_documents = []

    # Ensure there are at least two documents to process
    while len(documents) < 2:
        documents = list(coll_clients.find())
        time.sleep(1)

    for doc1 in documents:
        if doc1["checked"] != "0":
            continue
        for doc2 in documents:
            if doc2["_id"] == doc1["_id"] or doc2["checked"] != "0":
                continue
            if (
                doc1["securityCodeDest"] == doc2["securityCodeExp"] and
                doc2["securityCodeDest"] == doc1["securityCodeExp"]
            ):
                # Adjust endpoints if they match
                if doc1["endpoint"] == doc2["endpoint"]:
                    doc1["endpoint"] = "10.0.0.1"
                    doc2["endpoint"] = "10.0.0.2"

                # Update the `checked` field in the database
                coll_clients.update_one(
                    {"_id": doc1["_id"]},
                    {"$set": {"checked": "1"}}
                )
                coll_clients.update_one(
                    {"_id": doc2["_id"]},
                    {"$set": {"checked": "1"}}
                )


                # Add the pair to the results
                paired_documents.append({"pair_1": doc1, "pair_2": doc2})
                break

    # Insert paired documents into the matches collection
    if paired_documents:
        coll_matches.insert_many(paired_documents)

    # Close the database connections
    client_cli.close()
    client_matches.close()


def get_pair_data(publicKey, ipAddress, securityCodeDest, port, securityCodeExp):
    collection, client = connect_to_database_matches()

    document = collection.find_one({
        "$or": [
            {"pair_1.publicKey": publicKey,
             "pair_1.ipAddress": ipAddress,
             "pair_1.securityCodeDest": securityCodeDest,
             "pair_1.port": port,
             "pair_1.securityCodeExp": securityCodeExp},

            {"pair_2.publicKey": publicKey,
             "pair_2.ipAddress": ipAddress,
             "pair_2.securityCodeDest": securityCodeDest,
             "pair_2.port": port,
             "pair_2.securityCodeExp": securityCodeExp}
        ]
    })

    print(document)

    # if (document["pair_1"]["publicKey"] == publicKey and
    #         document["pair_1"]["ipAddress"] == ipAddress and
    #         document["pair_1"]["securityCodeDest"] == securityCodeDest and
    #         document["pair_1"]["port"] == port and
    #         document["pair_1"]["securityCodeExp"] == securityCodeExp):


    if document:
        if (document["pair_1"]["securityCodeDest"] == securityCodeDest and
                document["pair_1"]["securityCodeExp"] == securityCodeExp):
            other_pair = document["pair_2"]
        else:
            other_pair = document["pair_1"]

        client.close()
        print("aici")
        print(other_pair)

        print("***********************************************************************")
        print(document["pair_1"])
        print(document["pair_2"])
        print("***********************************************************************")

        print(f"PublicKey: {other_pair['publicKey']}")
        print(f"IPAddress: {other_pair['ipAddress']}")
        print(f"Port: {other_pair['port']}")
        print(f"Endpoint: {other_pair['endpoint']}")

        return (other_pair["publicKey"], other_pair["ipAddress"],other_pair["port"], other_pair["endpoint"])


def remove_duplicate_pairs():
    collection, client = connect_to_database_matches()

    removed_count = 0

    # Fetch all documents
    documents = list(collection.find())

    # Use a set to track unique pairs
    unique_pairs = set()

    for doc in documents:
        # Get pair_1 and pair_2 (as strings to hash them)
        pair_1 = doc.get("pair_1")
        pair_2 = doc.get("pair_2")

        # Create a sorted tuple of pair_1 and pair_2 to identify duplicates
        pair_key = tuple(sorted([str(pair_1), str(pair_2)]))

        if pair_key in unique_pairs:
            # If the pair already exists, remove the duplicate document
            collection.delete_one({"_id": doc["_id"]})
            removed_count += 1
        else:
            # Add the pair to the set
            unique_pairs.add(pair_key)

    # Close connection
    client.close()

    return removed_count

def drop_collection():
    collection,client = connect_to_database_matches()
    collection.drop()