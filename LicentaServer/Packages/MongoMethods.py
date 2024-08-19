import pymongo


# mongodb_uri = "mongodb://licenta2024:licenta2024@207.180.196.203:27017/"
# client = pymongo.MongoClient(mongodb_uri)
# db = client["DataBaseLicenta"]
# collection = db["ConnectionClients"]
#
# document = {
#     "publicKey": "exempluPublicKey",
#     "ipAddress": "192.168.1.1",
#     "securityCodeDest": "destCodeExample",
#     "securityCodeExp": "expCodeExample"
# }
#
# # Inserează documentul în colecția "ConnectionClients"
# result = collection.insert_one(document)
#
# # Afișează ID-ul documentului inserat
# print(f"Document inserat cu ID-ul: {result.inserted_id}")
#
# # Închide conexiunea la MongoDB
# client.close()
def connect_to_database():
    mongodb_uri = "mongodb://licenta2024:licenta2024@207.180.196.203:27017/"
    client = pymongo.MongoClient(mongodb_uri)
    db = client["DataBaseLicenta"]
    collection = db["ConnectionClients"]

    return collection, client


def insert_data_into_db(safe_word, machine_ip, pub_key, sub_ip, port_ip):
    collection, client = connect_to_database()

    document = {
        "publicKey": str(pub_key),
        "ipAddress": str(machine_ip),
        "securityCode": str(safe_word),
        "port": str(port_ip),
        "endpoint": str(sub_ip)
    }
    collection.insert_one(document)
    client.close()
