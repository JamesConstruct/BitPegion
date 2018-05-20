from messageblocks import *
from flask import Flask, request
from nodes import *
import requests
import copy

# load configuration
config = configparser.ConfigParser()
config.read('config.ini')


class Chain:
    def __init__(self):
        self.blocks = []
        self.restore_chain()

    def restore_chain(self):
        with open(config.get("blockchain", "file"), "r") as chain_file:
            self.blocks = json.dumps(chain_file.read())


    @staticmethod
    def verify_block(block):
        hashed = hashlib.sha512(json.dumps({"size": len(block.messages),
                                "limit": block.size,
                                "messages": block.messages,
                                "public_key": None,
                                "private_key": None,
                                "time": block.time,
                                "hash": None,
                                "signature": None
                                }).encode('utf-8')).hexdigest()
        if hashed == block.hash:
            if hashed[:3] in hashlib.sha512(block.private.encode('utf-8')).hexdigest():
                signed_block = copy.copy(block)
                signed_block.signature = None
                signed_block.update_json()
                try:
                    VerifyingKey.from_string(codecs.decode(block.public, 'hex_codec'), curve=NIST521p).verify(codecs.decode(block.signature, 'hex_codec'), signed_block.json.encode('utf-8'))
                    print("block is valid.")
                    for message in block.messages:
                        if not check_message(message):
                            print("Invalid message found!")
                            return False
                    return True
                except:
                    print("Block is invalid.")
                    return False
                else:
                    print("Block was not verified.")
            else:
                print("Private key does not match the pattern.")
        else:
            print("Hash does not fit.")
        return False

print("Initiating nodes..")
nodes = Nodes()
print("Synchronizing nodes..")
nodes.synchronize()

chain = Chain()


@app.route("/new_block", methods=["POST"])
def block_received():
    values = request.form
    if 'block' in values:
        values = json.loads(values['block'])
    else:
        return 'Missing values.', 400
    required = ['size', 'limit', 'messages', 'public_key', 'private_key', 'time', 'hash', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    block = Block(-1)
    block.from_json(values)
    if chain.verify_block(block):
        return "Block was added to chain.", 200
    return "Block was not verified.", 403

app.run(host='0.0.0.0', port=int(config.get("nodes", "port")))