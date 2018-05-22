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
        # self.messages = []

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
            if not keys.key_was_used(block.private):
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
                print("Key was used already.")
        else:
            print("Hash does not fit.")
        return False

    @property
    def json(self):
        json = "{"
        for i in range(len(self.blocks)):
            json += self.blocks[i].id + ": " + self.blocks[i].json
        json += "}"
        return json

    @property
    def last_block(self):
        if len(self.blocks) == 0:
            self.new_block()
        return self.blocks[len(self.blocks)-1]

    def add_message(self, message):
        if self.last_block.signature != None:
            self.new_block()
        return self.last_block.add_message(message)

    def new_block(self):
        self.blocks.append(Block(len(self.blocks)))

print("Loading keys..")
keys = Keys()
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
    if chain.verify_block(block):  # everything is correct, include received block to our chain, spread it ?
        chain.last_block.is_closing = False
        for msg in chain.last_block.messages:
            if msg in block.messages:
                del
        return "Block was added to chain.", 200
    return "Block was not verified.", 403

@app.route("/last_block", methods=["GET"])
def last_block():
    return chain.last_block.json, 200

@app.route("/chain", methods=["GET"])
def return_chain():
    return chain.json, 200

@app.route("/new_message", methods=["POST"])
def add_msg_to_chain():
    values = request.form
    required = ["author", "conversation_id", "message", "signature"]
    if not all(k in values for k in required):
        return 'Missing values', 400
    return chain.add_message({'author': values["author"], 'conversation_id': values["conversation_id"], 'message': values["message"], 'signature': values["signature"]}), 200

app.run(host='0.0.0.0', port=int(config.get("nodes", "port")))