#!usr/bin/env

import hashlib
import json
import time
import configparser
# import math
# from Crypto.PublicKey import DSA
# from Crypto.Signature import DSS
# from Crypto.Hash import SHA3_512
from ecdsa import SigningKey, VerifyingKey, NIST521p
import codecs

# load configuration
config = configparser.ConfigParser()
config.read('config.ini')


class Keys:
    def __init__(self):
        self.keys = {}
        try:
            with open("keys.json", "r") as file:
                self.keys = json.loads(file.read())
        except FileNotFoundError:
            f = open("keys.json", "w")
            f.write("{}")
            f.close()

    def add_key(self, block, key):
        with open("keys.json", "w") as file:
            self.keys[block.id] = key
            file.write(json.dumps(self.keys))

    def key_was_used(self, key):
        if key in self.keys.values():
            return True
        else:
            return False


class Block:
    def __init__(self, id):
        self.id = id
        self.size = int(config.get("blocks", "block_size"))
        self.messages = {}
        self.hash = None
        self.public = None
        self.private = None
        self.signature = None
        self.json = None
        self.time = None
        self.update_json()

    def from_json(self, json):
        self.size = json['size']
        self.size = json['limit']
        self.messages = json['messages']
        self.public = json['public_key']
        self.private = json['private_key']
        self.time = json['time']
        self.hash = json['hash']
        self.signature = json['signature']

    def update_json(self):
        if self.time is not None:
            block_time = self.time
        else:
            block_time = time.time()
        self.json = json.dumps({"size": len(self.messages),
                                "limit": self.size,
                                "messages": self.messages,
                                "public_key": self.public,
                                "private_key": self.private,
                                "time": block_time,
                                "hash": self.hash,
                                "signature": self.signature
                                })

    def add_message(self, piece):
        def check_message(message):
            def is_message(message):
                try:
                    _ = message["author"]
                    _ = message["conversation_id"]
                    _ = message["message"]
                    _ = message["signature"]
                    try:
                        v = VerifyingKey.from_string(codecs.decode(message["author"], 'hex_codec'), curve=NIST521p).verify(codecs.decode(message["signature"], 'hex_codec'), message["message"].encode('utf-8'))
                    except AssertionError:
                        v = False
                    if v:
                        return True
                    else:
                        return False
                except IndexError:
                    return False
            if is_message(message):
                return True
            else:
                return False

        if len(self.messages) < self.size:
            if self.public is None:
                if check_message(piece):
                    self.messages[len(self.messages)] = piece
                    self.update_json()
                    return "Message accepted."
                else:
                    return "Invalid piece."
            else:
                return "Block is already closed."
        else:
            self.close_block()

    def close_block(self, keys):
        def generate_signature(block):
            global keys
            i = 0
            block.update_json()
            block.time = json.loads(block.json)['time']  # need time to be constant (not changing every update)
            print(block.json)
            block.hash = hashlib.sha512(block.json.encode('utf-8')).hexdigest()
            print(block.hash)
            print(block.json)
            needed = block.hash[:3]
            sk = SigningKey.generate(curve=NIST521p)
            h = hashlib.sha512(sk.to_string().hex().encode('utf-8')).hexdigest()
            while needed not in h:
                sk = SigningKey.generate(curve=NIST521p)
                h = hashlib.sha512(sk.to_string().hex().encode('utf-8')).hexdigest()
                if keys.key_was_used(sk.to_string().hex()):
                    h = ""
                i += 1
            block.private = sk.to_string().hex()
            block.public = sk.get_verifying_key().to_string().hex()
            block.update_json()
            block.signature = sk.sign(block.json.encode('utf-8')).hex()
            keys.add_key(block, sk.to_string().hex())
            print("Block", block.id, "closed. Attempts:", i)

        generate_signature(self)
        self.update_json()


def create_message(message):
    sk = SigningKey.generate(curve=NIST521p)
    vk = sk.get_verifying_key().to_string()
    return {'author': vk.hex(), 'conversation_id': 'a1b2c3d4', 'message': message, 'signature': sk.sign(message.encode('utf-8')).hex()}

if __name__ == '__main__':
    keys = Keys()
    block = Block(0)
    msg = create_message('Hello!')
    print("response:", block.add_message(msg))
    print(block.messages)
    block.close_block(keys)
    print(block.json)
