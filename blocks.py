#!usr/bin/env

import hashlib
import json
import time
import configparser
import math
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA3_512

# load configuration
config = configparser.ConfigParser()
config.read('config.ini')


class Block:
    def __init__(self):
        self.size = int(config.get("blocks", "block_size"))
        self.puzzles = []
        self.proof = None
        self.update_json()

    def update_json(self):
        self.json = json.dumps({"size": len(self.puzzles),
                                "limit": self.size,
                                "puzzles": json.dumps(self.puzzles),
                                "proof": self.proof
                                })

    def add_puzzle(self, piece):
        if (len(self.puzzles) < self.size):
            if (self.proof == None):
                if (Logic.check_puzzle(self, piece)):
                    self.puzzles.append(piece)
                    self.update_json()
                else:
                    return "Invalid piece"
            else:
                return "Block is already closed."
        else:
            self.close_block()

    def close_block(self):
        self.proof = Logic.proof_of_ownership(self)
        self.update_json()


class Logic:
    @staticmethod
    def check_puzzle(block, puzzle):
        if (Structure.is_puzzle(puzzle)):
            return True
        else:
            return False

    @staticmethod
    def consensus():
        pass

    @staticmethod
    def proof(block):
        def f(a, b, x):
            return math.sqrt(x**3+a*x+b)

        def hash_sum():
            h = int(hashlib.sha512(block.json.encode('utf-8')).hexdigest(), 16)
            s = 0
            for i in list(str(h)):
                s += int(i)
            return s
        a = int(hashlib.sha512(block.json.encode('utf-8')).hexdigest()[:16], 16)
        b = int(hashlib.sha512(block.json.encode('utf-8')).hexdigest()[16:32], 16)
        graph = {}
        for x in range(100):
            graph[x] = f(a, b, x)
        print(graph)
        return None

    @staticmethod
    def proof_of_work(block):
        nonce = 0
        h = hashlib.sha512(block.json.encode('utf-8') + str(nonce).encode('utf-8')).hexdigest()
        while h[124:] != 4*"0":
            nonce += 1
            h = hashlib.sha512(block.json.encode('utf-8') + str(nonce).encode('utf-8')).hexdigest()
        print("Found proof:", nonce, "final hash:", h)
        return nonce

    @staticmethod
    def proof_of_ownership(block):
        key = DSA.generate(int(config.get("logic", "key_size")))
        hash_obj = SHA3_512.new(block.json.encode('utf-8'))
        signer = DSS.new(key, 'fips-186-3')
        signature = key.sign(hash_obj)
        return signature

class Structure:
    @staticmethod
    def is_puzzle(puzzle):
        try:
            _ = puzzle["A"]
            _ = puzzle["B"]
            _ = puzzle["C"]
            return True
        except:
            return False


MainBlock = Block()
MainBlock.add_puzzle({"A":"", "B":"", "C":""})
print(MainBlock.puzzles)
MainBlock.close_block()