from flask import Flask, request
import configparser
import json
import requests
from urllib.parse import
import urllib

# load configuration
config = configparser.ConfigParser()
config.read('config.ini')

app = Flask('BitPegion - blockchain messaging')


class Nodes:
    def __init__(self):
        self.file = config.get("nodes", "file")
        self.nodes = []
        self.load_nodes()
        self.verify_nodes()

    def verify_nodes(self):
        for node in self.nodes:
            try:
                response = requests.get(f"https://{node}/ping")
                if response.status_code != 200 or "Pong" not in response.text:
                    del self.nodes[self.nodes.index(node)]
            except:
                del self.nodes[self.nodes.index(node)]
        self.update_nodes()

    @staticmethod
    def verify_node(node):
        try:
            response = requests.get(f"http://{node}/ping")
            if response.status_code != 200 or "Pong" not in response.text:
                return False
            return True
        except:
            return False

    def load_nodes(self):
        with open(self.file, "r") as file:
            self.nodes = json.loads(file.read())

    def update_nodes(self):
        with open(self.file, "w") as file:
            file.write(json.dumps(self.nodes))

    @property
    def count(self):
        return len(self.nodes)

    def synchronize(self):
        i = 0
        while self.count < int(config.get("nodes", "min_nodes")) and i < self.count:
            node = self.nodes[i]
            response = requests.get(f"http://{node}/nodes")
            if response.status_code == 200:
                try:
                    new_nodes = json.loads(response.text)
                    ii = 0
                    while self.count < int(config.get("nodes", "max_nodes")):
                        if self.verify_node(new_nodes[ii]) and new_nodes[ii] not in self.nodes:
                            self.nodes.append(new_nodes[ii])
                        else:
                            print("Node on address", node, "haven't responded correctly.")
                        ii += 1
                except:
                    print("Node on address", node, "haven't responded correctly.")
            i += 1

    def spread_block(self, block):
        for node in self.nodes:
            try:
                response = urllib.requests.urlopen(f"http://{node}/new_block", ...)
            except:
                pass


@app.route('/nodes/register', methods=['POST'])
def register_node():
    values = request.form

    required = ['address']
    if not all(k in values for k in required):
        return 'Missing values', 400

    if nodes.verify_node(values["address"]):
        parsed_url = urlparse(values["address"])
        if parsed_url.netloc:
            adr = parsed_url.netloc
        elif parsed_url.path:
            adr = parsed_url.path  # Accepts an URL without scheme like '192.168.0.5:5000'.
        else:
            return "Invalid address", 200
        if all(node.split(':')[0] != adr.split(':')[0] for node in n.nodes):
            nodes.nodes.append(adr)
        else:
            return "Node already registered", 200
        nodes.update_nodes()
        return "Node added", 200
    else:
        return "Could not connect to node address", 200


@app.route('/nodes', methods=['GET'])
def print_nodes():
    return json.dumps(n.nodes, indent=4)


@app.route('/ping')
def ping():
    return "Pong", 200



