import datetime
import hashlib
import json

import requests
from flask import Flask, jsonify, request
from uuid import uuid4
from urllib.parse import urlparse


class BlockChain:

    #  Creates the blockchain

    # constructor
    def __init__(self):

        # defines an empty list to hold all blocks
        self.chain = []

        # defines a property to check if chain is started
        self.chain_started = False

        # defines a list for holding waiting blocks mined by other nodes
        self.waiting_blocks = []

        # a private property to hold transaction along blockchain transactions aren't hold in particular block
        self.transactions = []

        # Creates infrastructure for multi node env
        self.nodes = set()

    def start_chain(self):
        """starts the chain.
        -> If there is any node in system generates genesis block
        -> If there is other nodes in the system replicates other nodes chain
        -> Also sets chain_started = True. Other chain functions shouldn't be used if chain_started is false
        """

        # If there is nodes in the set
        if len(self.nodes) > 0:
            # Then replace the chain from other nodes
            replace_chain()
        else:
            # If there is no node in network than create genesis block
            self.create_block(nonce=1, previous_hash='0')

        self.chain_started = True
        return True

    def create_block(self, nonce, previous_hash):
        # this function adds block to chain

        # block is a object that contains index timestatmpt nonce and prev has
        block = {'index': len((self.chain)) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'nonce': nonce,
                 'previous_hash': previous_hash,
                 'transactions': self.transactions
                 }

        self.chain.append(block)
        return block

    def add_transaction(self, sender, receiver, amount):

        # this adds new transaction object to transaction list in blockchain
        self.transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount
        })

        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def get_previous_block(self):
        """returns the last element in the chain """
        return self.chain[-1]

    def proof_of_work(self, previous_nonce):

        # sets new nonce to one
        new_nonce = 1

        # Nonce check setted to false
        check_nonce = False

        # while there is no proof of work (a nonce ending with 4 zero)
        while check_nonce is False:

            # Calculate hash
            hash_ops = hashlib.sha256(str(new_nonce ** 2 - previous_nonce ** 2).encode()).hexdigest()

            ## if the calculated hash is ending with 4 zero set check nonce to true end loop
            if hash_ops[:4] == '0000':
                check_nonce = True
            else:
                # else keep calculating the nonces
                new_nonce += 1

        ## when you find a valid nonce return the finded nonce
        return new_nonce

    def calculateHash(self, block):
        # json dumps serializes object to json format sort keys mean that argument should be sorted
        # first function takes a signles block as a arguemnts then jsonifies the block
        encoded_block = json.dumps(block, sort_keys=True).encode()

        # after jsonofying the block it converts string to encyripted hash with sha256
        return hashlib.sha256(encoded_block).hexdigest()

    # This function adds a new node to node set inside blockchain
    def add_node(self, adress):
        parsed_url = urlparse(adress)
        self.nodes.add(parsed_url.netloc)

    def add_waiting_block(self, block):
        self.waiting_blocks.append(block)

    def update_chain(self):
        """Adds blocks mined from other blocks to waiting blocks if its valid"""

        # While there is waiting blocks in waiting_blocks list
        while blockchain.waiting_blocks:

            # Get the latest block mined by other nodes
            current_block = blockchain.waiting_blocks.pop(0)

            # Create temporary chain for last two blocks
            test_chain = [blockchain.get_previous_block(), current_block]

            # If the temporary chain is valid add new block to block_chain
            if blockchain.isChainValid(test_chain):
                blockchain.chain.append(current_block)


    def replace_chain(self):

        # this denotes to all nodes in the network
        network = self.nodes

        longest_chain = None

        # Set max lenght as self chain as trial then look for ching logner than this
        max_length = len(self.chain)

        # Check all the nodes in the network
        for node in network:

            # use http response to obtain chain
            response = requests.get(f'http://{node}/get_chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length:
                    max_length = length
                    longest_chain = chain

        if longest_chain:
            self.chain = longest_chain
            return True
        return False

    def isChainValid(self, chain):
        """
        This functions checks if the blockchain is valid or not
        :param chain: is a chain to control
        :return: Boolean if blockchain is valid
        """

        # If the length of chain is one then return true
        if len(chain) == 1:
            return True

        # Get last two block and perform calculations
        previous_block = chain[len(chain) - 2]
        block = chain[len(chain) - 1]

        if block['previous_hash'] != hashlib.sha256(
                json.dumps(previous_block, sort_keys=True).encode()).hexdigest():
            return False

        previous_nonce = previous_block['nonce']
        nonce = block['nonce']

        hash_operation = hashlib.sha256(str(nonce ** 2 - previous_nonce ** 2).encode()).hexdigest()
        if hash_operation[:4] != '0000':
            return False

        return True

    def getChain(self):
        return self.chain


## Create web application with flask
app = Flask(__name__)

app.config[' JSONIFY_PRETTYPRINT_REGULAR'] = False
node_adress = str(uuid4()).replace('-', '')
print(f'node adress is {node_adress}')

# Instantiating the Blockchain class to obtain our Blockchain
blockchain = BlockChain()


# Mining a new block


@app.route('/mine_block', methods=['GET'])
def mine_block():
    """
    Mines a new block and
    :return: json that shows : message, index, timestamp, nonce, previous_hash, transaction
    """

    # Get last block in the chain
    previous_block = blockchain.get_previous_block()

    # Get last nonce in the chain
    previous_nonce = previous_block['nonce']

    # calculate nonce
    nonce = blockchain.proof_of_work(previous_nonce)

    # Calculate previous hash
    previous_hash = hashlib.sha256(json.dumps(previous_block, sort_keys=True).encode()).hexdigest()

    # Creates a block
    block = blockchain.create_block(nonce, previous_hash)

    # create a json object of block
    block_json = {
        'index': block['index'],
        'timestamp': block['timestamp'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
        'transactions': block['transactions']
    }

    # For every node in the network
    for node in blockchain.nodes:

        #dumb json object
        dumped_json_block = json.dumps(block_json)

        # set content header type to json
        headers = {'Content-Type': 'application/json'}
        # post new block
        requests.post(f'http://{node}/share_block', data=dumped_json_block)


    return jsonify(block_json), 200

    # Retrieving the Blockchain


@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.isChainValid(blockchain.chain)

    if is_valid:
        response = {'message': 'BlockChain is valid'}
    else:
        response = {'message': 'BlockChain is invalid'}

    return jsonify(response), 200


@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']

    if not all(key in json for key in transaction_keys):
        return 'Some elemenets are missing', 400

    index = blockchain.add_transaction(json['sender'], json['receiver'], json['amount'])
    response = {'message': f'This transaction has been added to block {index}'}
    return jsonify(response), 201


@app.route('/connect_nodes', methods=['POST'])
def connect_nodes():
    json = request.get_json()
    nodes = json.get('nodes')

    if nodes is None:
        return 'No node', 400

    for node in nodes:
        print(node)
        blockchain.add_node(node)

    response = {'message': 'all the nodes are now connected', 'total_nodes': list(blockchain.nodes)}

    return jsonify(response), 200


@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        response = {'message': 'The other nodes was containing more blocks so chain is replaced',
                    'chain': blockchain.chain}
    else:
        response = {'message': 'BlockChain hasnt replaced',
                    'chain': blockchain.chain}
    return response, 200


@app.route('/start_chain', methods=['GET'])
def start_chain():
    response_chain = blockchain.start_chain()
    return {"response": f'blockchain started {response_chain}'}, 200


@app.route('/share_block', methods=['POST'])
def share_block():
    """
    Gets recent mined blocks from other nodes and adds itself chain if its valid
    :return:
    """
    # Gets data from the post request
    block_object = json.loads(request.data)

    # adds new block to blockchains waiting blocks
    blockchain.add_waiting_block(block_object)

    # Then update add waiting blocks to blockchain if they are valid
    blockchain.update_chain()

    return {"response": f'Node recieved succesfully {blockchain.waiting_blocks}'}, 200


app.run(host='localhost', port=8000)
