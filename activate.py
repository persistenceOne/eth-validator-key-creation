import json
import sys
import requests
from web3 import Web3
import argparse


class Keysmanager:
    url = None
    validators = None

    def __init__(self, url):
        self.url = url

    def get_validators(self, time, address):
        query = """ {
            validators(
                first: 1000
                where: {timestamp_gt: "time_start", nodeOperator: "address"}
                orderBy: timestamp
                orderDirection: asc
            ) {
                nodeOperator
                id
                publicKey
                signature
                status
                timestamp
                }
            }
          """.replace("time_start", str(time)).replace("address", address)
        response = requests.post(self.url, json={'query': query})
        return response.json()

    def get_pubkeys(self, address):
        """
        :return: validator keys to monitor , validator keys for validity check
        """
        validators = []
        keys_monitor = self.get_validators(0, address)['data']['validators']
        while True:
            validators = validators + keys_monitor
            if len(keys_monitor) == 1000:
                keys_monitor = self.get_validators(keys_monitor[1000]["timestamp"], address)['data']['validators']
            else:
                break
        return validators


class Issuer:
    web3_eth = None
    issuer_contract = None
    account = None

    def __init__(self, contract_abi, contract_address, eth_rpc):
        self.web3_eth = Web3(Web3.HTTPProvider(eth_rpc))
        self.issuer_contract = self.web3_eth.eth.contract(abi=contract_abi,
                                                          address=Web3.toChecksumAddress(contract_address))

    def set_account(self, private_key):
        self.account = self.web3_eth.eth.account.privateKeyToAccount(private_key)

    def activations(self, pubkey, index):
        return self.issuer_contract.functions.activations(pubkey, index).call()

    def depositToEth2(self, ley):
        if self.account is None:
            raise ValueError("set account before performing this action")
        return self.issuer_contract.functions.depositToEth2(ley).buildTransaction(
            {'from': self.account.address, 'gasPrice': self.web3_eth.toWei('2', 'gwei'), 'gas': 1000000})

    def do_transaction(self, tx):

        result = self.web3_eth.eth.call(tx)
        print("=========================result==========================================")
        print(result)
        tx['nonce'] = self.web3_eth.eth.get_transaction_count(self.account.address)
        signed_tx = self.web3_eth.eth.account.sign_transaction(tx, self.account.key)
        tx_hash = self.web3_eth.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx_receipt = self.web3_eth.eth.wait_for_transaction_receipt(tx_hash)
        print(tx_receipt)
        if tx_receipt.status == 1:
            print('TX successful')
        else:
            print('TX reverted')


def main(eth1_endpoint, graph_endpoint, private_key, contract_address, contract_abi):
    with open(contract_abi, 'r') as file:
        a = json.load(file)
    issuer = Issuer(a['abi'], contract_address, eth1_endpoint)
    issuer.set_account(private_key)
    subgraph = Keysmanager(graph_endpoint)
    validators = subgraph.get_pubkeys(issuer.account.address)
    del issuer
    verified = []
    unverified = []
    deposited = []
    for validator in validators:
        if validator["status"] == "DEPOSITED":
            deposited.append(validator["publicKey"])
        if validator["status"] == "VERIFIED":
            verified.append(validator["publicKey"])
        if validator["status"] == "UNVERIFIED":
            unverified.append(validator["publicKey"])
    print(
        f"You have {len(unverified)} unverified validators, {len(verified)} verified validators and {len(deposited)} active validators ")
    exit()
    if len(verified) > 0:
        print("Doing activating keys transaction")
        for key in verified:
            issuer = Issuer(a['abi'], contract_address, eth1_endpoint)
            issuer.set_account(private_key)
            if Web3.fromWei(issuer.web3_eth.eth.get_balance(Web3.toChecksumAddress(contract_address)), "ether") > 32:
                tx = issuer.depositToEth2(key)
                issuer.do_transaction(tx)
            else:
                print(
                    f"Balance of pool low for activation. \nCurrent balance: {Web3.fromWei(issuer.web3_eth.eth.get_balance(Web3.toChecksumAddress(contract_address)), 'ether')}")
                del issuer
                break
            del issuer
    else:
        print("No activating deposit pending")


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Keys activation script for node operators")
    required = parser.add_argument_group("required arguments")
    required.add_argument("-eth1", "--ethereum-endpoint",
                          help="either a websocket or http endpoint(Eg:http://127.0.0.1:8545)",
                          required=True)
    required.add_argument("-graph", "--graph-endpoint",
                          help="http endpoint to graph node for queries(Eg: http://localhost:8000/subgraphs/name/keysmanager)",
                          required=True)
    required.add_argument("-priv", "--private-key",
                          help="private key associated with the account whitelisted with pstake stketh to make the transaction",
                          required=True)
    parser.add_argument("-contract", "--contract-address", help="contract address to make the transaction to",
                        default="0x2aDd159D38d9Dd1d980Bc017666073F91823d56d")
    parser.add_argument("-abi", "--contract-abi", help="telegram channel id bot is subscribed to for sending error",
                        default="contracts/Issuer.json")
    args = parser.parse_args()
    print(args)
    main(args.ethereum_endpoint, args.graph_endpoint, args.private_key, args.contract_address, args.contract_abi)
