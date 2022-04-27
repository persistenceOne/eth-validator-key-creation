import json
import sys

import requests
from web3 import Web3


class KeysSubgraph:
    url = None

    def __init__(self, url):
        self.url = url

    def get_validators(self, address: str):
        query = """ {
  validators(where: {nodeOperator: "address"}) {
    id
    nodeOperator
    publicKey
    signature
    status
  }
        }
          """.replace("address", address)
        response = requests.post(self.url, json={'query': query})
        return response.json()["data"]["validators"]


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


if __name__ == '__main__':
    with open("contracts/Issuer.json", 'r') as file:
        a = json.load(file)
    issuer = Issuer(a['abi'], "0x2aDd159D38d9Dd1d980Bc017666073F91823d56d", sys.argv[1])
    issuer.set_account(sys.argv[2])
    subgraph = KeysSubgraph(sys.argv[3])
    validators = subgraph.get_validators(issuer.account.address)
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
    print(f"You have {len(unverified)} unverified validators, {len(verified)} verified validators and {len(deposited)} active validators ")
    if len(verified) > 0:
        print("doing activating keys transaction")
        for key in verified:
            if issuer.web3_eth.eth.get_balance(issuer.account.address)/10**16 > 32:
                tx = issuer.depositToEth2(key)
                issuer.do_transaction(tx)
            else:
                print("balance of pool low for activation")
                break
    else:
        print("No activating deposit pending")



