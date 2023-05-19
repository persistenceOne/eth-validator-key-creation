import json
import pathlib
from web3 import Web3


class EthereumContract:
    contract = None
    web3: Web3 = None

    def __init__(self, address, _web3: Web3, abi_path):
        abi = self._import_abi(filepath=abi_path)
        self.web3 = _web3
        self.contract = self.web3.eth.contract(abi=abi, address=address)

    def _import_abi(self, filepath):
        with open(filepath, "r") as file:
            abi = json.load(file)["abi"]
        file.close()
        return abi


class KeysManager(EthereumContract):

    def add_validator(self, public_key, signature, node_operator_address):
        return self.contract.functions.addValidator(public_key, signature, node_operator_address).build_transaction(
            {"from": node_operator_address})


class DepositContract(EthereumContract):
    def deposit_validator(self, public_key, withdrawal_credentials, signature, deposit_data_root,
                          node_operator_address):
        return self.contract.functions.deposit(public_key, withdrawal_credentials, signature,
                                               deposit_data_root).build_transaction(
            {"from": node_operator_address, "value": Web3.to_wei(1, "ether")})


class Issuer(EthereumContract):

    def deposit_beacon(self, public_key, node_operator_address):
        return self.contract.functions.depositToEth2(public_key).build_transaction({"from": node_operator_address})
