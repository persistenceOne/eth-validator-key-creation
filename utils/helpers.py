import json
from collections import namedtuple

import requests
from py_ecc.bls import G2ProofOfPossession as bls

from staking_deposit.settings import get_chain_setting
from staking_deposit.utils.ssz import DepositMessage, compute_deposit_domain, compute_signing_root


class Helpers:
    @staticmethod
    def read_file(file_path):
        """
        This is used to read params from json file and convert them to python Namespaces
        :param file_path: takes the json filepath
        :returns: it returns data in form of python Namespace
        """
        with open(file_path, "r") as file:
            data = json.load(file, object_hook=lambda d: namedtuple(
                'X', d.keys())(*d.values()))
        file.close()
        return data

    @staticmethod
    def generate_deposit_signature_from_priv_key(chain: str, private_key: int, public_key: bytes,
                                                 withdraw_credenttials: bytes,
                                                 amount: int = 31000000000):
        deposit_data = DepositMessage(
            pubkey=public_key,
            withdrawal_credentials=withdraw_credenttials,
            amount=amount,
        )
        domain = compute_deposit_domain(fork_version=get_chain_setting(chain).GENESIS_FORK_VERSION)
        signing_root = compute_signing_root(deposit_data, domain)
        signature = bls.Sign(private_key, signing_root)
        return signature.hex()


class Subgraph:
    graph_url = None

    def __init__(self, graph_url):
        self.graph_url = graph_url

    def get_verified_result(self, node_operator_address):
        query = """{
                validators(where:{nodeOperator:"node_operator_address",status:"VERIFIED"}) {
                    id
                    signature
                    publicKey
                    nodeOperator
                    status
                    }
                    }
                """.replace("node_operator_address", node_operator_address)
        response = requests.post(self.graph_url, json={'query': query})
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

    def get_unverified_result(self, node_operator_address):
        query = """{
                validators(where:{nodeOperator:"node_operator_address",status:"UNVERIFIED"}) {
                    id
                    signature
                    publicKey
                    nodeOperator
                    status
                    }
                    }
                """.replace("node_operator_address", node_operator_address)
        response = requests.post(self.graph_url, json={'query': query})
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()
