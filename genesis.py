import time

from web3 import Web3
from web3.middleware import geth_poa_middleware
from py_ecc.bls import G2ProofOfPossession as bls
from eth2deposit.key_handling.keystore import Keystore
from eth2deposit.utils.ssz import DepositMessage, compute_signing_root, compute_deposit_domain, DepositData
import os
from typing import List, Tuple

from eth_typing import HexAddress, HexStr
import sys
from eth2deposit.credentials import CredentialList
from eth2deposit.exceptions import ValidationError
from eth2deposit.key_handling.key_derivation.mnemonic import get_mnemonic
from eth2deposit.utils.constants import WORD_LISTS_PATH, MAX_DEPOSIT_AMOUNT
from eth2deposit.settings import get_chain_setting, MAINNET, PRATER
from eth2deposit.utils.validation import verify_deposit_data_json

web3_eth = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
web3_eth.isConnected()
web3_eth.middleware_onion.inject(geth_poa_middleware, layer=0)
account = web3_eth.eth.account.privateKeyToAccount(sys.argv[1])
web3_eth.eth.account.enable_unaudited_hdwallet_features()
with open("contracts/deposit_contract.json", 'r') as file:
    abi = file.read()
depositcontract = web3_eth.eth.contract(abi=abi, address=Web3.toChecksumAddress(sys.argv[2]))
mnemonic = get_mnemonic(language='english', words_path=WORD_LISTS_PATH)

num_validator = 10
keystore_password = sys.argv[3]
print(keystore_password)


def generate_keys(mnemonic, validator_start_index: int,
                  num_validators: int, folder: str, chain: str, keystore_password: str,
                  eth1_withdrawal_address: HexAddress):
    amounts = [MAX_DEPOSIT_AMOUNT] * num_validators
    folder = os.path.join(folder, "genesis")
    chain_setting = get_chain_setting(chain)
    if not os.path.exists(folder):
        os.mkdir(folder)
    credentials = CredentialList.from_mnemonic(
        mnemonic=mnemonic,
        mnemonic_password="",
        num_keys=num_validators,
        amounts=amounts,
        chain_setting=chain_setting,
        start_index=validator_start_index,
        hex_eth1_withdrawal_address=eth1_withdrawal_address,
    )
    keystore_filefolders = credentials.export_keystores(password=keystore_password, folder=folder)
    print(keystore_filefolders)
    deposits_file = credentials.export_deposit_data_json(folder=folder)
    print(deposits_file)
    if not credentials.verify_keystores(keystore_filefolders=keystore_filefolders, password=keystore_password):
        raise ValidationError("Failed to verify the keystores.")
    if not verify_deposit_data_json(deposits_file, credentials.credentials):
        raise ValidationError("Failed to verify the deposit data JSON files.")
    return credentials


def generate_deposit_signature_from_priv_key(private_key: int, public_key: bytes, withdraw_credenttials: bytes,
                                             amount: int = 2200000000):
    deposit_data = DepositMessage(
        pubkey=public_key,
        withdrawal_credentials=withdraw_credenttials,
        amount=amount,
    )
    domain = compute_deposit_domain(fork_version=bytes.fromhex('00100001'))
    signing_root = compute_signing_root(deposit_data, domain)
    signature = bls.Sign(private_key, signing_root)
    return signature.hex()


def deposit_to_eth2_contract(pubkey, withdrawal_credentials, signature, deposit_data_root):
    tx = depositcontract.functions.deposit(
        pubkey, withdrawal_credentials, signature, deposit_data_root).buildTransaction(
        {'from': account.address, 'gasPrice': web3_eth.toWei('2', 'gwei'), 'gas': 100000,
         "value": web3_eth.toWei(32, "ether")})
    print(tx)
    web3_eth.eth.call(tx)
    tx['nonce'] = web3_eth.eth.get_transaction_count(account.address)
    signed_tx = web3_eth.eth.account.sign_transaction(tx, account.key)
    tx_hash = web3_eth.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3_eth.eth.wait_for_transaction_receipt(tx_hash)
    print(tx_receipt)
    if tx_receipt.status == 1:
        print('TX successful')
    else:
        print('TX reverted')


credentials = generate_keys(mnemonic=mnemonic, validator_start_index=0, num_validators=num_validator, folder="",
                            chain=PRATER,
                            keystore_password=keystore_password,
                            eth1_withdrawal_address=HexAddress(HexStr(account.address)))

for credential in credentials.credentials:
    deposit = credential.deposit_datum_dict
    print(deposit)
    deposit_to_eth2_contract(deposit['pubkey'].hex(), deposit['withdrawal_credentials'].hex(),
                             deposit['signature'].hex(),
                             deposit['deposit_data_root'].hex())
    time.sleep(10)
