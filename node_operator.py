import argparse

from web3 import Web3
from py_ecc.bls import G2ProofOfPossession as bls
from eth2deposit.utils.ssz import DepositMessage, compute_signing_root, compute_deposit_domain, DepositData
import os
from web3.gas_strategies.rpc import rpc_gas_price_strategy

from eth_typing import HexAddress, HexStr
from eth2deposit.credentials import CredentialList
from eth2deposit.exceptions import ValidationError
from eth2deposit.key_handling.key_derivation.mnemonic import get_mnemonic
from eth2deposit.utils.constants import WORD_LISTS_PATH, MAX_DEPOSIT_AMOUNT
from eth2deposit.settings import get_chain_setting, MAINNET, PRATER
from eth2deposit.utils.validation import verify_deposit_data_json


def connect_to_eth(eth_endpoint, private_key):
    web3_eth = Web3(Web3.HTTPProvider(eth_endpoint))
    web3_eth.isConnected()
    # web3_eth.middleware_onion.inject(geth_poa_middleware, layer=0)
    # gas_strategy = construct_time_based_gas_price_strategy(120, sample_size=120, probability=98, weighted=False)
    web3_eth.eth.set_gas_price_strategy(rpc_gas_price_strategy)
    # for time based gas price strategy
    # web3_eth.middleware_onion.add(middleware.time_based_cache_middleware)
    # web3_eth.middleware_onion.add(middleware.latest_block_based_cache_middleware)
    # web3_eth.middleware_onion.add(middleware.simple_cache_middleware)
    account = web3_eth.eth.account.privateKeyToAccount(private_key)
    web3_eth.eth.account.enable_unaudited_hdwallet_features()
    return web3_eth, account


def generate_keys(mnemonic, validator_start_index: int,
                  num_validators: int, folder: str, chain: str, keystore_password: str,
                  eth1_withdrawal_address: HexAddress):
    amounts = [1000000000] * num_validators
    folder = os.path.join(folder, "node_operator")
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


def generate_deposit_signature_from_priv_key(private_key: int, public_key: bytes,
                                             withdraw_credenttials: bytes,
                                             amount: int = 31000000000):
    deposit_data = DepositMessage(
        pubkey=public_key,
        withdrawal_credentials=withdraw_credenttials,
        amount=amount,
    )
    domain = compute_deposit_domain(fork_version=get_chain_setting(MAINNET).GENESIS_FORK_VERSION)
    signing_root = compute_signing_root(deposit_data, domain)
    signature = bls.Sign(private_key, signing_root)
    return signature.hex()


def submit_key(web3_eth, account, keysmanager_contract, signature, publkey, nonce):
    tx = keysmanager_contract.functions.addValidator(publkey,
                                                     signature,
                                                     account.address).buildTransaction(
        ({'from': account.address}))
    print(tx)
    web3_eth.eth.call(tx)
    tx['nonce'] = nonce
    tx['gas'] = web3_eth.eth.estimate_gas(tx)
    tx['gasPrice'] = 1.5*web3_eth.eth.generate_gas_price(tx)
    signed_tx = web3_eth.eth.account.sign_transaction(tx, account.key)
    tx_hash = web3_eth.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3_eth.eth.wait_for_transaction_receipt(tx_hash,timeout=300)
    print(tx_receipt)
    if tx_receipt.status == 1:
        print('TX successful')
    else:
        print('TX reverted')


def deposit_to_eth2_contract(web3_eth, account, depositcontract, pubkey, withdrawal_credentials, signature,
                             deposit_data_root, nonce):
    tx = depositcontract.functions.deposit(
        pubkey, withdrawal_credentials, signature, deposit_data_root).buildTransaction(
        {'from': account.address,"value": web3_eth.toWei(1, "ether")})
    print(tx)
    web3_eth.eth.call(tx)
    tx['nonce'] = nonce
    tx['gas'] = web3_eth.eth.estimate_gas(tx)
    tx['gasPrice'] = 1.5*web3_eth.eth.generate_gas_price(tx)
    signed_tx = web3_eth.eth.account.sign_transaction(tx, account.key)
    tx_hash = web3_eth.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3_eth.eth.wait_for_transaction_receipt(tx_hash,timeout=300)
    print(tx_receipt)
    if tx_receipt.status == 1:
        print('TX successful')
    else:
        print('TX reverted')


def main(args):
    web3_eth, account = connect_to_eth(args.ethereum_endpoint, args.private_key)
    with open(args.keysmanager_contract_abi, 'r') as file:
        a = file.read()
    keysmanager_contract = web3_eth.eth.contract(abi=a,
                                                 address=Web3.toChecksumAddress(args.keysmanager_contract_address))
    with open(args.deposit_contract_abi, 'r') as file:
        abi = file.read()
    depositcontract = web3_eth.eth.contract(abi=abi,
                                            address=Web3.toChecksumAddress(args.deposit_contract_address))
    mnemonic = get_mnemonic(language='english', words_path=WORD_LISTS_PATH)
    current_nonce = web3_eth.eth.get_transaction_count(account.address)
    del web3_eth, account
    num_validator = int(args.number_of_keys)
    keystore_password = args.keystore_password
    print(
        f"mnemonic for generation of keys from index 0 to {num_validator - 1} : \n\n {mnemonic} \n\n Please write it down and save it. \n Keystore password: {keystore_password}")

    credentials = generate_keys(mnemonic=mnemonic, validator_start_index=0, num_validators=num_validator,
                                folder="",
                                chain=MAINNET,
                                keystore_password=keystore_password,
                                eth1_withdrawal_address=HexAddress(
                                    HexStr("0x5945bfe76789c79f54C634f6f704d5400491C90a")))

    for credential in credentials.credentials:
        web3_eth, account = connect_to_eth(args.ethereum_endpoint, args.private_key)
        deposit = credential.deposit_datum_dict
        deposit_to_eth2_contract(web3_eth, account, depositcontract, deposit['pubkey'].hex(),
                                 deposit['withdrawal_credentials'].hex(),
                                 deposit['signature'].hex(),
                                 deposit['deposit_data_root'].hex(), current_nonce)

        current_nonce += 1
        signature_new = generate_deposit_signature_from_priv_key(credential.signing_sk,
                                                                 credential.signing_pk,
                                                                 credential.withdrawal_credentials)
        submit_key(web3_eth, account, keysmanager_contract, signature_new, deposit['pubkey'].hex(), current_nonce)
        current_nonce += 1
        del web3_eth, account


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Keys generation script for node operators")
    required = parser.add_argument_group("required arguments")
    required.add_argument("-eth1", "--ethereum-endpoint",
                          help="either a websocket or http endpoint(Eg:http://127.0.0.1:8545)",
                          required=True)
    required.add_argument("-priv", "--private-key",
                          help="private key associated with the account whitelisted with pstake stketh to make the transaction",
                          required=True)
    required.add_argument("-pass", "--keystore-password",
                          help="keystore password for validator public keys",
                          required=True)
    required.add_argument("-n", "--number-of-keys",
                          help="Number of keys to create for submitting to the contract",
                          required=True)
    parser.add_argument("-dc", "--deposit-contract-address", help="contract address to make the transaction to",
                        default="0x00000000219ab540356cBB839Cbe05303d7705Fa")
    parser.add_argument("-dabi", "--deposit-contract-abi",
                        help="telegram channel id bot is subscribed to for sending error",
                        default="contracts/deposit_contract.json")
    parser.add_argument("-kc", "--keysmanager-contract-address", help="contract address to make the transaction to",
                        default="0xD90BA04ada98b08105Eab75899dbf9cb9f2910C2")
    parser.add_argument("-kabi", "--keysmanager-contract-abi",
                        help="telegram channel id bot is subscribed to for sending error",
                        default="contracts/keysmanager.json")
    args = parser.parse_args()
    main(args)
