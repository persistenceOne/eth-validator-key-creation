import argparse

from eth_utils import to_canonical_address
from web3 import Web3
from py_ecc.bls import G2ProofOfPossession as bls

from eth2deposit.key_handling.keystore import Keystore
from eth2deposit.utils.ssz import DepositMessage, compute_signing_root, compute_deposit_domain, DepositData
from web3.gas_strategies.rpc import rpc_gas_price_strategy

from eth2deposit.utils.constants import WORD_LISTS_PATH, MAX_DEPOSIT_AMOUNT, ETH1_ADDRESS_WITHDRAWAL_PREFIX
from eth2deposit.settings import get_chain_setting, MAINNET, PRATER


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


def get_priv_key_sk(keystore_filefolder: str, password: str) -> int:
    """

    :return:
    """
    saved_keystore = Keystore.from_file(keystore_filefolder)
    secret_bytes = saved_keystore.decrypt(password)
    return int.from_bytes(secret_bytes, 'big')


def signing_pk(signing_sk) -> bytes:
    return bls.SkToPk(signing_sk)


def withdrawal_credentials(withdrawal_cred) -> bytes:
    withdrawal_credentials = ETH1_ADDRESS_WITHDRAWAL_PREFIX
    withdrawal_credentials += b'\x00' * 11
    withdrawal_credentials += to_canonical_address(withdrawal_cred)
    return withdrawal_credentials


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
    tx['gasPrice'] = int(1.5*web3_eth.eth.generate_gas_price(tx))
    signed_tx = web3_eth.eth.account.sign_transaction(tx, account.key)
    tx_hash = web3_eth.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3_eth.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
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
    current_nonce = web3_eth.eth.get_transaction_count(account.address)
    del web3_eth, account

    for validator_key in args.validator_priv_keys:
        web3_eth, account = connect_to_eth(args.ethereum_endpoint, args.private_key)
        sk_key = get_priv_key_sk(validator_key, args.keystore_password)
        pubkey = signing_pk(sk_key)
        print(pubkey.hex())
        withdrawal_creds = withdrawal_credentials("0x5945bfe76789c79f54C634f6f704d5400491C90a")
        print(withdrawal_creds.hex())
        signature_new = generate_deposit_signature_from_priv_key(sk_key, pubkey, withdrawal_creds)
        print(signature_new)
        submit_key(web3_eth, account, keysmanager_contract, signature_new, pubkey.hex(), current_nonce)
        del web3_eth, account
        current_nonce += 1


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
    required.add_argument("-keys", "--validator-priv-keys", nargs="*",
                          help="List of private key for which the transaction failed",
                          required=True)
    parser.add_argument("-kc", "--keysmanager-contract-address", help="contract address to make the transaction to",
                        default="0xD90BA04ada98b08105Eab75899dbf9cb9f2910C2")
    parser.add_argument("-kabi", "--keysmanager-contract-abi",
                        help="telegram channel id bot is subscribed to for sending error",
                        default="contracts/keysmanager.json")
    args = parser.parse_args()
    main(args)
