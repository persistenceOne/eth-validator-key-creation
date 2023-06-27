import argparse
import json
import time
import traceback

from web3 import Web3
from staking_deposit.exceptions import ValidationError
from staking_deposit.key_handling.key_derivation.mnemonic import get_mnemonic
from staking_deposit.utils.constants import WORD_LISTS_PATH, MIN_DEPOSIT_AMOUNT, MAX_DEPOSIT_AMOUNT
from staking_deposit.settings import get_chain_setting, MAINNET, PRATER, GOERLI
from staking_deposit.utils.validation import verify_deposit_data_json
from staking_deposit.validator_key import ValidatorKey, DepositData
from utils.helpers import Helpers, Subgraph
from utils.eth_connector import EthNode
from utils.contracts import Issuer, DepositContract, KeysManager
from staking_deposit.key_handling.keystore import Keystore


def generate_keys(args):
    """

    :param args:
    :return:
    """
    if args.mnemonic is None:
        args.mnemonic = get_mnemonic(language="english", words_path=WORD_LISTS_PATH)
        print("""==================\nGENERATED A MNEMONIC FOR YOUR VALIDATOR KEYS:
        \n\n{} \n \nPlease save it for future use as a backup mechanism \n================== """.format(args.mnemonic))
    if args.index is None:
        args.index = 0
        print("No index was supplied. Taking 0 as a validator starting index")
    keys = ValidatorKey()
    if args.testnet:
        keystore_files, deposit_file = keys.generate_keys(args.mnemonic, int(args.index), int(args.number), "",
                                                          GOERLI,
                                                          args.passphrase, Web3.toChecksumAddress(args.withdrawal),
                                                          MAX_DEPOSIT_AMOUNT)
    else:
        keystore_files, deposit_file = keys.generate_keys(args.mnemonic, int(args.index), int(args.number), "",
                                                          MAINNET,
                                                          args.passphrase,
                                                          Web3.toChecksumAddress(args.withdrawal),
                                                          MAX_DEPOSIT_AMOUNT)

    print("====================")
    print("keystore files for your validators can be found at:")
    print(keystore_files)
    print("deposit data file for your validators can be found at:")
    print(deposit_file)
    print("====================")


def start_staking(args):
    """

    :param args:
    :return:
    """
    print(args)
    config = Helpers.read_file(args.config)
    print(config)
    with open("stateFile.json", "r") as file:
        state = json.load(file)  # used to store the state of the system
    file.close()
    try:
        while True:
            subgraph = Subgraph(config.subgraph_endpoint)
            eth_node = EthNode(config.eth_endpoint, args.private_key)
            verified_keys = subgraph.get_verified_result(eth_node.account.address)["data"]["validators"]
            unverified_keys = subgraph.get_unverified_result(eth_node.account.address)["data"]["validators"]
            issuer_contract = Issuer(config.contracts.issuer, eth_node.eth_node, "./utils/Issuer.json")
            keys_manager_contract = KeysManager(config.contracts.keysManager, eth_node.eth_node,
                                                "./utils/KeysManager.json")
            deposit_contract = DepositContract(config.contracts.deposit, eth_node.eth_node,
                                               "./utils/DepositContract.json")
            keys = len(verified_keys) + len(unverified_keys)
            for key in verified_keys:
                if eth_node.get_balance(config.contracts.issuer) > 32:
                    print("Submitting Key to Issuer contract for deposit")
                    tx = issuer_contract.deposit_beacon(key["publicKey"], eth_node.account.address)
                    eth_node.make_tx(tx)
                else:
                    keys -= 1

            if keys == 0 and len(state) == 0:
                print("You don't have any key that needs to be deposited. Creating new keys")
                keys = ValidatorKey()
                if args.mnemonic is None:
                    args.mnemonic = get_mnemonic(language="english", words_path=WORD_LISTS_PATH)
                    print("""==================\nGENERATED A MNEMONIC FOR YOUR VALIDATOR KEYS:
                    \n\n{} \n \nPlease save it for future use as a backup mechanism \n================== """.format(
                        args.mnemonic))
                if args.index is None:
                    args.index = 0
                    print("No index was supplied. Taking 0 as a validator starting index")
                if args.testnet:
                    keystore_files, deposit_file = keys.generate_keys(args.mnemonic, int(args.index),
                                                                      config.validator_count, "", GOERLI,
                                                                      config.validator_key_passphrase,
                                                                      Web3.toChecksumAddress(
                                                                          config.contracts.withdrawal_address),
                                                                      MIN_DEPOSIT_AMOUNT)
                else:
                    keystore_files, deposit_file = keys.generate_keys(args.mnemonic, int(args.index),
                                                                      config.validator_count, "", MAINNET,
                                                                      config.validator_key_passphrase,
                                                                      Web3.toChecksumAddress(
                                                                          config.contracts.withdrawal_address),
                                                                      MIN_DEPOSIT_AMOUNT)
                print("making deposit to deposit contract and pSTAKE contract")
                state["deposit_file"] = deposit_file
                for index, cred in enumerate(keys.get_deposit_data(deposit_file)):
                    state[cred.pubkey] = {"file": keystore_files[index], "deposited": False}
                args.index += 2
                for index, cred in enumerate(keys.get_deposit_data(deposit_file)):
                    tx = deposit_contract.deposit_validator("0x" + cred.pubkey,
                                                            "0x" + cred.withdrawal_credentials,
                                                            "0x" + cred.signature,
                                                            "0x" + cred.deposit_data_root,
                                                            eth_node.account.address)
                    eth_node.make_tx(tx)
                    print("deposited to the deposit contract")
                    state[cred.pubkey]["deposited"] = True
                    secret = Keystore.from_file(keystore_files[index])
                    priv_key = int.from_bytes(secret.decrypt(config.validator_key_passphrase), 'big')
                    pubkey = bytes(bytearray.fromhex(secret.pubkey))
                    withdrawal_credentials = bytes(bytearray.fromhex(cred.withdrawal_credentials))
                    if args.testnet:
                        signature = Helpers.generate_deposit_signature_from_priv_key(GOERLI, priv_key,
                                                                                     pubkey,
                                                                                     withdrawal_credentials)
                    else:
                        signature = Helpers.generate_deposit_signature_from_priv_key(MAINNET, priv_key,
                                                                                     pubkey,
                                                                                     withdrawal_credentials)
                    tx = keys_manager_contract.add_validator("0x" + cred.pubkey, signature, eth_node.account.address)
                    eth_node.make_tx(tx)
                    print("deposited to the pSTAKE contract")
                    del state[cred.pubkey]
                state = {}
            elif len(state) != 0:
                keys = ValidatorKey()
                for index, cred in enumerate(keys.get_deposit_data(state["deposit_file"])):
                    if cred.pubkey in state:
                        if not state[cred.pubkey]["deposited"]:
                            tx = deposit_contract.deposit_validator("0x" + cred.pubkey,
                                                                    "0x" + cred.withdrawal_credentials,
                                                                    "0x" + cred.signature,
                                                                    "0x" + cred.deposit_data_root,
                                                                    eth_node.account.address)
                            eth_node.make_tx(tx)
                            print("deposited to the deposit contract")
                            state[cred.pubkey]["deposited"] = True

                        secret = Keystore.from_file(state[cred.pubkey]["file"])
                        priv_key = int.from_bytes(secret.decrypt(config.validator_key_passphrase), 'big')
                        pubkey = bytes(bytearray.fromhex(secret.pubkey))
                        withdrawal_credentials = bytes(bytearray.fromhex(cred.withdrawal_credentials))
                        if args.testnet:
                            signature = Helpers.generate_deposit_signature_from_priv_key(GOERLI, priv_key,
                                                                                         pubkey,
                                                                                         withdrawal_credentials)
                        else:
                            signature = Helpers.generate_deposit_signature_from_priv_key(MAINNET, priv_key,
                                                                                         pubkey,
                                                                                         withdrawal_credentials)
                        tx = keys_manager_contract.add_validator(Web3.toBytes(hexstr="0x" + cred.pubkey),
                                                                 Web3.toBytes(hexstr="0x" + signature),
                                                                 eth_node.account.address)
                        eth_node.make_tx(tx)
                        print("deposited to the pSTAKE contract")
                        del state[cred.pubkey]
                state = {}
            print("sleeping for 600 sec as no keys to be generated now")
            time.sleep(600)
    except Exception as err:
        print("ERROR! SCRIPT STOPPED!!")
        print(traceback.format_exc())
        print(err)
        with open("stateFile.json", "w") as file:
            json.dump(state, file)  # used to store the state of the system
        file.close()


# {'data': {'validators': [{'id': '0x90b406f5ddcfce59a4876bf976db8ed245f7cdc213171104438e123fd4cbbe728ad9b965ebb39525c34e4a768700d068', 'signature': '0xa9ea4c502bac6f30080ce517f132a8a8fb01041bca4970fa5a800b4fbd4b26b6a31560a2aa5b9757b075f7f9c7b49ce90dc1216c24052ad28f6bb735f6b6260d5f148715d56e2e46e2b6030a8771f485d4b3b86cf13ef00398c91385d8dd41a9', 'publicKey': '0x90b406f5ddcfce59a4876bf976db8ed245f7cdc213171104438e123fd4cbbe728ad9b965ebb39525c34e4a768700d068', 'nodeOperator': '0xfb1eeed1f21645c62c622a5e90e1cf49665b8ea4', 'status': 'DEPOSITED'}, {'id': '0x92ae457d1eabc84a9508354bf4a9d9ecc39cf89ad29051b4269b7e47f6aff103a665557bf235cce05628d846539dad5c', 'signature': '0xaf8ea5a6055d426f239abe64e8bf9f0b3af788ed2bcbbe66f989eccaa737115a588be49cb72d65439b0941af5783319f0cd8328a1053acffc754637e92d45d2a43147b88233dfefebe4e30ffa143bdda8e22cb6e98e1361340bfe33de1383861', 'publicKey': '0x92ae457d1eabc84a9508354bf4a9d9ecc39cf89ad29051b4269b7e47f6aff103a665557bf235cce05628d846539dad5c', 'nodeOperator': '0xfb1eeed1f21645c62c622a5e90e1cf49665b8ea4', 'status': 'VERIFIED'}, {'id': '0x93aad8845eb5fef409c920a4971fc766c679178d7fb832dcb14e48e23289556a7fb4b475611856466387ce7dca50d377', 'signature': '0xaa83efaf4349108ccd37bfacbffe97baa736d57329ffb5692c1531b17027a6f7ae57dbcc317b4ba865a3e509d74f95590ed74067ddef1dd50a41cfe93ca7a67acf4dd7ee3c853c9619ad7e2eac82d8abe619f3756cc6ab24b415823efd7765f2', 'publicKey': '0x93aad8845eb5fef409c920a4971fc766c679178d7fb832dcb14e48e23289556a7fb4b475611856466387ce7dca50d377', 'nodeOperator': '0xfb1eeed1f21645c62c622a5e90e1cf49665b8ea4', 'status': 'VERIFIED'}, {'id': '0xa74334aefd100ab6794f7b2def00209f29fcdd87d40b7b20f9d2f33546e1a2ced0bd3f29fc0c4141f641154ef0afa28b', 'signature': '0xb666334c19a9c70d7cc863526732aa9724de1e182b79a3404999e8a0cc2ec574ead96004f4b525f1d164a9c14773f8cf10b9ddceefd7a685a970f72219cda021be55422164a30b1926b3aa14da2c22bbd70a046e1332edd39f9d056d9081f16a', 'publicKey': '0xa74334aefd100ab6794f7b2def00209f29fcdd87d40b7b20f9d2f33546e1a2ced0bd3f29fc0c4141f641154ef0afa28b', 'nodeOperator': '0xfb1eeed1f21645c62c622a5e90e1cf49665b8ea4', 'status': 'VERIFIED'}]}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="""Keys generation script for node operators. 
                                        Refer README for instructions""")
    parser.add_argument("-t", "--testnet", help="if running on testnet", required=False, default=False, type=bool)
    subparsers = parser.add_subparsers()
    start = subparsers.add_parser("start", help="""This option can be used to generate validator keys and deposit them to 
                                                 ethereum deposit contract as well as pSTAKE protocol for activation""",
                                  parents=[parser], add_help=False)
    start.set_defaults(which="start")
    start.add_argument("-c", "--config", help="Config file for running the script", required=True)
    start.add_argument("-priv", "--private-key",
                       help="private key associated with the account whitelisted with pSTAKE to make the transaction",
                       required=True)
    start.add_argument("-m", "--mnemonic",
                       help="mnemonic to generate validator keys. If not present the script will generate one",
                       required=False)
    start.add_argument("-i", "--index",
                       help="""starting index for the validator keys to be generated. 
                               If using mnemonic, supply this or else the system will assume 0 to be starting index""",
                       required=False)
    generate = subparsers.add_parser("generate", help="Generate validator keys", parents=[parser], add_help=False)
    generate.set_defaults(which="generate")

    generate.add_argument("-m", "--mnemonic",
                          help="mnemonic to generate validator keys. If not present the script will generate one",
                          required=False)
    generate.add_argument("-n", "--number",
                          help="number of validators to be generated",
                          required=True)
    generate.add_argument("-w", "--withdrawal",
                          help="withdrawal address to set",
                          required=True)
    generate.add_argument("-i", "--index",
                          help="""starting index for the validator keys to be generated. 
                               If using mnemonic, supply this or else the system will assume 0 to be starting index""",
                          required=False)
    generate.add_argument("-p", "--passphrase",
                          help="passphrase to use for the keys. If not present no passphrase will be used",
                          required=False, default="")
    args = parser.parse_args()
    if args.which == "start":
        start_staking(args)
    elif args.which == "generate":
        generate_keys(args)
    else:
        raise ValidationError("Invalid argument given")
