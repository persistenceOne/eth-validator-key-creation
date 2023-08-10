import argparse
import json
import time
import traceback
from web3 import Web3
import logging
from staking_deposit.exceptions import ValidationError
from staking_deposit.key_handling.key_derivation.mnemonic import get_mnemonic
from staking_deposit.utils.constants import WORD_LISTS_PATH, MIN_DEPOSIT_AMOUNT, MAX_DEPOSIT_AMOUNT
from staking_deposit.settings import MAINNET, GOERLI
from staking_deposit.validator_key import ValidatorKey
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
    logging.info("Arguments supplied")
    logging.info(args)
    config = Helpers.read_file(args.config)
    logging.info("Config file supplied:")
    logging.info(config)
    statefile_path = "stateFile.json" if args.key_folder == '' else args.key_folder + "/stateFile.json"
    with open(statefile_path, "r") as file:
        state = json.load(file)  # used to store the state of the system
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
            keys_count = len(verified_keys) + len(unverified_keys) - config.keys_override
            for key in verified_keys:
                if eth_node.get_balance(config.contracts.issuer) > 32:
                    logging.info("Submitting Key to Issuer contract for deposit")
                    tx = issuer_contract.deposit_beacon(key["publicKey"], eth_node.account.address)
                    eth_node.make_tx(tx)
                keys_count -= 1
            logging.info("keys that need activation:" + str(keys_count))
            if keys_count == 0 and len(state["keys"]) == 0:
                logging.info("You don't have any key that needs to be deposited. Creating new keys")
                keys = ValidatorKey()
                if args.mnemonic is None:
                    args.mnemonic = get_mnemonic(language="english", words_path=WORD_LISTS_PATH)
                    logging.warning("No mnemonic is supplied. If this was not intended STOP THE SCRIPT!!")
                    logging.warning("""==================\nGENERATED A MNEMONIC FOR YOUR VALIDATOR KEYS:
                    \n\n{} \n \nPlease save it for future use as a backup mechanism \n================== """.format(
                        args.mnemonic))
                if "mnemonic" not in state.keys() or state["mnemonic"] == "":
                    state["mnemonic"] = Web3.keccak(text=args.mnemonic).hex()
                else:
                    if state["mnemonic"] != Web3.keccak(text=args.mnemonic).hex():
                        logging.warning(
                            "A new mnemonic was supplied which is different from last time. If this was not intended STOP THE SCRIPT!!")
                        state["mnemonic"] = Web3.keccak(text=args.mnemonic).hex()
                        if "index" not in state.keys():
                            logging.warning(
                                "No index found in the statefile. Using 0 as index. If this was not intended STOP THE SCRIPT!!")
                            state["index"] = 0

                if eth_node.eth_node.eth.chain_id == 5:
                    logging.debug("generating keys for testnet")
                    keystore_files, deposit_file = keys.generate_keys(args.mnemonic, int(state["index"]),
                                                                      config.validator_count, args.key_folder, GOERLI,
                                                                      config.validator_key_passphrase,
                                                                      Web3.toChecksumAddress(
                                                                          config.contracts.withdrawal_address),
                                                                      MIN_DEPOSIT_AMOUNT)
                    logging.info("validator keys are:")
                    logging.info(keystore_files)
                    logging.info("deposit file:")
                    logging.info(deposit_file)
                else:
                    logging.debug("generating keys for mainnet")
                    keystore_files, deposit_file = keys.generate_keys(args.mnemonic, int(state["index"]),
                                                                      config.validator_count, args.key_folder, MAINNET,
                                                                      config.validator_key_passphrase,
                                                                      Web3.toChecksumAddress(
                                                                          config.contracts.withdrawal_address),
                                                                      MIN_DEPOSIT_AMOUNT)
                    logging.info("validator keys are:")
                    logging.info(keystore_files)
                    logging.info("deposit file:")
                    logging.info(deposit_file)
                logging.info("making deposit to deposit contract and pSTAKE contract")
                state["keys"]["deposit_file"] = deposit_file
                for index, cred in enumerate(keys.get_deposit_data(deposit_file)):
                    state["keys"][cred.pubkey] = {"file": keystore_files[index], "deposited": False}
                state["index"] += config.validator_count
                for index, cred in enumerate(keys.get_deposit_data(deposit_file)):
                    tx = deposit_contract.deposit_validator("0x" + cred.pubkey,
                                                            "0x" + cred.withdrawal_credentials,
                                                            "0x" + cred.signature,
                                                            "0x" + cred.deposit_data_root,
                                                            eth_node.account.address)
                    eth_node.make_tx(tx)
                    logging.info("deposited to the deposit contract")
                    state["keys"][cred.pubkey]["deposited"] = True
                    secret = Keystore.from_file(keystore_files[index])
                    priv_key = int.from_bytes(secret.decrypt(config.validator_key_passphrase), 'big')
                    pubkey = bytes(bytearray.fromhex(secret.pubkey))
                    withdrawal_credentials = bytes(bytearray.fromhex(cred.withdrawal_credentials))
                    logging.debug("generating signature to submit to pSTAKE")
                    if eth_node.eth_node.eth.chain_id == 5:
                        logging.debug("generating signature for testnet")
                        signature = Helpers.generate_deposit_signature_from_priv_key(GOERLI, priv_key,
                                                                                     pubkey,
                                                                                     withdrawal_credentials)
                    else:
                        logging.debug("generating signature for mainnet")
                        signature = Helpers.generate_deposit_signature_from_priv_key(MAINNET, priv_key,
                                                                                     pubkey,
                                                                                     withdrawal_credentials)
                    logging.debug("verifying the signature generated")
                    if Helpers.check_signature(eth_node.eth_node.eth.chain_id, "0x" + cred.pubkey,
                                               "0x" + cred.withdrawal_credentials, signature):
                        tx = keys_manager_contract.add_validator("0x" + cred.pubkey, signature,
                                                                 eth_node.account.address)

                        eth_node.make_tx(tx)
                    logging.info("deposited to the pSTAKE contract")
                    del state["keys"][cred.pubkey]
            elif len(state["keys"]) != 0:
                logging.info("retrying failed tx from state file")
                keys = ValidatorKey()
                for index, cred in enumerate(keys.get_deposit_data(state["keys"]["deposit_file"])):
                    if cred.pubkey in state["keys"]:
                        if not state["keys"][cred.pubkey]["deposited"]:
                            tx = deposit_contract.deposit_validator("0x" + cred.pubkey,
                                                                    "0x" + cred.withdrawal_credentials,
                                                                    "0x" + cred.signature,
                                                                    "0x" + cred.deposit_data_root,
                                                                    eth_node.account.address)
                            eth_node.make_tx(tx)
                            logging.info("deposited to the deposit contract")
                            state["keys"][cred.pubkey]["deposited"] = True
                        secret = Keystore.from_file(state["keys"][cred.pubkey]["file"])
                        priv_key = int.from_bytes(secret.decrypt(config.validator_key_passphrase), 'big')
                        pubkey = bytes(bytearray.fromhex(secret.pubkey))
                        withdrawal_credentials = bytes(bytearray.fromhex(cred.withdrawal_credentials))
                        logging.debug("generating signature to submit to pSTAKE")
                        if eth_node.eth_node.eth.chain_id == 5:
                            logging.debug("generating signature for testnet")
                            signature = Helpers.generate_deposit_signature_from_priv_key(GOERLI, priv_key,
                                                                                         pubkey,
                                                                                         withdrawal_credentials)
                        else:
                            logging.debug("generating signature for mainnet")
                            signature = Helpers.generate_deposit_signature_from_priv_key(MAINNET, priv_key,
                                                                                         pubkey,
                                                                                         withdrawal_credentials)
                        logging.debug("verifying the signature generated")
                        if Helpers.check_signature(eth_node.eth_node.eth.chain_id, "0x" + cred.pubkey,
                                                   "0x" + cred.withdrawal_credentials, signature):
                            tx = keys_manager_contract.add_validator(Web3.toBytes(hexstr="0x" + cred.pubkey),
                                                                     Web3.toBytes(hexstr="0x" + signature),
                                                                     eth_node.account.address)
                            eth_node.make_tx(tx)
                        logging.info("deposited to the pSTAKE contract")
                        del state["keys"][cred.pubkey]
                state["keys"] = {}
            with open(statefile_path, "w") as file:
                json.dump(state, file)  # used to store the state of the system
            logging.info("sleeping for 600 sec as no keys to be generated now")
            time.sleep(600)
    except Exception as err:
        logging.error("ERROR! SCRIPT STOPPED!!")
        logging.error(err)
        print(traceback.format_exc())
        with open(statefile_path, "w") as file:
            json.dump(state, file)  # used to store the state of the system


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
    start.add_argument("-kf", "--key-folder", help="folder where keys will be stored", required=False, default="")
    start.add_argument("-priv", "--private-key",
                       help="private key associated with the account whitelisted with pSTAKE to make the transaction",
                       required=True)
    start.add_argument("-m", "--mnemonic",
                       help="mnemonic to generate validator keys. If not present the script will generate one",
                       required=False)
    start.add_argument('-d', '--debug', help="Print logs used for debugging", action="store_const", dest="loglevel",
                       const=logging.DEBUG, default=logging.WARNING)
    start.add_argument('-v', '--verbose', help="Verbose Logging", action="store_const", dest="loglevel",
                       const=logging.INFO)
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
        logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=args.loglevel)
        logging.info(args)
        logging.info("pSTAKE validator key creation started at started at: {}".format(time.time()))
        logging.getLogger("web3.RequestManager").setLevel(logging.WARNING)
        logging.getLogger("web3.providers.HTTPProvider").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        start_staking(args)
    elif args.which == "generate":
        generate_keys(args)
    else:
        raise ValidationError("Invalid argument given")
