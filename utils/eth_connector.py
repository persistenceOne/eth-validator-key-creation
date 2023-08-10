import logging
import traceback

from web3 import Web3
from web3.exceptions import TimeExhausted
from web3.gas_strategies.time_based import fast_gas_price_strategy


class EthNode:
    account = None
    eth_node = None
    local = False

    def __init__(self, rpc_url, private_key):
        self.eth_node = Web3(Web3.HTTPProvider(rpc_url))
        self.eth_node.eth.set_gas_price_strategy(fast_gas_price_strategy)
        self.account = self.eth_node.eth.account.from_key(
            private_key)

    def make_tx(self, tx):
        logging.debug(tx)
        tx['gas'] = 3 * tx['gas']
        if tx['gasPrice'] < Web3.toWei("10", "gwei"):
            tx['gasPrice'] = Web3.toWei("10", "gwei")
        self.eth_node.eth.call(tx)
        tx['nonce'] = self.eth_node.eth.get_transaction_count(
            self.account.address)
        try:
            signed_tx = self.eth_node.eth.account.sign_transaction(
                tx, self.account.key)
            tx_hash = self.eth_node.eth.send_raw_transaction(
                signed_tx.rawTransaction)
            tx_receipt = self.eth_node.eth.wait_for_transaction_receipt(tx_hash)
            if tx_receipt.status == 1:
                logging.info('TX successful')
                return True
            else:
                logging.info('TX reverted')
                return False
        except TimeExhausted as err:
            logging.error("time exhausted while waiting for tx to complete")
            logging.error(err)
            print(traceback.format_exc())

    def get_balance(self, address):
        return self.eth_node.eth.get_balance(address) / 10 ** 18
