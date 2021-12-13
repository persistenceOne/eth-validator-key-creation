import os
from typing import List, Tuple

from eth_typing import HexAddress, HexStr

from eth2deposit.credentials import CredentialList
from eth2deposit.exceptions import ValidationError
from eth2deposit.key_handling.key_derivation.mnemonic import get_mnemonic
from eth2deposit.utils.constants import WORD_LISTS_PATH, MAX_DEPOSIT_AMOUNT
from eth2deposit.settings import get_chain_setting, MAINNET
from eth2deposit.utils.validation import verify_deposit_data_json

mnemonic = get_mnemonic(language='english', words_path=WORD_LISTS_PATH)

num_validator = 2


def generate_keys(mnemonic, validator_start_index: int,
                  num_validators: int, folder: str, chain: str, keystore_password: str,
                  eth1_withdrawal_address: HexAddress) -> Tuple[str, List[str]]:
    amounts = [MAX_DEPOSIT_AMOUNT] * num_validators
    folder = os.path.join(folder, "keys")
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
    return deposits_file, keystore_filefolders


generate_keys(mnemonic=mnemonic, validator_start_index=0, num_validators=num_validator, folder="", chain=MAINNET,
              keystore_password="qawsedrf",
              eth1_withdrawal_address=HexAddress(HexStr("0x3d80b31a78c30fc628f20b2c89d7ddbf6e53cedc")))
