import json
from eth_typing import (
    BLSPubkey,
    BLSSignature,
)
from typing import Any, Dict, Sequence

from py_ecc.bls import G2ProofOfPossession as bls

from eth2deposit.exceptions import ValidationError
from eth2deposit.utils.ssz import (
    compute_deposit_domain,
    compute_signing_root,
    DepositData,
    DepositMessage,
)
from eth2deposit.credentials import (
    Credential,
)
from eth2deposit.utils.constants import (
    MAX_DEPOSIT_AMOUNT,
    MIN_DEPOSIT_AMOUNT,
    BLS_WITHDRAWAL_PREFIX,
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
)
from eth2deposit.utils.crypto import SHA256


def verify_deposit_data_json(filefolder: str, credentials: Sequence[Credential]) -> bool:
    """
    Validate every deposit found in the deposit-data JSON file folder.
    """
    with open(filefolder, 'r') as f:
        deposit_json = json.load(f)
        return all([validate_deposit(deposit, credential) for deposit, credential in zip(deposit_json, credentials)])
    return False


def validate_deposit(deposit_data_dict: Dict[str, Any], credential: Credential) -> bool:
    '''
    Checks whether a deposit is valid based on the eth2 rules.
    https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#deposits
    '''
    pubkey = BLSPubkey(bytes.fromhex(deposit_data_dict['pubkey']))
    withdrawal_credentials = bytes.fromhex(deposit_data_dict['withdrawal_credentials'])
    amount = deposit_data_dict['amount']
    signature = BLSSignature(bytes.fromhex(deposit_data_dict['signature']))
    deposit_message_root = bytes.fromhex(deposit_data_dict['deposit_data_root'])
    fork_version = bytes.fromhex(deposit_data_dict['fork_version'])

    # Verify pubkey
    if len(pubkey) != 48:
        print("failed pubkey")
        return False
    if pubkey != credential.signing_pk:
        print("failed wrong key")
        return False

    # Verify withdrawal credential
    if len(withdrawal_credentials) != 32:
        print("failed withdrawal_credentials ")
        return False
    if withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX == credential.withdrawal_prefix:
        if withdrawal_credentials[1:] != SHA256(credential.withdrawal_pk)[1:]:
            print("withdrawal_credentials not bls prefix")
            return False
    elif withdrawal_credentials[:1] == ETH1_ADDRESS_WITHDRAWAL_PREFIX == credential.withdrawal_prefix:
        if withdrawal_credentials[1:12] != b'\x00' * 11:
            return False
        if credential.eth1_withdrawal_address is None:
            return False
        if withdrawal_credentials[12:] != credential.eth1_withdrawal_address:
            return False
    else:
        return False

    # Verify deposit amount
    if not MIN_DEPOSIT_AMOUNT <= amount <= MAX_DEPOSIT_AMOUNT:
        return False

    # Verify deposit signature && pubkey
    deposit_message = DepositMessage(pubkey=pubkey, withdrawal_credentials=withdrawal_credentials, amount=amount)
    domain = compute_deposit_domain(fork_version)
    signing_root = compute_signing_root(deposit_message, domain)
    if not bls.Verify(pubkey, signing_root, signature):
        return False

    # Verify Deposit Root
    signed_deposit = DepositData(
        pubkey=pubkey,
        withdrawal_credentials=withdrawal_credentials,
        amount=amount,
        signature=signature,
    )
    print("signed_deposit ")

    return signed_deposit.hash_tree_root == deposit_message_root


def validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise ValidationError(f"The password length should be at least 8. Got {len(password)}.")
