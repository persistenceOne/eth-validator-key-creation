# splitting-keys
This repo is for generating keys and staking it on ETH

- Install the requirements from requirements.txt or create a virtual env.
- For installing requirements `python3 -m pip install -r requirements.txt`

### Creating genesis keys
- For making deposit for genesis event to happen
  - Run with the following params:
    - PRIVATE_KEY: private key for eth1 account 
    - DEPOSIT_CONTRACT_ADDRESS: Deposit contract which is used by beacon node
    - KEYSTORE_PASSWORD: Password to encrypt the validator private keystore file
```
  python3 genesis.py <PRIVATE_KEY> <DEPOSIT_CONTRACT_ADDRESS> <KEYSTORE_PASSWORD>
```

### Schedule deposit to Keysmanager by Node Operator
This will make a schedule deposit of one key per hour for 4 validators
- For submitting public keys to the keysmanager contract
  - Run with the following params:
    - PRIVATE_KEY: private key for eth1 account for node operator
    - KEYSMANAGER_ADDRESS: Keysmanager address for pstake liquid staking
    - DEPOSIT_CONTRACT_ADDRESS: Deposit contract address which is used by beacon node
    - KEYSTORE_PASSWORD: Password to encrypt the validator private keystore file
    - WITHDRAWAL_CREDS: Withdrawal Contract address where eth withdrawal will happen
```
  python3 node_operator.py <PRIVATE_KEY> <KEYSMANAGER_ADDRESS> <DEPOSIT_CONTRACT_ADDRESS> <KEYSTORE_PASSWORD> <WITHDRAWAL_CREDS>
```

