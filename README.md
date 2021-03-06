# splitting-keys
This repo used the code [from eth2-deposit-cli](https://github.com/ethereum/staking-deposit-cli) and creates scripts 
which can be used to create keys and signature with variable eth amount for the purpose of depositing them 
pstake smart contracts and on deposit contract.

- Install the requirements from requirements.txt or create a virtual env.
- For installing requirements `python3 -m pip install -r requirements.txt`

### Creating genesis keys [!! DONT RUN THIS FOR TESTNET KEY SUBMISSION]
genesis.py
- For making deposit for genesis event to happen. Used for imitating the genesis of beacon chain locally
  - Run with the following params:
    - PRIVATE_KEY: private key for eth1 account 
    - DEPOSIT_CONTRACT_ADDRESS: Deposit contract which is used by beacon node
    - KEYSTORE_PASSWORD: Password to encrypt the validator private keystore file
```
  python3 genesis.py <PRIVATE_KEY> <DEPOSIT_CONTRACT_ADDRESS> <KEYSTORE_PASSWORD>
```

### Deposit validator keys to Keysmanager contract by Node Operator
node_operator.py
- This script will create keys and submit them on deposit contract as well as pstake keysmanager contract for 
eth2 liquid staking.
- The keys can be found in node_operator folder which will be created while running the script
- Params to pass:
  - Required:
    - ETH1_ENDPOINT: endpoint to connect to eth1 chain
    - PRIVATE_KEY: private key for the node operator account for which you submitted your address to pstake
    - KEYSTORE_PASSWORD: password for the keys generated
    - NUMBER_OF_VALIDATORS: number of validators you want to create
```
  python3 node_operator.py -eth1 <ETH1_ENDPOINT> -priv <PRIVATE_KEY> -pass <KEYSTORE_PASSWORD> -n <NUMBER_OF_VALIDATORS>
```
- For more help just pass -h flag `python3 node_operator.py -h`

### Activating all verified keys
activate.py
- This script will do a transaction to pstake stketh smart contract to make your verified key active 
and issue you a refund
- Params to pass:
  - Required:
    - ETH1_ENDPOINT: endpoint to connect to eth1 chain
    - PRIVATE_KEY: private key for the node operator account for which you submitted your address to pstake
    - SUBGRAPH_ENDPOINT: endpoint to connect to pstake stketh subgraph
```
  python3 activate.py -eth1 <ETH1_ENDPOINT> -priv <PRIVATE_KEY> -graph <SUBGRAPH_ENDPOINT>
```
- For more help just pass -h flag `python3 activate.py -h`

### Generate signature for failed keys [!! TO BE USED ONLY IN CASE OF NODE OPERATOR SCRIPT CRASHING]
generate_signature_and_submit.py
- This script will generate a signature for private key and submit it to pstake keysmanager smart contract
- Params to pass:
  - Required:
    - ETH1_ENDPOINT: endpoint to connect to eth1 chain
    - PRIVATE_KEY: private key for the node operator account for which you submitted your address to pstake
    - KEYSTORE_PASSWORD: password for the keys generated
    - KEYSTORE_1.json,KEYSTORE_2.json: space separated keystore files for which the transaction failed and signature has to be submitted
```
  python3 generate_signature_and_submit.py -eth1 <ETH1_ENDPOINT> -priv <PRIVATE_KEY> -pass <KEYSTORE_PASSWORD> -keys <KEYSTORE_1.json> <KEYSTORE_2.json>
```
- For more help just pass -h flag `python3 generate_signature_and_submit.py -h`
