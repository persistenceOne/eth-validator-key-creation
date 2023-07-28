# splitting-keys
This repo used the code [from eth2-deposit-cli](https://github.com/ethereum/staking-deposit-cli) and creates scripts 
which can be used to create keys and signature with variable eth amount for the purpose of depositing them 
pstake smart contracts and on deposit contract. \

**NOTE: YOU NEED TO WHITELIST YOUR ADDRESS WITH PSTAKE TO BE ABLE TO RUN THE SCRIPT** 

- Install the requirements from requirements.txt or create a virtual env.
- For installing requirements `python -m pip install -r requirements.txt`

For running the script you can run the following script:
- `python node_operator.py --help` \
There are two options that'll be shown to you:
- **start**: This will start the script for the pSTAKE protocol.
- **generate**: This option you can use generate validator keys for Ethereum. The deposit data which is generated
is for deposit of 32 ETH.
- There is a global option as well:
  - -t (TESTNET): It takes boolean values as input. The default value if not selected is False. If you are participating
    on Goerli testnet you can set it to True

## Running the scripts (start)
This script performs the following actions:
1. It generates validator keys to be used for pSTAKE protocol
2. It generates deposit data and submit the keys to deposit contract with 1 ETH deposit
3. It generates a signature with the validator key for rest of 31 ETH that needs to be deposited and submits it to the  
  pSTAKE contract, which uses the same signature to make the remaining deposit
4. It also monitors the issuer contract for balance, so that it can make a transaction to activate the keys. \
5. The script also tracks the number of keys that you have deposited and maintain a balance of keys automatically that 
  needs to be present in the contract. A node operator just have to keep 3-4 eth balance with the account that they 
  submitted to pSTAKE protocol for whitelisting.
6. It generates a *stateFile.json* which store the current state of the system,i.e., validator keys the script is
  generating. If the script fails you can restart it again. It'll look into statefile to see if some keys was not 
  submitted and continue from there. **DO NOT DELETE THIS FILE!!**

For help on running the script you can pass the following options:\
```
python node_operator.py start --help
```
It will give you following options apart from the global options:
- -c (CONFIG): Pass the path of the configuration file you wish to use. Copy paste the example config(`cp config.example.json config.json `) and fill in the 
details. 
- -priv (PRIVATE_KEY): Private key for the address whitelisted with pSTAKE.\
#### OPTIONAL:
```
NOTE: ADVANCED USAGE BE CAREFUL WITH THE BELOW OPTIONS. IF MISCONFIGURED THE VALIDATOR CAN GET SLASHED FOR DOUBLE 
SIGNING!! THIS CAN HAPPEN WHEN YOU USE THE SAME MNEMONIC AND SAME INDEX. ONLY USE WHEN YOU ARE CONFIDENT ENOUGH!!
```
- -m (MNEMONIC): Mnemonic used to generate the validator keys. **IT IS NOT YOUR ACCOUNT MNEMONIC!!!**
  If nothing is passed it'll generate a new mnemonic and display it on the console. Note it down if you want to use it
  for all validator key creation.
- -i (INDEX): Index of validator to start with. Use this only when you are using your own mnemonic and keep track of
  last index used. You can find that on the console when running the script in the logs. 

To run the script:
```
python node_operator.py start -c <CONFIG_FILE> -priv <PRIVATE_KEY> -m <MNEMONIC_VALIDATOR_KEYS>
```

### Docker 
You can also use the following docker image: `persistenceone/node-operator:latest`
Or if you want to build your own docker image you can use the makefile to do so:
```
make docker-build
```
For running the image you can do following
- Make a config folder with config file inside of it and fill in the values from `README_CONFIG.md`
- To use the image mount a volume with the config file and run:
  - CONFIG_FILE_FOLDER: folder that you created with config file inside of it
  - PRIVATE_KEY: Private key associated with the whitelisted account with pSTAKE
  - TESTNET(BOOLEAN): Whether running on testnet(true/false)
```
docker run -v <CONFIG_FILE_FOLDER>:/config -it persistenceone/node-operator:latest python node_operator.py start -c /config/config.json -kf /config -priv <PRIVATE_KEY> -t <TESTNET>
```
You can find the validator keys in the config folder you created

## Creating keys (generate)
If you want to just generate staking keys for personal use case you can do that as well. \
For help on running the script you can pass the following options:
```
python node_operator.py generate --help
```
It will give you following options apart from the global options:
- -w (WITHDRAWAL): Withdrawal address to set for validator keys
- -n (NUMBER): Number of validators to create
- -p (PASSPHRASE): Passphrase for validators to use.
#### OPTIONAL:
- -m (MNEMONIC): Mnemonic used to generate the validator keys.If nothing is passed it'll generate a new mnemonic and
  display it on the console. Note it down if you want to use it for all validator key creation.
- -i (INDEX): Index of validator to start with. Use this only when you are using your own mnemonic and keep track of
  last index used.

