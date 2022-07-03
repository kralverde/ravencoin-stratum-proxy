# ravencoin-stratum-proxy
Allows you to mine directly to your own local wallet/node with any mining software that uses the stratum protocol.

##### Table of Contents  
[Headers](#headers)

<a name="headers"/>
## Setup:

1. Download and install the latest version of [Python](https://www.python.org/downloads/)
   - Run the executable and **Check** the `Add Python3 to PATH`! and press the `Install Now` option.
   - press the `Disable path lenght limit` option.


## Node setup:

Requires the following `raven.conf` options:
```
server=1
rpcuser=my_username
rpcpassword=my_password
rpcallowip=127.0.0.1
```
For testnet you can add `testnet=1` to your `raven.conf`

note:
- Default Mainnet rpcport = `8766`
- Default Testnet rpcport = `18766`

Make sure you configure the rpcport on `stratum-converter.py` accordingly.

## Usage:
The stratum converter uses the following flags `python stratum-converter.py Port_for_miner Ip_of_node Rpc_username Rpc_password Rpc_port Allow_external_connections Is_testnet(optional)` 

With this in mind we can run **testnet** from a local node with a local miner:
```
python3 stratum-converter.py 54325 localhost my_username my_password 18766 false true
```
And for a local node on **mainnet** with an external miner:
```
python3 stratum-converter.py 54325 localhost my_username my_password 8766 true
```

Connect to it with your miner of choise:

| status | miner | example |
| - | - | - |
| :heavy_check_mark: Works | T-rex | t-rex -a kawpow -o stratum+tcp://PROXY_IP:54325 -u YOUR_WALLET_ADDRESS -p x |
| :heavy_check_mark: Works | TeamRedMiner | teamredminer -o stratum+tcp://PROXY_IP:54325 -u YOUR_WALLET_ADDRESS -p x |
| :heavy_check_mark: Works | Gminer | miner --algo kawpow --server stratum+tcp://PROXY_IP:54325 --user YOUR_WALLET_ADDRESS --pass x |
| :exclamation:   Errors | NBminer | :grey_question: |
| :heavy_check_mark: Works | kawpowminer | kawpowminer -P stratum+tcp://YOUR_WALLET_ADDRESS.worker@PROXY_IP:54325 |


© 2022 GitHub, Inc.
Terms
Privacy




