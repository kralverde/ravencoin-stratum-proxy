# ravencoin-stratum-proxy

Allows you to mine to your local wallet/node

For windows users, please see windows.md

Requires the following raven.conf options:
```
server=1
rpcuser=my_username
rpcpassword=my_password
rpcallowip=127.0.0.1
```

## How To:

First, install python and git. May sure they are installed properly by running `python3 -V` and `git --version`

Next, download this repo with `git clone https://github.com/kralverde/ravencoin-stratum-proxy.git`

Then, enter the repo with `cd ravencoin-stratum-proxy`

Now you want to install dependencies  `python3 -m pip install -r requirements.txt` while in the ravencoin-stratum-proxy directory.

Now run stratum-converter.py and connect with your miner.

Ex.
```
python3 stratum-converter.py 54325 127.0.0.1 my_username my_password 18766 true
t-rex.exe -a kawpow -o stratum+tcp://127.0.0.1:54325 -u YOUR_WALLET_ADDRESS -p x
```
