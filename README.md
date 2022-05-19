# ravencoin-stratum-proxy

Allows you to mine to your local wallet/node

Simply run `python3 -m pip install -r requirements.txt` while in this directory

For windows users, please see windows.md

Requires the following raven.conf options:
```
server=1
rpcuser=my_username
rpcpassword=my_password
rpcallowip=127.0.0.1
```

Ex.
```
python3 stratum-converter.py 54325 127.0.0.1 my_username my_password 18766 true
t-rex.exe -a kawpow -o stratum+tcp://127.0.0.1:54325 -u YOUR_WALLET_ADDRESS -p x
```
