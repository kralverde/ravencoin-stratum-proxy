# ravencoin-stratum-proxy

Requires python >=3.8

Allows you to mine directly to your own local wallet/node with any mining software that uses the stratum protocol.


Requires the following raven.conf options:



## How To:

```
server=1
rpcuser=my_username
rpcpassword=my_password
rpcallowip=127.0.0.1
```

### Linux setup:
The script requires python 3.8 or higher and pip3 alonside it, to install use the following commands in terminal:
```
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get -y install python3.10
sudo apt-get -y install python3-pip
```

Use git to download the repo, if you dont have git installed use this command in terminal:
```
apt-get install git
```
Next, download the ravencoin-stratum-proxy repo to the current directory with:
```
git clone https://github.com/kralverde/ravencoin-stratum-proxy.git
```
Then, enter the repo directory with:
```
cd ravencoin-stratum-proxy
```
Now, install the dependecies with:
```
pip3 install -r requirements.txt
or
python3 -m pip install -r requirements.txt
```

### Windows setup:


First, install python (https://www.python.org/downloads/) (make sure pip is installed as well) and git (https://git-scm.com/downloads). May sure they are installed properly by running `python3 -V` and `git --version`


Then, enter the repo with `cd ravencoin-stratum-proxy`

Now you want to install dependencies  `python3 -m pip install -r requirements.txt` while in the ravencoin-stratum-proxy directory. (If this fails try `pip3 install -r requirements.txt`)

Now run stratum-converter.py and connect with your miner.

Ex.
```
python3 stratum-converter.py 54325 127.0.0.1 my_username my_password 18766 false true
t-rex.exe -a kawpow -o stratum+tcp://127.0.0.1:54325 -u YOUR_WALLET_ADDRESS -p x
```
