# ravencoin-stratum-proxy
Allows you to mine directly to your own local wallet/node with any mining software that uses the stratum protocol.

## Windows setup:

1. Download and install the latest version of [Python](https://www.python.org/downloads/)
   - Run the executable and **Check** the `Add Python3 to PATH`! and press the `Install Now` option.
   - press the `Disable path lenght limit` option.

2. Download and install the latest version of [git](https://git-scm.com/download/win) 
   - Should look like this -> `64-bit Git for Windows Setup.`
   - Run the executable and press next througout the installation prompts.

3. Write `cmd` in the windows start menu and open the "Command Promt".
   - Make sure Python and Git are installed properly by running `python3 -V` and `git --version`
   - Change the directory to the `Desktop` with the following command:
     ```
     cd Desktop
     ```
   - Now download the ravencoin-stratum-proxy repo onto the desktop with the following command:
     ```
     git clone https://github.com/kralverde/ravencoin-stratum-proxy.git
     ```
   - Change the current working directroy to the repo:
     ```
     cd ravencoin-stratum-proxy
     ```
   - Now install dependencies with
     ```
     pip3 install -r requirements.txt
     ```
     If you get an error message on pysha3 do the following:
     * Downlod [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
     * Put the `vs_buildtools.exe` file in the ravencoin-stratum-proxy folder and run this command:
       ```
       vs_buildtools.exe --norestart --passive --downloadThenInstall --includeRecommended --add Microsoft.VisualStudio.Workload.NativeDesktop --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Workload.MSBuildTools
       ```
     * After the install retry the command:
       ```
       pip3 install -r requirements.txt
       ```

## Linux setup:
1. The script requires python 3.8 or higher and pip3 alongside it, to install use the following commands in terminal:
   ```
   sudo add-apt-repository ppa:deadsnakes/ppa
   sudo apt-get update
   sudo apt-get -y install python3.10
   sudo apt-get -y install python3-pip
   ```

2. Use git to download the repo, if you dont have git installed use this command in terminal:
   ```
   apt-get install git
   ```
3. Download the ravencoin-stratum-proxy repo to the current directory with:
   ```
   git clone https://github.com/kralverde/ravencoin-stratum-proxy.git
   ```
   - Enter the repo directory with:
     ```
     cd ravencoin-stratum-proxy
     ```
   - Finally, install the dependecies with:
     ```
     pip3 install -r requirements.txt
     ```

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
python stratum-converter.py 54325 localhost my_username my_password 18766 false true
```
And for a local node on **mainnet** with an external miner:
```
python stratum-converter.py 54325 localhost my_username my_password 8766 true
```

Connect to it with your miner of choise:

| status | miner | example |
| - | - | - |
| :heavy_check_mark: Works | T-rex | t-rex -a kawpow -o stratum+tcp://127.0.0.1:54325 -u YOUR_WALLET_ADDRESS -p x |
| :heavy_check_mark: Works | TeamRedMiner | teamredminer -o stratum+tcp://127.0.0.1:54325 -u YOUR_WALLET_ADDRESS -p x |
| :heavy_check_mark: Works | Gminer | miner --algo kawpow --server stratum+tcp://127.0.0.1:54325 --user YOUR_WALLET_ADDRESS --pass x |
| :exclamation:   Errors | NBminer | :grey_question: |
| :grey_question: Not tested | kawpowminer | kawpowminer -P stratum+tcp://YOUR_WALLET_ADDRESS.worker@127.0.0.1:54325 |


© 2022 GitHub, Inc.
Terms
Privacy




